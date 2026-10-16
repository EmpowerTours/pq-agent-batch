//! Tiny reference batcher: signed-action JSON files -> `batch-input.json` for the zk-batch host
//! (`batch --input <file> --execute|--prove`). It applies the same acceptance rules the contract
//! enforces at settle time so a batch it emits does not revert for nonce / cap / balance / fee reasons
//! (pool slippage is NOT simulated).

use crate::action::{hex0x, unhex, SignedAction};
use crate::chain::{IAgentRegistry, IBatchSettlementV2, Rpc};
use agent_batch_lib::{batch_digest, verify_batch, HEADER, ORDER};
use alloy_primitives::{Address, FixedBytes, U256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const BATCH_INPUT_SCHEMA: &str = "pq-agent-batch/batch-input/v1";

/// What the batcher needs to know about an agent on chain.
#[derive(Debug, Clone)]
pub struct AgentOnChain {
    pub authorized: bool,
    pub last_nonce: u64,
    pub base: u128,
    pub quote: u128,
    pub cap_base_in: u128,
    pub cap_quote_in: u128,
    pub fee_balance: u128,
}

pub trait StateSource {
    fn agent(&self, id: u32, pk_hash: [u8; 32]) -> Result<AgentOnChain>;
    /// settlement.feeQuote(id, actions)
    fn fee_quote(&self, id: u32, actions: u64) -> Result<u128>;
    /// current chain time (unix seconds)
    fn now(&self) -> Result<u64>;
}

/// No chain access: every agent authorized, lastNonce 0, unlimited caps/balances, zero fees.
/// Used for golden tests and dry runs (`pqagent batch --offline`).
pub struct Offline {
    pub now: u64,
}

impl StateSource for Offline {
    fn agent(&self, _: u32, _: [u8; 32]) -> Result<AgentOnChain> {
        Ok(AgentOnChain { authorized: true, last_nonce: 0, base: u128::MAX, quote: u128::MAX,
            cap_base_in: u128::MAX, cap_quote_in: u128::MAX, fee_balance: u128::MAX })
    }
    fn fee_quote(&self, _: u32, _: u64) -> Result<u128> {
        Ok(0)
    }
    fn now(&self) -> Result<u64> {
        Ok(self.now)
    }
}

/// Live state from a settlement contract (and its registry).
pub struct OnChain<'a> {
    pub rpc: &'a Rpc,
    pub settlement: Address,
    pub registry: Address,
}

impl<'a> OnChain<'a> {
    pub fn new(rpc: &'a Rpc, settlement: Address) -> Result<Self> {
        let registry = rpc.view(settlement, IBatchSettlementV2::registryCall {})?;
        Ok(Self { rpc, settlement, registry })
    }
}

impl StateSource for OnChain<'_> {
    fn agent(&self, id: u32, pk_hash: [u8; 32]) -> Result<AgentOnChain> {
        let authorized = self.rpc.view(self.registry, IAgentRegistry::isAuthorizedCall { id, pkHash: FixedBytes(pk_hash) })?;
        let a = self.rpc.view(self.registry, IAgentRegistry::agentsCall { id })?;
        let s = self.rpc.view(self.settlement, IBatchSettlementV2::agentStateCall { id })?;
        let f = self.rpc.view(self.settlement, IBatchSettlementV2::feeAccountCall { id })?;
        Ok(AgentOnChain {
            authorized, last_nonce: s.lastNonce,
            base: s.base.to::<u128>(), quote: s.quote.to::<u128>(),
            cap_base_in: a.capBaseIn, cap_quote_in: a.capQuoteIn,
            fee_balance: f.balance.to::<u128>(),
        })
    }
    fn fee_quote(&self, id: u32, actions: u64) -> Result<u128> {
        Ok(self.rpc.view(self.settlement, IBatchSettlementV2::feeQuoteCall { id, actions: U256::from(actions) })?.to::<u128>())
    }
    fn now(&self) -> Result<u64> {
        let b = self.rpc.call_raw("eth_getBlockByNumber", serde_json::json!(["latest", false]))?;
        Ok(crate::chain::parse_qty(b["timestamp"].as_str().unwrap_or("0x0"))? as u64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupInput {
    pub agent_id: u32,
    pub first_nonce: u64,
    pub count: u16,
    pub pk_hash: String,
    pub fee_quote: String,
    pub public_key: String,
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Excluded {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    pub reason: String,
}

/// Prover input. The zk-batch host consumes chainId, settlement, batchId, batch, groups[].publicKey
/// and groups[].signatures; everything else is informational.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BatchInput {
    pub schema: String,
    pub chain_id: u64,
    pub settlement: String,
    pub batch_id: u64,
    pub orders: usize,
    pub state_checks: String,
    pub batch: String,
    pub digest: String,
    pub groups: Vec<GroupInput>,
    pub excluded: Vec<Excluded>,
}

pub struct BatchOptions {
    pub chain_id: u64,
    pub settlement: [u8; 20],
    pub batch_id: u64,
    /// drop actions expiring sooner than now + this (time to prove and land the batch)
    pub min_validity_secs: u64,
    /// stop adding orders beyond this many
    pub max_orders: usize,
}

/// Load every `*.json` in `dir` (sorted by file name) as a signed action.
pub fn load_dir(dir: &Path) -> Result<Vec<(String, Result<SignedAction>)>> {
    let mut files: Vec<_> = std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    files.sort();
    Ok(files.into_iter().map(|p| {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let r = std::fs::read(&p).map_err(anyhow::Error::from)
            .and_then(|b| serde_json::from_slice::<SignedAction>(&b).map_err(anyhow::Error::from));
        (name, r)
    }).collect())
}

struct Cand {
    src: String,
    a: SignedAction,
    order: [u8; ORDER],
    buy: bool,
    amount: u128,
}

pub fn build(actions: Vec<(String, Result<SignedAction>)>, opt: &BatchOptions, state: &dyn StateSource) -> Result<BatchInput> {
    let now = state.now()?;
    let mut excluded = vec![];
    let mut ex = |src: &str, a: Option<&SignedAction>, reason: String| excluded.push(Excluded {
        source: src.to_string(), agent_id: a.map(|a| a.agent_id), nonce: a.map(|a| a.nonce), reason });
    let mut by_agent: BTreeMap<u32, Vec<Cand>> = BTreeMap::new();
    for (src, r) in actions {
        let a = match r { Ok(a) => a, Err(e) => { ex(&src, None, format!("unparseable: {e:#}")); continue } };
        let p = match a.verify() { Ok(p) => p, Err(e) => { ex(&src, Some(&a), format!("invalid: {e:#}")); continue } };
        if p.chain_id != opt.chain_id || p.settlement != opt.settlement {
            ex(&src, Some(&a), "signed for a different chainId/settlement".into()); continue;
        }
        if (p.expiry as u64) < now + opt.min_validity_secs {
            ex(&src, Some(&a), format!("expires at {} (< now {} + {}s)", p.expiry, now, opt.min_validity_secs)); continue;
        }
        let order = p.order.encode()?;
        by_agent.entry(p.agent_id).or_default().push(Cand { src, buy: p.order.buy_base, amount: p.order.amount_in, a, order });
    }

    let mut batch = vec![];
    let mut groups = vec![];
    let mut pks = vec![];
    let mut sigs = vec![];
    let mut total = 0usize;
    for (id, mut cs) in by_agent {
        cs.sort_by(|x, y| x.a.nonce.cmp(&y.a.nonce).then(x.src.cmp(&y.src)));
        // duplicates: keep the first file per nonce
        let mut uniq: Vec<Cand> = vec![];
        for c in cs {
            if uniq.last().map(|l| l.a.nonce == c.a.nonce).unwrap_or(false) {
                ex(&c.src, Some(&c.a), "duplicate nonce (kept the first file)".into());
            } else { uniq.push(c) }
        }
        let pkh: [u8; 32] = crate::action::unhex_n(&uniq[0].a.pk_hash)?;
        let st = state.agent(id, pkh)?;
        let mut run: Vec<Cand> = vec![];
        for c in uniq {
            if c.a.nonce <= st.last_nonce {
                ex(&c.src, Some(&c.a), format!("nonce <= on-chain lastNonce {}", st.last_nonce)); continue;
            }
            let fits = match run.last() {
                None => true,
                Some(l) => c.a.nonce == l.a.nonce + 1 && c.a.expiry == l.a.expiry && c.a.model_hash == l.a.model_hash
                    && c.a.pk_hash == l.a.pk_hash && run.len() < u16::MAX as usize,
            };
            if fits && total + run.len() < opt.max_orders { run.push(c) } else {
                ex(&c.src, Some(&c.a), "not contiguous with this batch's run (gap / different expiry, model or key / size limit); deferred".into());
            }
        }
        if run.is_empty() { continue }
        let rpkh: [u8; 32] = crate::action::unhex_n(&run[0].a.pk_hash)?;
        let auth = if rpkh == pkh { st.authorized } else { state.agent(id, rpkh)?.authorized };
        if !auth {
            for c in &run { ex(&c.src, Some(&c.a), "registry: agent not active / killed / key not authorized".into()) }
            continue;
        }
        // trim from the end until caps, trading balances and the fee balance all hold
        let mut fee = 0u128;
        while !run.is_empty() {
            let (b, q) = run.iter().fold((0u128, 0u128), |(b, q), c| if c.buy { (b, q + c.amount) } else { (b + c.amount, q) });
            fee = state.fee_quote(id, run.len() as u64)?;
            let why = if b > st.cap_base_in || q > st.cap_quote_in { Some("per-batch cap exceeded") }
                else if b > st.base || q > st.quote { Some("insufficient trading balance on the settlement") }
                else if fee > st.fee_balance { Some("insufficient prepaid fee balance (feeQuote > feeAccount.balance)") }
                else { None };
            match why {
                None => break,
                Some(w) => { let c = run.pop().unwrap(); ex(&c.src, Some(&c.a), w.to_string()); }
            }
        }
        if run.is_empty() { continue }
        let f = &run[0].a;
        batch.extend_from_slice(&id.to_be_bytes());
        batch.extend_from_slice(&(run.len() as u16).to_be_bytes());
        batch.extend_from_slice(&f.nonce.to_be_bytes());
        batch.extend_from_slice(&f.expiry.to_be_bytes());
        batch.extend_from_slice(&rpkh);
        batch.extend_from_slice(&unhex(&f.model_hash)?);
        for c in &run { batch.extend_from_slice(&c.order) }
        pks.push(unhex(&f.public_key)?);
        for c in &run { sigs.push(unhex(&c.a.signature)?) }
        total += run.len();
        groups.push(GroupInput {
            agent_id: id, first_nonce: f.nonce, count: run.len() as u16, pk_hash: f.pk_hash.clone(),
            fee_quote: fee.to_string(), public_key: f.public_key.clone(),
            signatures: run.iter().map(|c| c.a.signature.clone()).collect(),
        });
    }
    debug_assert!(groups.is_empty() || batch.len() >= HEADER);
    let digest = if batch.is_empty() { [0u8; 32] } else {
        // same check the guest performs; must hold for anything we emit
        verify_batch(opt.chain_id, opt.settlement, opt.batch_id, &batch, &pks, &sigs)
            .context("internal: assembled batch fails guest verification")?
    };
    debug_assert!(batch.is_empty() || digest == batch_digest(opt.chain_id, opt.settlement, opt.batch_id, &batch));
    Ok(BatchInput {
        schema: BATCH_INPUT_SCHEMA.into(), chain_id: opt.chain_id, settlement: hex0x(&opt.settlement), batch_id: opt.batch_id,
        orders: total, state_checks: String::new(), batch: hex0x(&batch), digest: hex0x(&digest), groups, excluded,
    })
}
