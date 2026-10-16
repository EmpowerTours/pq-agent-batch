//! High-level API mirroring the CLI: `Agent::init`, `register`, `fund`, `balance`, `set_alert`,
//! `sign`, `status`. All state lives in a keystore directory (default `.pqagent/`).

use crate::action::{hex0x, unhex_n, ActionParams, Order, SignedAction};
use crate::chain::{IAgentRegistry, IBatchSettlementV2, IERC20, Receipt, Rpc};
use crate::config::Config;
use crate::keys::{self, AgentKey};
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_signer_local::PrivateKeySigner;
use anyhow::{anyhow, bail, ensure, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

pub struct InitOptions {
    pub chain_id: u64,
    pub settlement: Address,
    pub rpc: Option<String>,
    /// raw model artifact bytes (file contents or the string's UTF-8)
    pub model: Vec<u8>,
    pub model_source: String,
    pub passphrase: Option<String>,
    /// INSECURE: reproduce the repo's public TEST key i (golden vectors / demos)
    pub test_seed: Option<u8>,
    pub force: bool,
    pub expiry_bucket_secs: u32,
}

pub struct Agent {
    pub dir: PathBuf,
    pub config: Config,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub agent_id: u32,
    pub tx_hash: String,
    pub registration_fee: String,
    pub bond: String,
    pub cap_base_in: String,
    pub cap_quote_in: String,
    pub gas_used: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Balance {
    pub agent_id: u32,
    pub fee_token_index: u8,
    pub fee_token: String,
    pub fee_balance: String,
    pub alert_threshold: String,
    pub low: bool,
    pub fee_per_action: String,
    pub max_fee_per_batch: String,
    /// lower bound; "unlimited" when the fee is zero
    pub remaining_actions: String,
    pub auto_top_up_amount: String,
    pub auto_top_up_from: String,
    pub pending_withdrawal: String,
    pub trading_base: String,
    pub trading_quote: String,
    pub last_nonce: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub agent_id: u32,
    pub pk_hash: String,
    pub authorized: bool,
    pub operator: String,
    pub active: bool,
    pub killed: bool,
    pub stake: String,
    pub cap_base_in: String,
    pub cap_quote_in: String,
    pub last_nonce: u64,
    pub next_nonce: u64,
    pub fee_balance: String,
    pub remaining_actions: String,
}

impl Agent {
    pub fn key_path(dir: &Path) -> PathBuf { dir.join("key.json") }

    /// Generate (or reproduce, with test_seed) an ML-DSA-65 key, write key.json (0600, dir 0700),
    /// pubkey.hex and config.json. Never prints or returns the private key.
    pub fn init(dir: &Path, o: InitOptions) -> Result<Agent> {
        if Self::key_path(dir).exists() && !o.force {
            bail!("{} already exists (use --force to overwrite; this destroys the old key)", Self::key_path(dir).display());
        }
        keys::ensure_private_dir(dir)?;
        let key = match o.test_seed { Some(i) => AgentKey::test_key(i), None => AgentKey::generate()? };
        keys::save_key(&Self::key_path(dir), &key, o.passphrase.as_deref())?;
        std::fs::write(dir.join("pubkey.hex"), format!("{}\n", hex::encode(key.public_key())))?;
        let config = Config {
            schema: crate::config::CONFIG_SCHEMA.into(), rpc: o.rpc, chain_id: o.chain_id,
            settlement: format!("{:#x}", o.settlement), registry: None, agent_id: None,
            pk_hash: hex0x(&key.pk_hash()), model_hash: hex0x(&keys::model_hash(&o.model)),
            model_source: o.model_source, key_encrypted: o.passphrase.is_some(), next_nonce: 1,
            expiry_bucket_secs: o.expiry_bucket_secs,
        };
        config.save(dir)?;
        let gi = dir.join(".gitignore");
        if !gi.exists() { std::fs::write(gi, "# pqagent keystore: never commit\n*\n")?; }
        Ok(Agent { dir: dir.to_path_buf(), config })
    }

    pub fn open(dir: &Path) -> Result<Agent> {
        Ok(Agent { dir: dir.to_path_buf(), config: Config::load(dir)? })
    }

    pub fn save(&self) -> Result<()> { self.config.save(&self.dir) }

    pub fn key(&self) -> Result<AgentKey> {
        let pass = std::env::var(keys::PASSPHRASE_ENV).ok();
        let k = keys::load_key(&Self::key_path(&self.dir), pass.as_deref())?;
        ensure!(hex0x(&k.pk_hash()) == self.config.pk_hash, "key.json does not match config.json pkHash");
        Ok(k)
    }

    pub fn pk_hash(&self) -> Result<[u8; 32]> { unhex_n(&self.config.pk_hash) }
    pub fn settlement(&self) -> Result<Address> { Ok(self.config.settlement.parse()?) }
    pub fn agent_id(&self) -> Result<u32> {
        self.config.agent_id.ok_or_else(|| anyhow!("no agentId yet: run `pqagent register` (or `pqagent init --agent-id`)"))
    }

    pub fn rpc(&self) -> Result<Rpc> {
        let url = self.config.rpc.clone().ok_or_else(|| anyhow!("no rpc configured: pass --rpc"))?;
        let rpc = Rpc::new(&url);
        let cid = rpc.chain_id()?;
        ensure!(cid == self.config.chain_id, "rpc chainId {cid} != configured chainId {}", self.config.chain_id);
        Ok(rpc)
    }

    pub fn registry(&mut self, rpc: &Rpc) -> Result<Address> {
        if let Some(r) = &self.config.registry { return Ok(r.parse()?) }
        let r = rpc.view(self.settlement()?, IBatchSettlementV2::registryCall {})?;
        self.config.registry = Some(format!("{r:#x}"));
        self.save()?;
        Ok(r)
    }

    /// Self-register: pays registrationFee + bond (>= minStake) as msg.value. cap 0 = registry maximum.
    pub fn register(&mut self, op: &PrivateKeySigner, cap_base_in: u128, cap_quote_in: u128, extra_bond: u128) -> Result<Registration> {
        if let Some(id) = self.config.agent_id { bail!("already registered as agent {id} (delete agentId from config.json to re-register)") }
        let rpc = self.rpc()?;
        let reg = self.registry(&rpc)?;
        ensure!(rpc.view(reg, IAgentRegistry::openRegistrationCall {})?, "registry {reg:#x} has open registration disabled (ask the admin)");
        let fee = rpc.view(reg, IAgentRegistry::registrationFeeCall {})?.to::<u128>();
        let bond = rpc.view(reg, IAgentRegistry::minStakeCall {})?.to::<u128>() + extra_bond;
        let rc = rpc.send(op, reg, IAgentRegistry::selfRegisterCall {
            pkHash: FixedBytes(self.pk_hash()?), capBaseIn: cap_base_in, capQuoteIn: cap_quote_in,
        }, U256::from(fee + bond))?;
        let id = crate::chain::registered_id(&rc, reg).ok_or_else(|| anyhow!("no AgentRegistered log in {}", rc.tx_hash))?;
        let a = rpc.view(reg, IAgentRegistry::agentsCall { id })?;
        self.config.agent_id = Some(id);
        self.save()?;
        Ok(Registration { agent_id: id, tx_hash: format!("{:#x}", rc.tx_hash), registration_fee: fee.to_string(),
            bond: bond.to_string(), cap_base_in: a.capBaseIn.to_string(), cap_quote_in: a.capQuoteIn.to_string(), gas_used: rc.gas_used })
    }

    /// Deposit to the prepaid fee balance in the agent's fee token (native MON or approved ERC20).
    /// `select_token` switches the fee token first (only allowed while the balance is zero).
    pub fn fund(&mut self, op: &PrivateKeySigner, amount: u128, select_token: Option<u8>) -> Result<Vec<Receipt>> {
        let rpc = self.rpc()?;
        let (id, s) = (self.agent_id()?, self.settlement()?);
        let mut out = vec![];
        if let Some(t) = select_token {
            if rpc.view(s, IBatchSettlementV2::feeAccountCall { id })?.token != t {
                out.push(rpc.send(op, s, IBatchSettlementV2::selectFeeTokenCall { id, idx: t }, U256::ZERO)?);
            }
        }
        let token = rpc.view(s, IBatchSettlementV2::feeAccountCall { id })?.token;
        if token == 0 {
            out.push(rpc.send(op, s, IBatchSettlementV2::depositFeeNativeCall { id }, U256::from(amount))?);
        } else {
            let erc20 = rpc.view(s, IBatchSettlementV2::feeTokenCall { idx: token })?;
            let have = rpc.view(erc20, IERC20::allowanceCall { owner: op.address(), spender: s })?;
            if have < U256::from(amount) {
                out.push(rpc.send(op, erc20, IERC20::approveCall { spender: s, amount: U256::from(amount) }, U256::ZERO)?);
            }
            out.push(rpc.send(op, s, IBatchSettlementV2::depositFeeTokenCall { id, amount: U256::from(amount) }, U256::ZERO)?);
        }
        Ok(out)
    }

    /// Deposit trading balances (base/quote ERC20s) the agent's orders spend.
    pub fn deposit_trading(&mut self, op: &PrivateKeySigner, base_amt: u128, quote_amt: u128) -> Result<Vec<Receipt>> {
        let rpc = self.rpc()?;
        let (id, s) = (self.agent_id()?, self.settlement()?);
        ensure!(base_amt <= crate::action::MAX_U96 && quote_amt <= crate::action::MAX_U96, "amounts must fit uint96");
        let mut out = vec![];
        for (amt, tok) in [(base_amt, rpc.view(s, IBatchSettlementV2::baseCall {})?), (quote_amt, rpc.view(s, IBatchSettlementV2::quoteCall {})?)] {
            if amt == 0 { continue }
            if rpc.view(tok, IERC20::allowanceCall { owner: op.address(), spender: s })? < U256::from(amt) {
                out.push(rpc.send(op, tok, IERC20::approveCall { spender: s, amount: U256::from(amt) }, U256::ZERO)?);
            }
        }
        out.push(rpc.send(op, s, IBatchSettlementV2::depositCall {
            agentId: id, baseAmt: alloy_primitives::Uint::from(base_amt), quoteAmt: alloy_primitives::Uint::from(quote_amt) }, U256::ZERO)?);
        Ok(out)
    }

    pub fn balance(&mut self) -> Result<Balance> {
        let rpc = self.rpc()?;
        let (id, s) = (self.agent_id()?, self.settlement()?);
        let fa = rpc.view(s, IBatchSettlementV2::feeAccountCall { id })?;
        let fc = rpc.view(s, IBatchSettlementV2::feeConfigCall { idx: fa.token })?;
        let rem = rpc.view(s, IBatchSettlementV2::remainingActionsCall { id })?;
        let at = rpc.view(s, IBatchSettlementV2::autoTopUpCall { id })?;
        let pw = rpc.view(s, IBatchSettlementV2::pendingFeeWithdrawalCall { id })?;
        let st = rpc.view(s, IBatchSettlementV2::agentStateCall { id })?;
        let tok = if fa.token == 0 { "native MON".to_string() } else { format!("{:#x}", rpc.view(s, IBatchSettlementV2::feeTokenCall { idx: fa.token })?) };
        Ok(Balance {
            agent_id: id, fee_token_index: fa.token, fee_token: tok, fee_balance: fa.balance.to_string(),
            alert_threshold: fa.threshold.to_string(), low: fa.low, fee_per_action: fc.feePerAction.to_string(),
            max_fee_per_batch: fc.maxFeePerBatch.to_string(),
            remaining_actions: if rem == U256::MAX { "unlimited".into() } else { rem.to_string() },
            auto_top_up_amount: at.amount.to_string(), auto_top_up_from: format!("{:#x}", at.from),
            pending_withdrawal: if pw.amount.is_zero() { "none".into() } else { format!("{} ready at {}", pw.amount, pw.readyAt) },
            trading_base: st.base.to_string(), trading_quote: st.quote.to_string(), last_nonce: st.lastNonce,
        })
    }

    /// Low-balance alert threshold, plus optional ERC20 auto top-up (amount pulled per topUp from the
    /// operator, who must also approve the settlement; `approve` sets that allowance).
    pub fn set_alert(&mut self, op: &PrivateKeySigner, threshold: u128, auto_top_up: Option<u128>, approve: Option<u128>) -> Result<Vec<Receipt>> {
        let rpc = self.rpc()?;
        let (id, s) = (self.agent_id()?, self.settlement()?);
        let u96 = |v: u128| -> Result<alloy_primitives::Uint<96, 2>> { ensure!(v <= crate::action::MAX_U96, "must fit uint96"); Ok(alloy_primitives::Uint::from(v)) };
        let mut out = vec![rpc.send(op, s, IBatchSettlementV2::setFeeAlertCall { id, threshold: u96(threshold)? }, U256::ZERO)?];
        if let Some(a) = auto_top_up {
            out.push(rpc.send(op, s, IBatchSettlementV2::setAutoTopUpCall { id, amount: u96(a)? }, U256::ZERO)?);
        }
        if let Some(al) = approve {
            let token = rpc.view(s, IBatchSettlementV2::feeAccountCall { id })?.token;
            ensure!(token != 0, "auto top-up/approve needs an ERC20 fee token (native MON balances are funded with `fund`)");
            let erc20 = rpc.view(s, IBatchSettlementV2::feeTokenCall { idx: token })?;
            out.push(rpc.send(op, erc20, IERC20::approveCall { spender: s, amount: U256::from(al) }, U256::ZERO)?);
        }
        Ok(out)
    }

    /// Next nonce to sign: max(local counter, on-chain lastNonce + 1) when an rpc is reachable.
    pub fn next_nonce(&self, rpc: Option<&Rpc>) -> Result<u64> {
        let mut n = self.config.next_nonce;
        if let (Some(rpc), Some(id)) = (rpc, self.config.agent_id) {
            let st = rpc.view(self.settlement()?, IBatchSettlementV2::agentStateCall { id })?;
            n = n.max(st.lastNonce + 1);
        }
        Ok(n)
    }

    /// Default expiry: now + ttl rounded up to the configured bucket.
    pub fn default_expiry(&self, now: u64, ttl: u64) -> Result<u32> {
        let b = self.config.expiry_bucket_secs.max(1) as u64;
        let e = (now + ttl).div_ceil(b) * b;
        u32::try_from(e).map_err(|_| anyhow!("expiry overflows u32"))
    }

    /// ML-DSA sign one order and advance the local nonce counter.
    pub fn sign(&mut self, order: Order, nonce: u64, expiry: u32) -> Result<SignedAction> {
        let p = ActionParams {
            chain_id: self.config.chain_id, settlement: unhex_n(&self.config.settlement)?, agent_id: self.agent_id()?,
            nonce, expiry, model_hash: unhex_n(&self.config.model_hash)?, order,
        };
        let a = p.sign(&self.key()?)?;
        self.config.next_nonce = self.config.next_nonce.max(nonce + 1);
        self.save()?;
        Ok(a)
    }

    pub fn status(&mut self) -> Result<Status> {
        let rpc = self.rpc()?;
        let reg = self.registry(&rpc)?;
        let (id, s) = (self.agent_id()?, self.settlement()?);
        let pkh = self.pk_hash()?;
        let auth = rpc.view(reg, IAgentRegistry::isAuthorizedCall { id, pkHash: FixedBytes(pkh) })?;
        let a = rpc.view(reg, IAgentRegistry::agentsCall { id })?;
        let st = rpc.view(s, IBatchSettlementV2::agentStateCall { id })?;
        let fa = rpc.view(s, IBatchSettlementV2::feeAccountCall { id })?;
        let rem = rpc.view(s, IBatchSettlementV2::remainingActionsCall { id })?;
        Ok(Status {
            agent_id: id, pk_hash: hex0x(&pkh), authorized: auth, operator: format!("{:#x}", a.operator), active: a.active,
            killed: a.killed, stake: a.stake.to_string(), cap_base_in: a.capBaseIn.to_string(), cap_quote_in: a.capQuoteIn.to_string(),
            last_nonce: st.lastNonce, next_nonce: self.config.next_nonce.max(st.lastNonce + 1), fee_balance: fa.balance.to_string(),
            remaining_actions: if rem == U256::MAX { "unlimited".into() } else { rem.to_string() },
        })
    }
}
