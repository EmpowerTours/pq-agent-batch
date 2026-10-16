//! Signed actions: the packed order encoding, the exact 133-byte message the guest verifies, and the
//! JSON submission format accepted by the batcher (`schema/signed-action.v1.json`).

use crate::keys::{self, AgentKey};
use agent_batch_lib::{order_message, Group, ORDER};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

pub const SCHEMA_ID: &str = "pq-agent-batch/signed-action/v1";
pub const MAX_U96: u128 = (1u128 << 96) - 1;

/// One order. `buy_base = true` spends quote for base (flags bit0 = 1); false sells base for quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Order {
    pub buy_base: bool,
    pub amount_in: u128,
    pub min_amount_out: u128,
}

impl Order {
    /// 25-byte packed order: flags u8 | amountIn u96 | minAmountOut u96 (big-endian).
    pub fn encode(&self) -> Result<[u8; ORDER]> {
        ensure!(self.amount_in > 0, "amountIn must be > 0 (contract: ZeroAmount)");
        ensure!(self.amount_in <= MAX_U96 && self.min_amount_out <= MAX_U96, "amounts must fit in uint96");
        let mut o = [0u8; ORDER];
        o[0] = self.buy_base as u8;
        o[1..13].copy_from_slice(&self.amount_in.to_be_bytes()[4..]);
        o[13..25].copy_from_slice(&self.min_amount_out.to_be_bytes()[4..]);
        Ok(o)
    }

    pub fn decode(o: &[u8]) -> Result<Self> {
        ensure!(o.len() == ORDER && o[0] <= 1, "bad order encoding");
        let mut a = [0u8; 16];
        let mut m = [0u8; 16];
        a[4..].copy_from_slice(&o[1..13]);
        m[4..].copy_from_slice(&o[13..25]);
        Ok(Self { buy_base: o[0] == 1, amount_in: u128::from_be_bytes(a), min_amount_out: u128::from_be_bytes(m) })
    }
}

/// Everything bound into one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionParams {
    pub chain_id: u64,
    pub settlement: [u8; 20],
    pub agent_id: u32,
    pub nonce: u64,
    pub expiry: u32,
    pub model_hash: [u8; 32],
    pub order: Order,
}

impl ActionParams {
    /// The exact signed message (133 B). Built with the guest's own `order_message`, as order 0 of a
    /// one-order group starting at `nonce`, which equals order j of any group with firstNonce + j == nonce.
    pub fn message(&self, pk_hash: [u8; 32]) -> Result<Vec<u8>> {
        let o = self.order.encode()?;
        let g = Group {
            agent_id: self.agent_id, count: 1, first_nonce: self.nonce, expiry: self.expiry,
            pk_hash, model_hash: self.model_hash, orders_at: 0,
        };
        Ok(order_message(self.chain_id, self.settlement, &g, 0, &o))
    }

    pub fn sign(&self, key: &AgentKey) -> Result<SignedAction> {
        let msg = self.message(key.pk_hash())?;
        let sig = key.sign(&msg);
        Ok(SignedAction {
            schema: SCHEMA_ID.into(),
            chain_id: self.chain_id,
            settlement: hex0x(&self.settlement),
            agent_id: self.agent_id,
            nonce: self.nonce,
            expiry: self.expiry,
            model_hash: hex0x(&self.model_hash),
            pk_hash: hex0x(&key.pk_hash()),
            order: OrderJson {
                side: if self.order.buy_base { "buy".into() } else { "sell".into() },
                amount_in: self.order.amount_in.to_string(),
                min_amount_out: self.order.min_amount_out.to_string(),
            },
            order_bytes: hex0x(&self.order.encode()?),
            message: hex0x(&msg),
            public_key: hex0x(key.public_key()),
            signature: hex0x(&sig),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OrderJson {
    /// "buy" = buy base with quote (flags 1), "sell" = sell base for quote (flags 0)
    pub side: String,
    /// decimal string, token base units, 0 < x < 2^96
    pub amount_in: String,
    pub min_amount_out: String,
}

/// JSON submission accepted by the batcher. `orderBytes` and `message` are redundant (derivable from
/// the other fields) and are re-derived and compared on load.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAction {
    pub schema: String,
    pub chain_id: u64,
    pub settlement: String,
    pub agent_id: u32,
    pub nonce: u64,
    pub expiry: u32,
    pub model_hash: String,
    pub pk_hash: String,
    pub order: OrderJson,
    pub order_bytes: String,
    pub message: String,
    pub public_key: String,
    pub signature: String,
}

pub fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).with_context(|| format!("bad hex: {:.20}…", s))
}

pub fn unhex_n<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = unhex(s)?;
    v.as_slice().try_into().map_err(|_| anyhow::anyhow!("expected {N} bytes, got {}", v.len()))
}

impl SignedAction {
    pub fn params(&self) -> Result<ActionParams> {
        let side = match self.order.side.as_str() { "buy" => true, "sell" => false, s => bail!("side must be buy|sell, got {s}") };
        Ok(ActionParams {
            chain_id: self.chain_id,
            settlement: unhex_n(&self.settlement)?,
            agent_id: self.agent_id,
            nonce: self.nonce,
            expiry: self.expiry,
            model_hash: unhex_n(&self.model_hash)?,
            order: Order {
                buy_base: side,
                amount_in: self.order.amount_in.parse().context("amountIn")?,
                min_amount_out: self.order.min_amount_out.parse().context("minAmountOut")?,
            },
        })
    }

    /// Full offline check: schema, field consistency, sha256(publicKey) == pkHash, ML-DSA signature
    /// over the re-derived message.
    pub fn verify(&self) -> Result<ActionParams> {
        ensure!(self.schema == SCHEMA_ID, "unknown schema {}", self.schema);
        ensure!(self.agent_id > 0, "agentId must be > 0");
        let p = self.params()?;
        let pk = unhex(&self.public_key)?;
        ensure!(pk.len() == keys::PUBLIC_KEY_LEN, "publicKey must be {} bytes", keys::PUBLIC_KEY_LEN);
        let pkh: [u8; 32] = unhex_n(&self.pk_hash)?;
        ensure!(keys::pk_hash(&pk) == pkh, "pkHash != sha256(publicKey)");
        ensure!(unhex(&self.order_bytes)? == p.order.encode()?, "orderBytes inconsistent with order");
        let msg = p.message(pkh)?;
        ensure!(unhex(&self.message)? == msg, "message inconsistent with fields");
        let sig = unhex(&self.signature)?;
        ensure!(sig.len() == keys::SIGNATURE_LEN, "signature must be {} bytes", keys::SIGNATURE_LEN);
        ensure!(keys::verify(&pk, &msg, &sig), "ML-DSA-65 signature does not verify");
        Ok(p)
    }
}
