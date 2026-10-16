//! Minimal blocking JSON-RPC client + the registry / settlement calls the CLI needs.
//! Transactions are EIP-1559, gas limit = eth_estimateGas (Monad charges the limit, not gas used).

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall, SolEvent};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// Env var holding the operator's EVM private key (hex). Never stored by the SDK.
pub const OPERATOR_KEY_ENV: &str = "PQAGENT_OPERATOR_KEY";

sol! {
    interface IAgentRegistry {
        function selfRegister(bytes32 pkHash, uint128 capBaseIn, uint128 capQuoteIn) external payable returns (uint32 id);
        function registerAgent(address operator, bytes32 pkHash, uint128 capBaseIn, uint128 capQuoteIn) external payable returns (uint32 id);
        function registrationFee() external view returns (uint96);
        function minStake() external view returns (uint96);
        function openRegistration() external view returns (bool);
        function defaultCapBaseIn() external view returns (uint128);
        function defaultCapQuoteIn() external view returns (uint128);
        function admin() external view returns (address);
        function isAuthorized(uint32 id, bytes32 pkHash) external view returns (bool);
        function agents(uint32 id) external view returns (address operator, bool active, bool killed, uint96 stake, uint128 capBaseIn, uint128 capQuoteIn);
        event AgentRegistered(uint32 indexed agentId, address operator, bytes32 pkHash, uint96 stake);
    }
    interface IBatchSettlementV2 {
        function registry() external view returns (address);
        function base() external view returns (address);
        function quote() external view returns (address);
        function agentState(uint32 id) external view returns (uint96 base, uint96 quote, uint64 lastNonce);
        function deposit(uint32 agentId, uint96 baseAmt, uint96 quoteAmt) external;
        function feeToken(uint8 idx) external view returns (address);
        function feeConfig(uint8 idx) external view returns (uint72 feePerAction, uint72 maxFeePerBatch, bool enabled, uint104 accrued);
        function feeAccount(uint32 id) external view returns (uint96 balance, uint96 threshold, uint8 token, bool low);
        function autoTopUp(uint32 id) external view returns (address from, uint96 amount);
        function pendingFeeWithdrawal(uint32 id) external view returns (uint96 amount, uint64 readyAt, address to);
        function feeQuote(uint32 id, uint256 actions) external view returns (uint256);
        function remainingActions(uint32 id) external view returns (uint256);
        function selectFeeToken(uint32 id, uint8 idx) external;
        function depositFeeNative(uint32 id) external payable;
        function depositFeeToken(uint32 id, uint256 amount) external;
        function setFeeAlert(uint32 id, uint96 threshold) external;
        function setAutoTopUp(uint32 id, uint96 amount) external;
        function batchDigest(uint64 batchId, bytes batch) external view returns (bytes32);
    }
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function balanceOf(address who) external view returns (uint256);
        function symbol() external view returns (string);
    }
}

pub struct Rpc {
    pub url: String,
    agent: ureq::Agent,
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub tx_hash: B256,
    pub status: bool,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub logs: Vec<Value>,
}

impl Rpc {
    pub fn new(url: &str) -> Self {
        Self { url: url.to_string(), agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build() }
    }

    pub fn call_raw(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: Value = self.agent.post(&self.url).send_json(body)
            .with_context(|| format!("rpc {method} to {}", self.url))?.into_json()?;
        if let Some(e) = resp.get("error") {
            let data = e.get("data").and_then(|d| d.as_str()).unwrap_or("");
            bail!("rpc {method}: {}{}", e.get("message").and_then(|m| m.as_str()).unwrap_or("error"),
                if data.is_empty() { String::new() } else { format!(" (data {data}{})", decode_revert(data)) });
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    fn qty(&self, method: &str, params: Value) -> Result<u128> {
        let v = self.call_raw(method, params)?;
        parse_qty(v.as_str().ok_or_else(|| anyhow!("{method}: not a quantity"))?)
    }

    pub fn chain_id(&self) -> Result<u64> {
        Ok(self.qty("eth_chainId", json!([]))? as u64)
    }
    pub fn balance(&self, a: Address) -> Result<U256> {
        Ok(U256::from(self.qty("eth_getBalance", json!([a, "latest"]))?))
    }

    /// eth_call returning the decoded return value.
    pub fn view<C: SolCall>(&self, to: Address, c: C) -> Result<C::Return> {
        let out = self.call_raw("eth_call", json!([{"to": to, "data": Bytes::from(c.abi_encode())}, "latest"]))?;
        let b = crate::action::unhex(out.as_str().unwrap_or("0x"))?;
        if b.is_empty() { bail!("eth_call {}: empty return (no contract at {to}?)", C::SIGNATURE) }
        C::abi_decode_returns(&b).map_err(|e| anyhow!("decode {}: {e}", C::SIGNATURE))
    }

    /// Sign and send a call; waits for the receipt and fails on revert.
    pub fn send<C: SolCall>(&self, signer: &PrivateKeySigner, to: Address, c: C, value: U256) -> Result<Receipt> {
        self.send_raw(signer, to, c.abi_encode(), value)
            .with_context(|| format!("tx {}", C::SIGNATURE))
    }

    pub fn send_raw(&self, signer: &PrivateKeySigner, to: Address, data: Vec<u8>, value: U256) -> Result<Receipt> {
        let from = signer.address();
        let chain_id = self.chain_id()?;
        let nonce = self.qty("eth_getTransactionCount", json!([from, "pending"]))? as u64;
        let input = Bytes::from(data);
        let gas = self.qty("eth_estimateGas", json!([{"from": from, "to": to, "data": input, "value": value}]))? as u64;
        let blk = self.call_raw("eth_getBlockByNumber", json!(["latest", false]))?;
        let base_fee = blk.get("baseFeePerGas").and_then(|v| v.as_str()).map(parse_qty).transpose()?.unwrap_or(0);
        let prio = 1_000_000_000u128;
        let tx = TxEip1559 {
            chain_id, nonce, gas_limit: gas,
            max_fee_per_gas: 2 * base_fee + prio,
            max_priority_fee_per_gas: prio,
            to: TxKind::Call(to), value, access_list: Default::default(), input,
        };
        let sig = signer.sign_hash_sync(&tx.signature_hash())?;
        let env: TxEnvelope = tx.into_signed(sig).into();
        let raw = Bytes::from(env.encoded_2718());
        let h = self.call_raw("eth_sendRawTransaction", json!([raw]))?;
        let tx_hash: B256 = h.as_str().ok_or_else(|| anyhow!("no tx hash"))?.parse()?;
        let t0 = Instant::now();
        loop {
            let r = self.call_raw("eth_getTransactionReceipt", json!([tx_hash]))?;
            if !r.is_null() {
                let rc = Receipt {
                    tx_hash,
                    status: r["status"].as_str() == Some("0x1"),
                    gas_used: parse_qty(r["gasUsed"].as_str().unwrap_or("0x0"))? as u64,
                    gas_limit: gas,
                    logs: r["logs"].as_array().cloned().unwrap_or_default(),
                };
                if !rc.status { bail!("transaction {tx_hash} reverted") }
                return Ok(rc);
            }
            if t0.elapsed() > Duration::from_secs(120) { bail!("no receipt for {tx_hash} after 120s") }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

pub fn parse_qty(s: &str) -> Result<u128> {
    u128::from_str_radix(s.trim_start_matches("0x"), 16).with_context(|| format!("bad quantity {s}"))
}

/// Best-effort decoding of this protocol's custom errors for nicer messages.
pub fn decode_revert(data: &str) -> String {
    const KNOWN: &[&str] = &[
        "RegistrationClosed()", "StakeTooLow(uint256,uint256)", "CapsTooHigh(uint128,uint128,uint128,uint128)",
        "NotOperator()", "NotAdmin()", "UnknownAgent(uint32)", "FeeTokenNotEnabled(uint8)", "WrongFeeToken(uint32,uint8)",
        "FeeAccountNotEmpty(uint32)", "InsufficientFeeBalance(uint32,uint256,uint256)", "BadFeeToken(uint8)",
        "AgentKilled(uint32)", "UnknownKey(uint32,bytes32)", "InsufficientBalance(uint32)", "NonceNotIncreasing(uint32,uint64,uint64)",
        "CapExceeded(uint32)", "Expired(uint256)", "AmountTooLarge()", "ZeroValue()",
        "UnsupportedToken(uint256,uint256)", "ZeroAddress()", "NotPendingAdmin()", "BadConfig()",
    ];
    let d = data.trim_start_matches("0x");
    if d.len() < 8 { return String::new() }
    for k in KNOWN {
        let sel = hex::encode(&alloy_primitives::keccak256(k.as_bytes())[..4]);
        if d[..8].eq_ignore_ascii_case(&sel) { return format!(" = {k}") }
    }
    String::new()
}

pub fn load_operator(key_file: Option<&std::path::Path>) -> Result<PrivateKeySigner> {
    let raw = zeroize::Zeroizing::new(match key_file {
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("read operator key {}", p.display()))?,
        None => std::env::var(OPERATOR_KEY_ENV)
            .map_err(|_| anyhow!("no operator key: pass --operator-key-file or set {OPERATOR_KEY_ENV}"))?,
    });
    let s = raw.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = zeroize::Zeroizing::new(hex::decode(s).map_err(|_| anyhow!("operator key is not hex"))?);
    if b.len() != 32 { bail!("operator key must be 32 bytes") }
    PrivateKeySigner::from_bytes(&B256::from_slice(&b)).map_err(|e| anyhow!("operator key: {e}"))
}

/// Agent id from the AgentRegistered log in a receipt.
pub fn registered_id(rc: &Receipt, registry: Address) -> Option<u32> {
    let topic = format!("{:#x}", IAgentRegistry::AgentRegistered::SIGNATURE_HASH);
    rc.logs.iter().find_map(|l| {
        let addr: Address = l["address"].as_str()?.parse().ok()?;
        let t = l["topics"].as_array()?;
        if addr != registry || t.first()?.as_str()? != topic { return None }
        Some(U256::from_str_radix(t.get(1)?.as_str()?.trim_start_matches("0x"), 16).ok()?.to::<u32>())
    })
}
