//! `.pqagent/config.json` (no secrets) and amount helpers.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const CONFIG_SCHEMA: &str = "pq-agent-batch/agent-config/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc: Option<String>,
    pub chain_id: u64,
    pub settlement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<u32>,
    pub pk_hash: String,
    pub model_hash: String,
    /// where the model hash came from (file path or "string"), informational
    pub model_source: String,
    pub key_encrypted: bool,
    /// next nonce `sign` will use (the CLI also never goes at or below on-chain lastNonce)
    pub next_nonce: u64,
    /// default expiry = now + ttl rounded UP to this bucket, so actions signed close together share
    /// one expiry and can be packed into one group
    pub expiry_bucket_secs: u32,
}

impl Config {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("config.json")
    }
    pub fn load(dir: &Path) -> Result<Self> {
        let p = Self::path(dir);
        let c: Config = serde_json::from_slice(&std::fs::read(&p).with_context(|| format!("read {} (run `pqagent init` first)", p.display()))?)
            .with_context(|| format!("parse {}", p.display()))?;
        if c.schema != CONFIG_SCHEMA { bail!("unknown config schema {}", c.schema) }
        Ok(c)
    }
    pub fn save(&self, dir: &Path) -> Result<()> {
        let mut s = serde_json::to_string_pretty(self)?;
        s.push('\n');
        std::fs::write(Self::path(dir), s)?;
        Ok(())
    }
}

/// Parse an amount: plain integer = token base units (wei); `<decimal>mon`, `<decimal>ether` or
/// `<decimal>e<N>` = × 10^N; `<decimal>gwei` = × 10^9. Example: `0.05mon`, `2.5ether`, `1e17`, `1000`.
pub fn parse_amount(s: &str) -> Result<u128> {
    let t = s.trim().to_ascii_lowercase().replace('_', "");
    let (num, dec): (&str, usize) = if let Some(n) = t.strip_suffix("mon").or_else(|| t.strip_suffix("ether")) {
        (n.trim(), 18)
    } else if let Some(n) = t.strip_suffix("gwei") {
        (n.trim(), 9)
    } else if let Some((n, e)) = t.split_once('e') {
        (n.trim(), e.parse::<usize>().ok().filter(|e| *e <= 36).ok_or_else(|| anyhow::anyhow!("bad exponent in {s:?}"))?)
    } else {
        (t.as_str(), 0)
    };
    let (i, f) = num.split_once('.').unwrap_or((num, ""));
    if i.is_empty() && f.is_empty() { bail!("bad amount {s:?}") }
    if f.len() > dec { bail!("amount {s:?} has more than {dec} decimals") }
    if !i.chars().chain(f.chars()).all(|c| c.is_ascii_digit()) { bail!("bad amount {s:?}") }
    let digits = format!("{}{}{}", i, f, "0".repeat(dec - f.len()));
    let v = digits.trim_start_matches('0');
    if v.is_empty() { return Ok(0) }
    v.parse::<u128>().with_context(|| format!("amount {s:?} too large"))
}

/// `1234500000000000000` -> `1.2345` (18 decimals), trailing zeros trimmed.
pub fn fmt_units(v: u128) -> String {
    let i = v / 1_000_000_000_000_000_000;
    let f = v % 1_000_000_000_000_000_000;
    if f == 0 { return i.to_string() }
    let fs = format!("{:018}", f);
    format!("{}.{}", i, fs.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn amounts() {
        assert_eq!(parse_amount("1000").unwrap(), 1000);
        assert_eq!(parse_amount("0.05mon").unwrap(), 50_000_000_000_000_000);
        assert_eq!(parse_amount("2.5ether").unwrap(), 2_500_000_000_000_000_000);
        assert_eq!(parse_amount("3gwei").unwrap(), 3_000_000_000);
        assert_eq!(parse_amount("1_000e18").unwrap(), 1000 * 10u128.pow(18));
        assert!(parse_amount("1.5").is_err());
        assert_eq!(parse_amount("1e17").unwrap(), 10u128.pow(17));
        assert_eq!(parse_amount("2.5e6").unwrap(), 2_500_000);
        assert!(parse_amount("1.25e1").is_err());
        assert!(parse_amount("abc").is_err());
        assert_eq!(fmt_units(1_234_500_000_000_000_000), "1.2345");
        assert_eq!(fmt_units(5 * 10u128.pow(18)), "5");
    }
}
