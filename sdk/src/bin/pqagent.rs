//! `pqagent` — register a post-quantum AI agent and submit ML-DSA-65 signed actions.
//! Run `pqagent <command> --help` for details. See sdk/README.md for the 5-minute quickstart.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use pqagent::action::{hex0x, unhex_n, Order, SignedAction};
use pqagent::agent::{Agent, InitOptions};
use pqagent::batcher::{self, BatchOptions, Offline, OnChain};
use pqagent::chain::{load_operator, Receipt, Rpc};
use pqagent::config::{fmt_units, parse_amount};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "pqagent", version, about = "Post-quantum (ML-DSA-65) agent keys, registration, fees and signed actions for pq-agent-batch")]
struct Cli {
    /// keystore directory (key.json 0600, config.json, pubkey.hex)
    #[arg(long, global = true, env = "PQAGENT_DIR", default_value = ".pqagent")]
    dir: PathBuf,
    /// JSON-RPC endpoint (overrides config.json)
    #[arg(long, global = true, env = "PQAGENT_RPC")]
    rpc: Option<String>,
    /// machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct OperatorArgs {
    /// file with the operator's EVM private key (hex). Alternative: env PQAGENT_OPERATOR_KEY
    #[arg(long)]
    operator_key_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an ML-DSA-65 agent key + config (private key never printed)
    Init {
        /// BatchSettlementV2 address
        #[arg(long)]
        settlement: String,
        /// chain id (queried from --rpc when omitted)
        #[arg(long)]
        chain_id: Option<u64>,
        /// model artifact: modelHash = keccak256(file bytes)
        #[arg(long, conflicts_with = "model")]
        model_file: Option<PathBuf>,
        /// model identifier string: modelHash = keccak256(utf8)
        #[arg(long)]
        model: Option<String>,
        /// set if the agent is already registered (e.g. by the admin)
        #[arg(long)]
        agent_id: Option<u32>,
        /// default expiry bucket in seconds (actions signed within one bucket share an expiry)
        #[arg(long, default_value_t = 3600)]
        expiry_bucket: u32,
        /// overwrite an existing key (destroys it)
        #[arg(long)]
        force: bool,
        /// INSECURE: reproduce the repo's public TEST key N (golden vectors / demos only)
        #[arg(long, hide = true)]
        test_seed: Option<u8>,
    },
    /// Self-register on the registry: pays registrationFee + bond via msg.value
    Register {
        #[command(flatten)]
        op: OperatorArgs,
        /// per-batch cap on base sold (token units, e.g. 1000e18); 0 = registry maximum
        #[arg(long, default_value = "0")]
        cap_base: String,
        /// per-batch cap on quote spent; 0 = registry maximum
        #[arg(long, default_value = "0")]
        cap_quote: String,
        /// bond on top of the registry's minStake (refunded on retire)
        #[arg(long, default_value = "0")]
        extra_bond: String,
    },
    /// Deposit to the prepaid fee balance (native MON, or the selected ERC20: approve + deposit)
    Fund {
        #[command(flatten)]
        op: OperatorArgs,
        /// amount, e.g. 0.05mon or 50000000000000000
        #[arg(long)]
        amount: String,
        /// switch fee token first (0 = native MON, 1..3 = listed ERC20s); balance must be zero
        #[arg(long)]
        token: Option<u8>,
    },
    /// Deposit trading balances (base / quote ERC20s) that orders spend
    Deposit {
        #[command(flatten)]
        op: OperatorArgs,
        #[arg(long, default_value = "0")]
        base: String,
        #[arg(long, default_value = "0")]
        quote: String,
    },
    /// Fee balance, remaining actions, alert/top-up config, trading balances
    Balance,
    /// Set the low-balance alert threshold and optional ERC20 auto top-up
    Alert {
        #[command(flatten)]
        op: OperatorArgs,
        /// LowFeeBalance fires once when the balance drops below this (0 = off)
        #[arg(long)]
        threshold: String,
        /// amount pulled from the operator per permissionless topUp() (ERC20 fee tokens only; 0 = off)
        #[arg(long)]
        auto_topup: Option<String>,
        /// also approve the settlement to pull this much fee token for top-ups
        #[arg(long)]
        approve: Option<String>,
    },
    /// Build + ML-DSA sign one order; writes the submission JSON
    Sign {
        /// buy base with quote
        #[arg(long, conflicts_with = "sell", required_unless_present = "sell")]
        buy: bool,
        /// sell base for quote
        #[arg(long)]
        sell: bool,
        /// amountIn (token units, e.g. 2e18 / 2ether / raw integer)
        #[arg(long)]
        amount: String,
        /// minimum amountOut (slippage bound). Required: an order without one can be sandwiched for its
        /// whole value (audit M-02). Pass --no-slippage-limit to sign minOut = 0 deliberately.
        #[arg(long, required_unless_present = "no_slippage_limit")]
        min_out: Option<String>,
        /// sign with minOut = 0 (no slippage protection); only for tests
        #[arg(long, conflicts_with = "min_out")]
        no_slippage_limit: bool,
        /// nonce (default: max(local counter, on-chain lastNonce + 1))
        #[arg(long)]
        nonce: Option<u64>,
        /// absolute unix expiry (default: now + --ttl rounded up to the expiry bucket)
        #[arg(long)]
        expiry: Option<u32>,
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// output file (default: stdout); a directory (existing, or a new path ending in / or without a
        /// .json extension, which is created) gets <agentId>-<nonce>.json
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Registry authorization + agent info
    Status,
    /// Verify a signed-action JSON file offline (schema, pkHash, signature)
    Verify { file: PathBuf },
    /// Reference batcher: signed actions in a directory -> zk-batch host input (batch-input.json)
    Batch {
        /// directory of signed-action JSON files
        #[arg(long)]
        actions: PathBuf,
        #[arg(long)]
        batch_id: u64,
        #[arg(long, short)]
        out: PathBuf,
        /// settlement (default: from config.json)
        #[arg(long)]
        settlement: Option<String>,
        #[arg(long)]
        chain_id: Option<u64>,
        /// skip on-chain checks (authorization, lastNonce, caps, balances, feeQuote)
        #[arg(long)]
        offline: bool,
        /// drop actions expiring within this many seconds (time to prove + land)
        #[arg(long, default_value_t = 0)]
        min_validity: u64,
        #[arg(long, default_value_t = 1000)]
        max_orders: usize,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn open(cli: &Cli) -> Result<Agent> {
    let mut a = Agent::open(&cli.dir)?;
    if let Some(r) = &cli.rpc {
        if a.config.rpc.as_deref() != Some(r) { a.config.rpc = Some(r.clone()); a.save()?; }
    }
    Ok(a)
}

fn amt(s: &str) -> Result<u128> { parse_amount(s) }

fn txs(cli: &Cli, rcs: &[Receipt]) {
    if cli.json { return }
    for r in rcs { println!("  tx {:#x}  gasUsed {} (limit {})", r.tx_hash, r.gas_used, r.gas_limit) }
}

fn print<T: serde::Serialize>(cli: &Cli, v: &T, human: impl FnOnce()) -> Result<()> {
    if cli.json { println!("{}", serde_json::to_string_pretty(v)?) } else { human() }
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    match &cli.cmd {
        Cmd::Init { settlement, chain_id, model_file, model, agent_id, expiry_bucket, force, test_seed } => {
            let (bytes, src) = match (model_file, model) {
                (Some(f), _) => (std::fs::read(f).with_context(|| format!("read {}", f.display()))?, f.display().to_string()),
                (None, Some(s)) => (s.as_bytes().to_vec(), format!("string:{s}")),
                (None, None) => bail!("pass --model-file <path> or --model <string>"),
            };
            let chain_id = match (chain_id, &cli.rpc) {
                (Some(c), _) => *c,
                (None, Some(r)) => Rpc::new(r).chain_id()?,
                (None, None) => bail!("pass --chain-id or --rpc"),
            };
            let pass = std::env::var(pqagent::keys::PASSPHRASE_ENV).ok().filter(|p| !p.is_empty());
            let mut a = Agent::init(&cli.dir, InitOptions {
                chain_id, settlement: settlement.parse().context("--settlement")?, rpc: cli.rpc.clone(), model: bytes,
                model_source: src, passphrase: pass, test_seed: *test_seed, force: *force, expiry_bucket_secs: *expiry_bucket,
            })?;
            if let Some(id) = agent_id { a.config.agent_id = Some(*id); a.save()?; }
            let c = &a.config;
            print(&cli, c, || {
                if test_seed.is_some() { println!("WARNING: --test-seed reproduces a PUBLIC test key; never use it for real funds") }
                println!("initialised {} (dir 0700, key.json 0600, encrypted: {})", cli.dir.display(), if c.key_encrypted { "yes (PQAGENT_PASSPHRASE)" } else { "no" });
                println!("pkHash     {}", c.pk_hash);
                println!("modelHash  {}  ({})", c.model_hash, c.model_source);
                println!("publicKey  {}/pubkey.hex (1952 bytes)", cli.dir.display());
                println!("chainId    {}  settlement {}", c.chain_id, c.settlement);
                println!("next: pqagent register --operator-key-file <file>");
            })
        }
        Cmd::Register { op, cap_base, cap_quote, extra_bond } => {
            let mut a = open(&cli)?;
            let signer = load_operator(op.operator_key_file.as_deref())?;
            let r = a.register(&signer, amt(cap_base)?, amt(cap_quote)?, amt(extra_bond)?)?;
            print(&cli, &r, || {
                println!("registered agent {}  (operator {:#x})", r.agent_id, signer.address());
                println!("  paid registrationFee {} MON + bond {} MON", fmt_units(r.registration_fee.parse().unwrap()), fmt_units(r.bond.parse().unwrap()));
                println!("  caps per batch: base {}  quote {}", fmt_units(r.cap_base_in.parse().unwrap()), fmt_units(r.cap_quote_in.parse().unwrap()));
                println!("  tx {}  gasUsed {}", r.tx_hash, r.gas_used);
                println!("AGENT_ID={}", r.agent_id);
            })
        }
        Cmd::Fund { op, amount, token } => {
            let mut a = open(&cli)?;
            let signer = load_operator(op.operator_key_file.as_deref())?;
            let v = amt(amount)?;
            let rcs = a.fund(&signer, v, *token)?;
            let b = a.balance()?;
            print(&cli, &b, || {
                println!("deposited {} ({} units) to agent {} fee balance", fmt_units(v), v, b.agent_id);
                txs(&cli, &rcs);
                println!("fee balance {} {}  remainingActions {}", fmt_units(b.fee_balance.parse().unwrap()), b.fee_token, b.remaining_actions);
            })
        }
        Cmd::Deposit { op, base, quote } => {
            let mut a = open(&cli)?;
            let signer = load_operator(op.operator_key_file.as_deref())?;
            let rcs = a.deposit_trading(&signer, amt(base)?, amt(quote)?)?;
            let b = a.balance()?;
            print(&cli, &b, || {
                txs(&cli, &rcs);
                println!("trading balances: base {}  quote {}", fmt_units(b.trading_base.parse().unwrap()), fmt_units(b.trading_quote.parse().unwrap()));
            })
        }
        Cmd::Balance => {
            let mut a = open(&cli)?;
            let b = a.balance()?;
            print(&cli, &b, || {
                let u = |s: &str| fmt_units(s.parse().unwrap_or(0));
                println!("agent {}", b.agent_id);
                println!("  fee token        #{} {}", b.fee_token_index, b.fee_token);
                println!("  fee balance      {}  ({} units)", u(&b.fee_balance), b.fee_balance);
                println!("  fee per action   {}  (cap per batch {})", u(&b.fee_per_action), if b.max_fee_per_batch == "0" { "none".into() } else { u(&b.max_fee_per_batch) });
                println!("  remainingActions {}", b.remaining_actions);
                println!("  alert threshold  {}  low={}", u(&b.alert_threshold), b.low);
                println!("  auto top-up      {}", if b.auto_top_up_amount == "0" { "off".into() } else { format!("{} from {}", u(&b.auto_top_up_amount), b.auto_top_up_from) });
                println!("  pending withdraw {}", b.pending_withdrawal);
                println!("  trading balances base {}  quote {}", u(&b.trading_base), u(&b.trading_quote));
                println!("  lastNonce        {}", b.last_nonce);
            })
        }
        Cmd::Alert { op, threshold, auto_topup, approve } => {
            let mut a = open(&cli)?;
            let signer = load_operator(op.operator_key_file.as_deref())?;
            let rcs = a.set_alert(&signer, amt(threshold)?, auto_topup.as_deref().map(amt).transpose()?, approve.as_deref().map(amt).transpose()?)?;
            let b = a.balance()?;
            print(&cli, &b, || {
                txs(&cli, &rcs);
                println!("alert threshold {}  low={}  auto top-up {}", fmt_units(b.alert_threshold.parse().unwrap()), b.low, b.auto_top_up_amount);
            })
        }
        Cmd::Sign { buy, sell: _, amount, min_out, no_slippage_limit: _, nonce, expiry, ttl, out } => {
            let mut a = open(&cli)?;
            let rpc = match &a.config.rpc { Some(_) => a.rpc().ok(), None => None };
            let nonce = match nonce { Some(n) => *n, None => a.next_nonce(rpc.as_ref())? };
            let expiry = match expiry {
                Some(e) => *e,
                None => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                    a.default_expiry(now, *ttl)?
                }
            };
            let order = Order { buy_base: *buy, amount_in: amt(amount)?, min_amount_out: match min_out { Some(m) => amt(m)?, None => 0 } };
            let s = a.sign(order, nonce, expiry)?;
            let js = serde_json::to_string_pretty(&s)? + "\n";
            match out {
                None => print!("{js}"),
                Some(p) => {
                    let as_dir = p.is_dir() || (!p.exists()
                        && (p.as_os_str().to_string_lossy().ends_with('/') || p.extension().map_or(true, |e| e != "json")));
                    if as_dir { std::fs::create_dir_all(p)?; }
                    let path = if as_dir { p.join(format!("{:06}-{:012}.json", s.agent_id, s.nonce)) } else { p.clone() };
                    std::fs::write(&path, js)?;
                    if !cli.json {
                        println!("signed agent {} nonce {} expiry {} {} {} (minOut {}) -> {}", s.agent_id, s.nonce, s.expiry,
                            s.order.side, s.order.amount_in, s.order.min_amount_out, path.display());
                    }
                }
            }
            Ok(())
        }
        Cmd::Status => {
            let mut a = open(&cli)?;
            let s = a.status()?;
            print(&cli, &s, || {
                println!("agent {}  authorized={}  active={}  killed={}", s.agent_id, s.authorized, s.active, s.killed);
                println!("  pkHash   {}", s.pk_hash);
                println!("  operator {}  stake {} MON", s.operator, fmt_units(s.stake.parse().unwrap()));
                println!("  caps     base {}  quote {}", fmt_units(s.cap_base_in.parse().unwrap()), fmt_units(s.cap_quote_in.parse().unwrap()));
                println!("  nonces   lastNonce {}  next {}", s.last_nonce, s.next_nonce);
                println!("  fees     balance {}  remainingActions {}", fmt_units(s.fee_balance.parse().unwrap()), s.remaining_actions);
            })
        }
        Cmd::Verify { file } => {
            let s: SignedAction = serde_json::from_slice(&std::fs::read(file)?)?;
            let p = s.verify()?;
            print(&cli, &serde_json::json!({"valid": true, "agentId": p.agent_id, "nonce": p.nonce}), || {
                println!("OK: valid ML-DSA-65 signature; agent {} nonce {} pkHash {}", p.agent_id, p.nonce, s.pk_hash)
            })
        }
        Cmd::Batch { actions, batch_id, out, settlement, chain_id, offline, min_validity, max_orders } => {
            let cfg = Agent::open(&cli.dir).ok().map(|a| a.config);
            let settlement: [u8; 20] = match (settlement, &cfg) {
                (Some(s), _) => unhex_n(s)?,
                (None, Some(c)) => unhex_n(&c.settlement)?,
                _ => bail!("pass --settlement (no config.json found)"),
            };
            let rpc_url = cli.rpc.clone().or_else(|| cfg.as_ref().and_then(|c| c.rpc.clone()));
            let rpc = rpc_url.as_deref().map(Rpc::new);
            let chain_id = match (chain_id, &rpc, &cfg) {
                (Some(c), _, _) => *c,
                (None, Some(r), _) if !offline => r.chain_id()?,
                (None, _, Some(c)) => c.chain_id,
                _ => bail!("pass --chain-id"),
            };
            let opt = BatchOptions { chain_id, settlement, batch_id: *batch_id, min_validity_secs: *min_validity, max_orders: *max_orders };
            let loaded = batcher::load_dir(actions)?;
            let mut bi = if *offline {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                let mut b = batcher::build(loaded, &opt, &Offline { now })?;
                b.state_checks = "offline (signatures and framing only)".into();
                b
            } else {
                let rpc = rpc.as_ref().ok_or_else(|| anyhow!("on-chain checks need --rpc (or pass --offline)"))?;
                let st = OnChain::new(rpc, settlement.into())?;
                let mut b = batcher::build(loaded, &opt, &st)?;
                b.state_checks = format!("on-chain via {} (registry {:#x})", rpc.url, st.registry);
                b
            };
            if bi.orders == 0 { bi.digest = hex0x(&[0u8; 32]); }
            std::fs::write(out, serde_json::to_string_pretty(&bi)? + "\n")?;
            print(&cli, &bi, || {
                println!("batch {}: {} orders in {} groups, {} bytes, digest {}", bi.batch_id, bi.orders, bi.groups.len(),
                    (bi.batch.len() - 2) / 2, bi.digest);
                for g in &bi.groups { println!("  agent {} nonces {}..{} feeQuote {}", g.agent_id, g.first_nonce, g.first_nonce + g.count as u64 - 1, g.fee_quote) }
                for e in &bi.excluded { println!("  excluded {} (agent {} nonce {}): {}", e.source, e.agent_id.map(|v| v.to_string()).unwrap_or("?".into()), e.nonce.map(|v| v.to_string()).unwrap_or("?".into()), e.reason) }
                println!("wrote {}  -> prove: cd zk-batch/script && cargo run --release --bin batch -- --execute --input {}", out.display(), abs(out));
            })?;
            if bi.orders == 0 { bail!("no valid actions to batch") }
            Ok(())
        }
    }
}

fn abs(p: &Path) -> String {
    std::fs::canonicalize(p).map(|p| p.display().to_string()).unwrap_or_else(|_| p.display().to_string())
}
