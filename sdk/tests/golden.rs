//! Golden vectors: the SDK must reproduce, byte for byte, keys / pkHashes known to the contracts and
//! the batches that were really proved (SP1 Groth16) and settled on Solonet.

use pqagent::action::{hex0x, unhex, ActionParams, Order, SignedAction};
use pqagent::batcher::{self, AgentOnChain, BatchOptions, Offline, StateSource};
use pqagent::keys::{self, AgentKey};
use serde_json::Value;

// contracts/script/DeploySolonet.s.sol TEST_PK_A / TEST_PK_B
const PK_A: &str = "0x8b1551c421b573beeaebb39debb1e0371e13c93155a7a5be60b29dd691095b05";
const PK_B: &str = "0x62d3462f41b0be23edd19e0aa7477bf95edcf207d9d325ddd73298cb14a946e3";

fn fixture(name: &str) -> Value {
    let p = format!("{}/../results/solonet/{name}/groth16-batch-fixture.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn test_keys_match_contract_pk_hashes() {
    assert_eq!(hex0x(&AgentKey::test_key(1).pk_hash()), PK_A);
    assert_eq!(hex0x(&AgentKey::test_key(2).pk_hash()), PK_B);
    assert_eq!(AgentKey::test_key(1).public_key().len(), keys::PUBLIC_KEY_LEN);
    // sha256 of the encoded verifying key, exactly
    let k = AgentKey::test_key(1);
    assert_eq!(keys::pk_hash(k.public_key()), k.pk_hash());
}

#[test]
fn model_hash_is_keccak() {
    assert_eq!(hex0x(&keys::model_hash(b"quantum-portfolio model v1 (test)")),
        hex0x(&alloy_primitives::keccak256(b"quantum-portfolio model v1 (test)").0));
}

/// Sign the host's deterministic order pattern with the SDK and run it through the batcher.
fn sdk_batch(n: u64, nonce_base: u64, batch_id: u64, chain_id: u64, settlement: [u8; 20]) -> pqagent::BatchInput {
    let keys = [AgentKey::test_key(1), AgentKey::test_key(2)];
    let model = keys::model_hash(b"quantum-portfolio model v1 (test)");
    let half = n.div_ceil(2);
    let mut actions = vec![];
    for i in 0..n {
        let g = (i >= half) as usize;
        let buy = i % 2 == 0;
        let amt: u128 = if buy { 2_000_000_000_000_000_000 } else { 1_000_000_000_000_000_000 } + i as u128 * 1_000_000_000_000_000;
        let p = ActionParams {
            chain_id, settlement, agent_id: g as u32 + 1, nonce: nonce_base + i + 1, expiry: u32::MAX,
            model_hash: model, order: Order { buy_base: buy, amount_in: amt, min_amount_out: 1 },
        };
        let s = p.sign(&keys[g]).unwrap();
        // round-trip through JSON like a real submission
        let s: SignedAction = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        actions.push((format!("{:03}.json", i), Ok(s)));
    }
    let opt = BatchOptions { chain_id, settlement, batch_id, min_validity_secs: 0, max_orders: 10_000 };
    let mut b = batcher::build(actions, &opt, &Offline { now: 1_700_000_000 }).unwrap();
    b.state_checks = "offline (signatures and framing only)".into();
    b
}

fn reproduce(name: &str) -> pqagent::BatchInput {
    let fx = fixture(name);
    let settlement: [u8; 20] = unhex(fx["settlement"].as_str().unwrap()).unwrap().try_into().unwrap();
    let b = sdk_batch(fx["n"].as_u64().unwrap(), fx["nonceBase"].as_u64().unwrap(), fx["batchId"].as_u64().unwrap(),
        fx["chainId"].as_u64().unwrap(), settlement);
    assert!(b.excluded.is_empty(), "{:?}", b.excluded);
    assert_eq!(b.batch, fx["batch"].as_str().unwrap(), "{name}: packed batch differs from the proved fixture");
    assert_eq!(b.digest, fx["digest"].as_str().unwrap(), "{name}: digest differs");
    assert_eq!(b.digest, fx["publicValues"].as_str().unwrap(), "{name}: digest != proof public values");
    b
}

#[test]
fn reproduces_proved_batch_b1_n10() {
    let b = reproduce("b1-n10");
    assert_eq!(b.orders, 10);
    // committed batcher output (guest-executed in CI): must regenerate identically
    let path = format!("{}/tests/fixtures/batch-input-b1-n10.json", env!("CARGO_MANIFEST_DIR"));
    let fresh = serde_json::to_string_pretty(&b).unwrap() + "\n";
    if std::env::var("PQAGENT_REGEN").is_ok() { std::fs::write(&path, &fresh).unwrap(); }
    assert_eq!(std::fs::read_to_string(&path).expect("fixture missing: PQAGENT_REGEN=1 cargo test"), fresh);
}

#[test]
fn reproduces_proved_batch_b2_n100() {
    let b = reproduce("b2-n100");
    assert_eq!(b.orders, 100);
    assert_eq!(b.groups.len(), 2);
    assert_eq!((b.groups[0].first_nonce, b.groups[1].first_nonce), (6, 56));
}

#[test]
fn message_layout_and_signature() {
    let k = AgentKey::test_key(1);
    let p = ActionParams {
        chain_id: 20143, settlement: [0x46; 20], agent_id: 7, nonce: 42, expiry: 1_800_000_000,
        model_hash: [0xab; 32], order: Order { buy_base: true, amount_in: 5, min_amount_out: 3 },
    };
    let m = p.message(k.pk_hash()).unwrap();
    assert_eq!(m.len(), 133);
    assert_eq!(&m[..32], &alloy_primitives::keccak256(b"EmpowerTours.AgentOrder.v2").0);
    assert_eq!(&m[32..40], &20143u64.to_be_bytes());
    assert_eq!(&m[40..60], &[0x46; 20]);
    assert_eq!(&m[60..64], &7u32.to_be_bytes());
    assert_eq!(&m[64..72], &42u64.to_be_bytes());
    assert_eq!(&m[72..76], &1_800_000_000u32.to_be_bytes());
    assert_eq!(&m[76..108], &[0xab; 32]);
    assert_eq!(hex::encode(&m[108..]), "01000000000000000000000005000000000000000000000003");
    let s = p.sign(&k).unwrap();
    assert_eq!(unhex(&s.signature).unwrap().len(), keys::SIGNATURE_LEN);
    s.verify().unwrap();
    // deterministic signing
    assert_eq!(p.sign(&k).unwrap().signature, s.signature);
    // any field change breaks verification
    let mut t = s.clone(); t.nonce = 43; assert!(t.verify().is_err());
    let mut t = s.clone(); t.order.amount_in = "6".into(); assert!(t.verify().is_err());
    let mut t = s.clone(); t.pk_hash = hex0x(&AgentKey::test_key(2).pk_hash()); assert!(t.verify().is_err());
    let mut t = s.clone(); t.public_key = hex0x(AgentKey::test_key(2).public_key()); assert!(t.verify().is_err());
    // amounts must be in (0, 2^96)
    assert!(Order { buy_base: false, amount_in: 0, min_amount_out: 0 }.encode().is_err());
    assert!(Order { buy_base: false, amount_in: 1 << 96, min_amount_out: 0 }.encode().is_err());
    assert_eq!(Order::decode(&p.order.encode().unwrap()).unwrap(), p.order);
}

#[test]
fn schema_covers_submission_fields() {
    let schema: Value = serde_json::from_str(include_str!("../schema/signed-action.v1.json")).unwrap();
    let s = serde_json::to_value(ActionParams {
        chain_id: 1, settlement: [1; 20], agent_id: 1, nonce: 1, expiry: 1, model_hash: [0; 32],
        order: Order { buy_base: false, amount_in: 1, min_amount_out: 0 },
    }.sign(&AgentKey::test_key(1)).unwrap()).unwrap();
    let mut req: Vec<&str> = schema["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    let mut have: Vec<&str> = s.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    req.sort(); have.sort();
    assert_eq!(req, have);
    let props = schema["properties"].as_object().unwrap();
    for (k, v) in s.as_object().unwrap() {
        if let Some(pat) = props[k].get("pattern").and_then(|p| p.as_str()) {
            // patterns are ^0x[0-9a-f]{N}$ — check length + charset
            let n: usize = pat.split('{').nth(1).and_then(|x| x.split('}').next()).and_then(|x| x.parse().ok()).unwrap_or(0);
            let st = v.as_str().unwrap();
            assert!(st.starts_with("0x") && st.len() == n + 2 && st[2..].chars().all(|c| c.is_ascii_hexdigit()), "{k}");
        }
    }
    assert_eq!(schema["properties"]["schema"]["const"], pqagent::action::SCHEMA_ID);
}

struct Fake {
    last: u64,
    fee_per: u128,
    fee_bal: u128,
    auth: bool,
    cap: u128,
}
impl StateSource for Fake {
    fn agent(&self, _: u32, _: [u8; 32]) -> anyhow::Result<AgentOnChain> {
        Ok(AgentOnChain { authorized: self.auth, last_nonce: self.last, base: u128::MAX, quote: u128::MAX,
            cap_base_in: self.cap, cap_quote_in: self.cap, fee_balance: self.fee_bal })
    }
    fn fee_quote(&self, _: u32, n: u64) -> anyhow::Result<u128> { Ok(n as u128 * self.fee_per) }
    fn now(&self) -> anyhow::Result<u64> { Ok(1000) }
}

#[test]
fn batcher_rules() {
    let k = AgentKey::test_key(1);
    let mk = |nonce: u64, expiry: u32, amt: u128| (format!("{nonce}-{expiry}.json"), Ok(ActionParams {
        chain_id: 1, settlement: [9; 20], agent_id: 5, nonce, expiry, model_hash: [1; 32],
        order: Order { buy_base: false, amount_in: amt, min_amount_out: 0 },
    }.sign(&k).unwrap()));
    let opt = BatchOptions { chain_id: 1, settlement: [9; 20], batch_id: 3, min_validity_secs: 60, max_orders: 100 };
    let set = || vec![mk(2, 5000, 10), mk(3, 5000, 10), mk(4, 5000, 10), mk(6, 5000, 10), mk(5, 9000, 10), mk(7, 1030, 10)];
    // lastNonce 2: nonce 2 stale; run 3,4; 5 has another expiry; 6 gap; 7 expires too soon
    let b = batcher::build(set(), &opt, &Fake { last: 2, fee_per: 1, fee_bal: 100, auth: true, cap: 1000 }).unwrap();
    assert_eq!((b.orders, b.groups[0].first_nonce), (2, 3));
    assert_eq!(b.excluded.len(), 4, "{:#?}", b.excluded);
    // fee balance pays for one action only -> trimmed to nonce 3
    let b = batcher::build(set(), &opt, &Fake { last: 2, fee_per: 7, fee_bal: 10, auth: true, cap: 1000 }).unwrap();
    assert_eq!(b.orders, 1);
    assert!(b.excluded.iter().any(|e| e.reason.contains("fee balance")));
    // cap 15 -> only one 10-unit order fits
    let b = batcher::build(set(), &opt, &Fake { last: 2, fee_per: 0, fee_bal: 0, auth: true, cap: 15 }).unwrap();
    assert_eq!(b.orders, 1);
    // unauthorized -> nothing
    let b = batcher::build(set(), &opt, &Fake { last: 2, fee_per: 0, fee_bal: 0, auth: false, cap: 1000 }).unwrap();
    assert_eq!(b.orders, 0);
    // wrong settlement and a forged signature are rejected
    let mut forged = mk(3, 5000, 10).1.unwrap(); forged.order.amount_in = "11".into();
    let wrong = ("w.json".to_string(), Ok(ActionParams { chain_id: 1, settlement: [8; 20], agent_id: 5, nonce: 3, expiry: 5000,
        model_hash: [1; 32], order: Order { buy_base: false, amount_in: 1, min_amount_out: 0 } }.sign(&k).unwrap()));
    let b = batcher::build(vec![("f.json".into(), Ok(forged)), wrong], &opt, &Offline { now: 0 }).unwrap();
    assert_eq!(b.orders, 0);
    assert_eq!(b.excluded.len(), 2);
}

#[test]
fn keystore_permissions_and_encryption() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("ks");
    keys::ensure_private_dir(&dir).unwrap();
    let k = AgentKey::generate().unwrap();
    let plain = dir.join("plain.json");
    keys::save_key(&plain, &k, None).unwrap();
    let enc = dir.join("enc.json");
    keys::save_key(&enc, &k, Some("correct horse")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&plain).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&enc).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(keys::load_key(&plain, None).unwrap().pk_hash(), k.pk_hash());
    assert_eq!(keys::load_key(&enc, Some("correct horse")).unwrap().pk_hash(), k.pk_hash());
    assert!(keys::load_key(&enc, Some("wrong")).is_err());
    assert!(keys::load_key(&enc, None).is_err());
    let raw: Value = serde_json::from_slice(&std::fs::read(&enc).unwrap()).unwrap();
    assert!(raw.get("seed").is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(keys::load_key(&plain, None).is_err(), "world-readable key must be refused");
    }
}
