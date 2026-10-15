//! Host (v2): derive 2 deterministic TEST ML-DSA-65 agent keys, build a packed batch
//! (same order pattern as contracts/script/BuildBatchV2.s.sol), sign every order, then
//! execute the guest (cycle counts) or prove it.
//!   cargo run --release -- --execute -n 100
//!   cargo run --release -- --prove -n 10    (needs a large-RAM machine; see README)
use agent_batch_lib::{batch_digest, order_message, parse_batch, verify_batch};
use alloy_primitives::keccak256;
use clap::Parser;
use ml_dsa::{MlDsa65, SigningKey, B32};
use sha2::{Digest, Sha256};
use sp1_sdk::{blocking::{MockProver, ProveRequest, Prover, ProverClient}, include_elf, Elf, HashableKey, ProvingKey, SP1Stdin};

const ELF: Elf = include_elf!("agent-batch-program");

#[derive(Parser)]
struct Args {
    #[arg(long)] execute: bool,
    #[arg(long)] prove: bool,
    #[arg(short, long, default_value_t = 2)] n: u32,
    #[arg(long, default_value_t = 20143)] chain_id: u64,
    #[arg(long, default_value = "0000000000000000000000000000000000000000")] settlement: String,
    #[arg(long, default_value_t = 1)] batch_id: u64,
    #[arg(long, default_value_t = 0)] nonce_base: u64,
    #[arg(long)] out: Option<String>,
    /// negative test: flip one bit of the LAST order's amountIn after signing
    #[arg(long)] tamper: bool,
    /// --prove: directory for proof artifacts (proof.bin, groth16-batch-fixture.json)
    #[arg(long, default_value = "proof-out")] proof_dir: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let a = Args::parse();
    assert!(a.execute != a.prove, "specify exactly one of --execute / --prove");
    let mut settlement = [0u8; 20];
    settlement.copy_from_slice(&hex::decode(a.settlement.trim_start_matches("0x")).unwrap());

    let keys: Vec<_> = (1u8..=2).map(|i| {
        let seed = B32::from(keccak256([b"EmpowerTours test agent seed ".as_slice(), &[i]].concat()).0);
        SigningKey::<MlDsa65>::from_seed(&seed)
    }).collect();
    let pks: Vec<Vec<u8>> = keys.iter().map(|k| k.expanded_key().verifying_key().encode().to_vec()).collect();
    let model_hash = keccak256(b"quantum-portfolio model v1 (test)");

    // ---- packed batch
    let n = a.n as u64;
    let half = (n + 1) / 2;
    let mut batch = Vec::new();
    let (mut base_in, mut quote_in) = (0u128, 0u128);
    let mut used = vec![];
    for g in 0..2u64 {
        let (from, to) = if g == 0 { (0, half) } else { (half, n) };
        if to == from { continue; }
        used.push(g as usize);
        batch.extend_from_slice(&((g + 1) as u32).to_be_bytes());
        batch.extend_from_slice(&((to - from) as u16).to_be_bytes());
        batch.extend_from_slice(&(a.nonce_base + from + 1).to_be_bytes());
        batch.extend_from_slice(&u32::MAX.to_be_bytes());
        batch.extend_from_slice(&Sha256::digest(&pks[g as usize]));
        batch.extend_from_slice(&model_hash.0);
        for i in from..to {
            let buy = i % 2 == 0;
            let amt: u128 = if buy { 2_000_000_000_000_000_000 } else { 1_000_000_000_000_000_000 } + i as u128 * 1_000_000_000_000_000;
            if buy { quote_in += amt } else { base_in += amt }
            batch.push(buy as u8);
            batch.extend_from_slice(&amt.to_be_bytes()[4..]);   // u96
            batch.extend_from_slice(&1u128.to_be_bytes()[4..]); // minAmountOut u96 = 1
        }
    }
    let groups = parse_batch(&batch).expect("host: own batch malformed");
    let mut sigs = vec![];
    for (gi, g) in groups.iter().enumerate() {
        for j in 0..g.count as usize {
            let msg = order_message(a.chain_id, settlement, g, j, &batch);
            sigs.push(keys[used[gi]].expanded_key().sign_deterministic(&msg, &[]).unwrap().encode().to_vec());
        }
    }
    let gpks: Vec<Vec<u8>> = used.iter().map(|&u| pks[u].clone()).collect();
    if a.tamper { let l = batch.len(); batch[l - 13] ^= 1; } // low byte of last amountIn
    let expected = batch_digest(a.chain_id, settlement, a.batch_id, &batch);
    match verify_batch(a.chain_id, settlement, a.batch_id, &batch, &gpks, &sigs) {
        Some(d) => assert_eq!(d, expected),
        None => println!("host: batch fails verification (tampered={})", a.tamper),
    }
    println!("N={} batch={}B ({} groups) expected digest 0x{}", n, batch.len(), groups.len(), hex::encode(expected));
    if let Some(p) = &a.out {
        std::fs::write(p, serde_json::to_string_pretty(&serde_json::json!({
            "chain_id": a.chain_id, "settlement": a.settlement, "batch_id": a.batch_id, "n": n,
            "base_in": base_in.to_string(), "quote_in": quote_in.to_string(),
            "pk_hashes": pks.iter().map(|p| hex::encode(Sha256::digest(p))).collect::<Vec<_>>(),
            "batch": hex::encode(&batch), "digest": hex::encode(expected) })).unwrap()).unwrap();
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&a.chain_id);
    stdin.write(&settlement);
    stdin.write(&a.batch_id);
    stdin.write(&batch);
    let mut k = 0;
    for (gi, g) in groups.iter().enumerate() {
        stdin.write(&gpks[gi]);
        for _ in 0..g.count { stdin.write(&sigs[k]); k += 1; }
    }

    if a.execute {
        let client = MockProver::new(); // light executor; full CPU prover OOMs on this box
        let t = std::time::Instant::now();
        let (out, report) = client.execute(ELF, stdin).run().unwrap();
        println!("guest exit_code={} committed_len={}", report.exit_code, out.as_slice().len());
        if report.exit_code != 0 {
            println!("REJECTED: guest panicked (exit_code {}), so no valid proof can exist", report.exit_code);
            std::process::exit(2);
        }
        assert_eq!(out.as_slice(), &expected, "committed digest mismatch");
        let cycles = report.total_instruction_count();
        println!("RESULT N={} cycles={} cycles_per_order={} committed=0x{} exec_secs={:.1}",
            n, cycles, cycles / n, hex::encode(out.as_slice()), t.elapsed().as_secs_f64());
        println!("{}", report);
    } else {
        let client = ProverClient::from_env(); // SP1_PROVER=cpu for local proving
        let pk = client.setup(ELF).unwrap();
        let vkey = pk.verifying_key().bytes32();
        println!("vkey {}", vkey);
        let t = std::time::Instant::now();
        let proof = client.prove(&pk, stdin).groth16().run().expect("prove");
        println!("groth16 proof generated in {:.0}s", t.elapsed().as_secs_f64());
        client.verify(&proof, pk.verifying_key(), None).expect("local verification of the proof failed");
        assert_eq!(proof.public_values.as_slice(), &expected, "proved public values != expected digest");
        std::fs::create_dir_all(&a.proof_dir).unwrap();
        proof.save(format!("{}/proof.bin", a.proof_dir)).expect("save proof");
        let fixture = serde_json::json!({
            "vkey": vkey,
            "publicValues": format!("0x{}", hex::encode(proof.public_values.as_slice())),
            "proof": format!("0x{}", hex::encode(proof.bytes())),
            "digest": format!("0x{}", hex::encode(expected)),
            "batch": format!("0x{}", hex::encode(&batch)),
            "n": n, "chainId": a.chain_id, "settlement": format!("0x{}", hex::encode(settlement)), "batchId": a.batch_id,
            "note": "Real SP1 Groth16 proof of the zk-batch v2 guest over a batch signed with deterministic TEST keys.",
        });
        std::fs::write(format!("{}/groth16-batch-fixture.json", a.proof_dir),
            serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
        println!("wrote {}/groth16-batch-fixture.json and proof.bin", a.proof_dir);
    }
}
