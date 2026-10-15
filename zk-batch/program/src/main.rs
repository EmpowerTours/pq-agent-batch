//! SP1 guest (v2): verify every order in a packed batch with ML-DSA-65 and commit one
//! 32-byte batch digest. Public output = abi.encode(batchDigest), checked by
//! BatchSettlementV2.settle(). Keys are decoded once per agent group.
#![no_main]
sp1_zkvm::entrypoint!(main);

use agent_batch_lib::{batch_digest, group_key, order_message, parse_batch, verify_sig};

pub fn main() {
    let chain_id = sp1_zkvm::io::read::<u64>();
    let settlement = sp1_zkvm::io::read::<[u8; 20]>();
    let batch_id = sp1_zkvm::io::read::<u64>();
    let batch = sp1_zkvm::io::read::<Vec<u8>>();
    let groups = parse_batch(&batch).expect("malformed batch");
    for g in &groups {
        let pk = sp1_zkvm::io::read::<Vec<u8>>();
        let vk = group_key(g, &pk).expect("pk does not match group pkHash");
        for j in 0..g.count as usize {
            let sig = sp1_zkvm::io::read::<Vec<u8>>();
            let msg = order_message(chain_id, settlement, g, j, &batch);
            assert!(verify_sig(&vk, &msg, &sig), "invalid order signature");
        }
    }
    sp1_zkvm::io::commit_slice(&batch_digest(chain_id, settlement, batch_id, &batch));
}
