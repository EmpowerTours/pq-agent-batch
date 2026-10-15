//! Shared logic for the batched ML-DSA-65 guest (v2 packed encoding) and its host.
//!
//! MUST mirror `contracts/src/BatchSettlementV2.sol` byte for byte:
//!   batch := group+                       (no trailing bytes)
//!   group := agentId u32 | count u16 | firstNonce u64 | expiry u32 | pkHash b32 | modelHash b32  (82 B)
//!            order[count]
//!   order := flags u8 (bit0 = buyBase, others 0) | amountIn u96 | minAmountOut u96                (25 B)
//!   agentId strictly increasing across groups, count >= 1, order j has nonce firstNonce + j.
//!
//!   signed message (133 B) = ORDER_TAG_V2 | chainid u64 | settlement u160 | agentId u32 |
//!                            nonce u64 | expiry u32 | modelHash | order(25 B)
//!   digest = keccak256(abi.encode(BATCH_TAG_V2, chainid, settlement, batchId, keccak256(batch)))
//!   publicValues = digest (32 B == abi.encode(bytes32))

use alloy_primitives::{keccak256, Address, U256};
use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const HEADER: usize = 82;
pub const ORDER: usize = 25;

#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub agent_id: u32,
    pub count: u16,
    pub first_nonce: u64,
    pub expiry: u32,
    pub pk_hash: [u8; 32],
    pub model_hash: [u8; 32],
    /// offset of the first order inside the batch
    pub orders_at: usize,
}

pub fn order_tag() -> [u8; 32] {
    keccak256(b"EmpowerTours.AgentOrder.v2").0
}
pub fn batch_tag() -> [u8; 32] {
    keccak256(b"EmpowerTours.AgentBatch.v2").0
}

fn be(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |a, x| (a << 8) | *x as u64)
}

/// Strict parser with the same acceptance rules as the contract's framing checks.
pub fn parse_batch(batch: &[u8]) -> Option<Vec<Group>> {
    if batch.is_empty() {
        return None;
    }
    let mut groups = Vec::new();
    let mut p = 0usize;
    let mut prev_id = 0u32;
    while p < batch.len() {
        if p + HEADER > batch.len() {
            return None;
        }
        let h = &batch[p..p + HEADER];
        let g = Group {
            agent_id: be(&h[0..4]) as u32,
            count: be(&h[4..6]) as u16,
            first_nonce: be(&h[6..14]),
            expiry: be(&h[14..18]) as u32,
            pk_hash: h[18..50].try_into().unwrap(),
            model_hash: h[50..82].try_into().unwrap(),
            orders_at: p + HEADER,
        };
        if g.count == 0 || g.agent_id <= prev_id {
            return None;
        }
        // contract computes lastNonce = firstNonce + count - 1 with checked math
        g.first_nonce.checked_add(g.count as u64 - 1)?;
        prev_id = g.agent_id;
        p = g.orders_at + g.count as usize * ORDER;
        if p > batch.len() {
            return None;
        }
        for j in 0..g.count as usize {
            if batch[g.orders_at + j * ORDER] > 1 {
                return None;
            }
        }
        groups.push(g);
    }
    Some(groups)
}

/// The exact bytes the agent signs for order j of group g.
pub fn order_message(chain_id: u64, settlement: [u8; 20], g: &Group, j: usize, batch: &[u8]) -> Vec<u8> {
    let o = &batch[g.orders_at + j * ORDER..g.orders_at + (j + 1) * ORDER];
    let mut m = Vec::with_capacity(133);
    m.extend_from_slice(&order_tag());
    m.extend_from_slice(&chain_id.to_be_bytes());
    m.extend_from_slice(&settlement);
    m.extend_from_slice(&g.agent_id.to_be_bytes());
    m.extend_from_slice(&(g.first_nonce + j as u64).to_be_bytes());
    m.extend_from_slice(&g.expiry.to_be_bytes());
    m.extend_from_slice(&g.model_hash);
    m.extend_from_slice(o);
    m
}

pub fn batch_digest(chain_id: u64, settlement: [u8; 20], batch_id: u64, batch: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(160);
    m.extend_from_slice(&batch_tag());
    m.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    m.extend_from_slice(&Address::from(settlement).into_word().0);
    m.extend_from_slice(&U256::from(batch_id).to_be_bytes::<32>());
    m.extend_from_slice(&keccak256(batch).0);
    keccak256(&m).0
}

/// Decode a group's key once; checks sha256(pk) == group.pkHash.
pub fn group_key(g: &Group, pk: &[u8]) -> Option<VerifyingKey<MlDsa65>> {
    let h: [u8; 32] = Sha256::digest(pk).into();
    if h != g.pk_hash {
        return None;
    }
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk).ok()?;
    Some(VerifyingKey::<MlDsa65>::decode(&enc))
}

pub fn verify_sig(vk: &VerifyingKey<MlDsa65>, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(enc) = EncodedSignature::<MlDsa65>::try_from(sig) else { return false };
    let Some(s) = Signature::<MlDsa65>::decode(&enc) else { return false };
    vk.verify(msg, &s).is_ok()
}

/// Full check (host-side helper; the guest does the same thing streaming).
pub fn verify_batch(chain_id: u64, settlement: [u8; 20], batch_id: u64, batch: &[u8],
                    pks: &[Vec<u8>], sigs: &[Vec<u8>]) -> Option<[u8; 32]> {
    let groups = parse_batch(batch)?;
    if pks.len() != groups.len() {
        return None;
    }
    let mut k = 0;
    for (g, pk) in groups.iter().zip(pks) {
        let vk = group_key(g, pk)?;
        for j in 0..g.count as usize {
            let msg = order_message(chain_id, settlement, g, j, batch);
            if !verify_sig(&vk, &msg, sigs.get(k)?) {
                return None;
            }
            k += 1;
        }
    }
    if k != sigs.len() {
        return None;
    }
    Some(batch_digest(chain_id, settlement, batch_id, batch))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn group(id: u32, count: u16, nonce: u64) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&count.to_be_bytes());
        b.extend_from_slice(&nonce.to_be_bytes());
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        b.extend_from_slice(&[7u8; 64]);
        for _ in 0..count { b.push(1); b.extend_from_slice(&[0u8; 24]); }
        b
    }
    #[test]
    fn parses_well_formed() {
        let b = [group(1, 2, 1), group(2, 1, 5)].concat();
        let g = parse_batch(&b).unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g[1].orders_at, HEADER + 2 * ORDER + HEADER);
    }
    #[test]
    fn rejects_malformed() {
        assert!(parse_batch(&[]).is_none());
        let ok = group(1, 2, 1);
        assert!(parse_batch(&ok[..ok.len() - 1]).is_none());               // truncated
        assert!(parse_batch(&[ok.clone(), vec![0]].concat()).is_none());     // trailing byte
        assert!(parse_batch(&group(1, 0, 1)).is_none());                    // zero count
        assert!(parse_batch(&[group(2, 1, 1), group(1, 1, 1)].concat()).is_none()); // not ascending
        assert!(parse_batch(&[group(1, 1, 1), group(1, 1, 9)].concat()).is_none()); // duplicate agent
        assert!(parse_batch(&group(1, 2, u64::MAX)).is_none());             // nonce overflow
        let mut bad = ok.clone(); bad[HEADER] = 2;                          // flags
        assert!(parse_batch(&bad).is_none());
    }
}
