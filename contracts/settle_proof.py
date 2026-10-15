#!/usr/bin/env python3
"""Settle a REAL proof produced by .github/workflows/prove.yml on a Monad node.

usage: python3 settle_proof.py <groth16-batch-fixture.json> [--dry-run]
env:   RPC (default http://localhost:8080), SETTLEMENT (must equal the fixture's bound address),
       KEY_FILE (devnet key, never committed; default ~/.solonet-test.pk)

Checks before sending: chain id, settlement address, contract vkey == fixture vkey,
contract batchDigest(batchId, batch) == fixture digest == publicValues, and that every
agent group's firstNonce is above the on-chain lastNonce. Then eth_estimateGas and send
with gas limit = estimate (Monad charges the limit), and print a callTracer breakdown.
"""
import json, os, sys, time, urllib.request
from eth_abi import encode, decode
from eth_utils import keccak
from eth_account import Account

RPC = os.environ.get("RPC", "http://localhost:8080")

def rpc(m, p):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"content-type": "application/json"})
    out = json.load(urllib.request.urlopen(r, timeout=120))
    if "error" in out: raise RuntimeError(out["error"])
    return out["result"]

def call(to, sig, types, args, rtypes):
    data = "0x" + (keccak(text=sig)[:4] + encode(types, args)).hex()
    return decode(rtypes, bytes.fromhex(rpc("eth_call", [{"to": to, "data": data}, "latest"])[2:]))

fx = json.load(open(sys.argv[1])); dry = "--dry-run" in sys.argv
bs = os.environ["SETTLEMENT"]
batch = bytes.fromhex(fx["batch"][2:]); proof = bytes.fromhex(fx["proof"][2:]); bid = int(fx["batchId"])
assert int(rpc("eth_chainId", []), 16) == int(fx["chainId"]), "chain id mismatch"
assert bs.lower() == fx["settlement"].lower(), f"proof is bound to {fx['settlement']}, not {bs}"
(vk,) = call(bs, "batchProgramVKey()", [], [], ["bytes32"])
assert "0x" + vk.hex() == fx["vkey"].lower(), f"contract vkey 0x{vk.hex()} != proof vkey {fx['vkey']}"
(dg,) = call(bs, "batchDigest(uint64,bytes)", ["uint64", "bytes"], [bid, batch], ["bytes32"])
assert "0x" + dg.hex() == fx["digest"].lower() == fx["publicValues"].lower(), "digest mismatch"
p = 0
while p < len(batch):  # nonce precondition per group
    aid = int.from_bytes(batch[p:p+4], "big"); cnt = int.from_bytes(batch[p+4:p+6], "big")
    first = int.from_bytes(batch[p+6:p+14], "big")
    _, _, last = call(bs, "agentState(uint32)", ["uint32"], [aid], ["uint96", "uint96", "uint64"])
    assert first > last, f"agent {aid}: firstNonce {first} <= on-chain lastNonce {last} (settle earlier batches first)"
    print(f"agent {aid}: orders {cnt}, nonces {first}..{first+cnt-1}, on-chain lastNonce {last}")
    p += 82 + cnt * 25
print("pre-checks OK: chain, settlement, vkey, digest, nonces")

key = open(os.environ.get("KEY_FILE", os.path.expanduser("~/.solonet-test.pk"))).read().strip()
me = Account.from_key(key).address
data = "0x" + (keccak(text="settle(uint64,bytes,bytes)")[:4] + encode(["uint64", "bytes", "bytes"], [bid, batch, proof])).hex()
est = int(rpc("eth_estimateGas", [{"from": me, "to": bs, "data": data}]), 16)
print(f"eth_estimateGas = {est}  (N={fx['n']}, {est / fx['n']:.0f} gas/order)")
if dry: sys.exit(0)
base_fee = int(rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
tx = dict(chainId=int(fx["chainId"]), nonce=int(rpc("eth_getTransactionCount", [me, "pending"]), 16), to=bs,
          data=data, value=0, gas=est, maxFeePerGas=2 * base_fee + 10**9, maxPriorityFeePerGas=10**9, type=2)
raw = Account.sign_transaction(tx, key).raw_transaction.hex()
txh = rpc("eth_sendRawTransaction", ["0x" + raw.removeprefix("0x")])
for _ in range(200):
    rc = rpc("eth_getTransactionReceipt", [txh])
    if rc: break
    time.sleep(0.3)
st = int(rc["status"], 16); used = int(rc["gasUsed"], 16)
tr = rpc("debug_traceTransaction", [txh, {"tracer": "callTracer"}])
frames = [(c.get("to", ""), int(c.get("gasUsed", "0x0"), 16)) for c in tr.get("calls", [])]
nz = sum(1 for b in bytes.fromhex(data[2:]) if b); z = len(data[2:]) // 2 - nz
res = dict(label=f"REAL-N{fx['n']}-live", N=fx["n"], batchId=bid, tx=txh, status=st, gas_limit=est,
           receipt_gasUsed=used, per_order=used / fx["n"], calldata_bytes=nz + z, calldata_gas_16_4=16 * nz + 4 * z,
           top_level_frames=frames, vkey=fx["vkey"], settlement=bs)
print(json.dumps(res, indent=1))
os.makedirs("measurements", exist_ok=True)
with open("measurements/results.jsonl", "a") as f: f.write(json.dumps(res) + "\n")
sys.exit(0 if st == 1 else 1)
