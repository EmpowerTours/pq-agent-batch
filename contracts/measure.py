#!/usr/bin/env python3
"""Measure BatchSettlement.settle() gas on a local Monad Solonet.

For each N: build calldata (forge script BuildBatch, offline), eth_estimateGas
against Solonet, send with gas limit == estimate (Monad charges the LIMIT),
then split gas using debug_traceTransaction(callTracer).
Usage: python3 measure.py <batchIdStart> N [N...]
"""
import json, os, subprocess, sys, urllib.request

RPC = "http://localhost:8080"
BS = os.environ["SETTLEMENT"]; VER = os.environ["STANDIN_VERIFIER"].lower()
REAL = os.environ["REAL_VERIFIER"].lower(); POOL = os.environ["POOL"].lower()
BASE = os.environ["BASE"].lower(); QUOTE = os.environ["QUOTE"].lower()
REG = os.environ["REGISTRY"].lower()
KEY = open(os.environ.get("KEY_FILE", os.path.expanduser("~/.solonet-test.pk"))).read().strip()  # LOCAL devnet key, never committed
FOUNDRY = os.path.expanduser("~/.foundry/bin/")

def rpc(m, p):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"content-type": "application/json"})
    out = json.load(urllib.request.urlopen(r, timeout=120))
    if "error" in out: raise RuntimeError(out["error"])
    return out["result"]

def sh(*a):
    return subprocess.run(a, check=True, capture_output=True, text=True).stdout.strip()

me = sh(FOUNDRY + "cast", "wallet", "address", "--private-key", KEY)
rows = []
bid = int(sys.argv[1])
for n in map(int, sys.argv[2:]):
    sh(FOUNDRY + "forge", "script", os.environ.get("BUILD", "script/BuildBatch.s.sol"), "--sig", "run(uint256,uint64,uint64)",
       str(n), str(bid), str(bid * 1000))
    cd = open(f"measurements/calldata_{n}.hex").read().strip()
    raw = bytes.fromhex(cd[2:])
    nz = sum(1 for b in raw if b); z = len(raw) - nz
    est = int(rpc("eth_estimateGas", [{"from": me, "to": BS, "data": cd}]), 16)
    # sign locally (calldata can exceed argv limits for cast)
    from eth_account import Account
    nonce = int(rpc("eth_getTransactionCount", [me, "pending"]), 16)
    base_fee = int(rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
    tx = dict(chainId=int(rpc("eth_chainId", []), 16), nonce=nonce, to=BS, data=cd, value=0, gas=est,
              maxFeePerGas=2 * base_fee + 10**9, maxPriorityFeePerGas=10**9, type=2)
    signed = Account.sign_transaction(tx, KEY)
    txh = rpc("eth_sendRawTransaction", ["0x" + signed.raw_transaction.hex().removeprefix("0x")])
    import time
    for _ in range(100):
        rc = rpc("eth_getTransactionReceipt", [txh])
        if rc: break
        time.sleep(0.3)
    status = int(rc["status"], 16); charged = int(rc["gasUsed"], 16)
    tr = rpc("debug_traceTransaction", [txh, {"tracer": "callTracer"}])
    executed = int(tr["gasUsed"], 16)
    ver = amm = reg = tok = 0
    def walk(c, depth):
        global ver, amm, reg, tok
        for s in c.get("calls", []):
            to = s.get("to", "").lower(); g = int(s.get("gasUsed", "0x0"), 16)
            if depth == 0:
                if to == VER: ver += g
                elif to == POOL: amm += g
                elif to == REG: reg += g
                elif to in (BASE, QUOTE): tok += g
            walk(s, depth + 1)
    walk(tr, 0)
    calldata_gas = 16 * nz + 4 * z
    logic = executed - 21000 - calldata_gas - ver - amm - reg - tok
    row = dict(label=os.environ.get("LABEL", "v1"), N=n, batchId=bid, tx=txh, status=status, gas_limit=est, receipt_gasUsed=charged,
               trace_gasUsed=executed, per_order_charged=charged / n, calldata_bytes=len(raw),
               calldata_gas_16_4=calldata_gas, verifier_frame=ver, registry_calls=reg,
               amm_frames=amm, token_transfer_to_amm=tok, intrinsic=21000, settlement_logic_rest=logic)
    print(json.dumps(row)); rows.append(row)
    bid += 1
with open("measurements/results.jsonl", "a") as f:
    for r in rows: f.write(json.dumps(r) + "\n")
