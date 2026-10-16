#!/usr/bin/env python3
"""Measure the gas cost of the fee path on Monad pricing, using the REAL proofs.

The committed real proofs are bound to the Solonet settlement 0x46658F50...Ab3e (already settled
there), so a fresh deployment cannot re-use them. Instead this runs eth_estimateGas against that
address with STATE OVERRIDES (nothing is sent, nothing changes on chain):
  * baseline: the deployed (pre-fee) code, agent nonces reset to their pre-batch values
  * new code: runtime of the CURRENT source built with the same immutables (forge script
    DumpSettlementRuntime, simulation only), the same agent state moved to the new storage slots,
    and fee config / fee accounts written directly into storage.
The baseline reproducing the live receipts (1,315,406 / 1,379,924) checks the method.

usage: python3 contracts/script/measure_fee_gas.py      (needs Solonet with the live deployment)
env:   RPC (default http://localhost:8080)
Writes results/solonet/fee-gas.json.
"""
import json, os, re, subprocess, urllib.request
from eth_abi import encode
from eth_utils import keccak

RPC = os.environ.get("RPC", "http://localhost:8080")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
dep = json.load(open(os.path.join(ROOT, "results", "solonet", "settlements.json")))
S = dep["contracts"]["settlement"]
FROM = "0x000000000000000000000000000000000000dEaD"   # settle() is permissionless; estimate only

def rpc(m, p):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"content-type": "application/json"})
    o = json.load(urllib.request.urlopen(r, timeout=120))
    if "error" in o: raise RuntimeError(o["error"])
    return o["result"]

def slot(key, base): return "0x" + keccak(encode(["uint256", "uint256"], [key, base])).hex()
def h32(x): return "0x%064x" % x

# storage slots of the current source
lay = json.loads(subprocess.run(["forge", "inspect", "BatchSettlementV2", "storageLayout", "--json"], cwd=os.path.join(ROOT, "contracts"),
                                check=True, capture_output=True, text=True).stdout)
L = {x["label"]: int(x["slot"]) for x in lay["storage"]}
OLD_AGENT_STATE = 0   # pre-fee BatchSettlementV2: agentState was the only storage variable

env = dict(os.environ, VERIFIER=dep["contracts"]["verifier"], BATCH_VKEY=dep["contracts"]["batchVKey"],
           REGISTRY=dep["contracts"]["registry"], POOL=dep["contracts"]["pool"])
out = subprocess.run(["forge", "script", "script/DumpSettlementRuntime.s.sol", "--fork-url", RPC], cwd=os.path.join(ROOT, "contracts"),
                     env=env, check=True, capture_output=True, text=True).stdout
new_rt = max(re.findall(r"0x[0-9a-f]{1000,}", out), key=len)

live = {i: int(rpc("eth_getStorageAt", [S, slot(i, OLD_AGENT_STATE), "latest"]), 16) for i in (1, 2)}
def agent(i, nonce): return (live[i] & ((1 << 192) - 1)) | (nonce << 192)   # keep balances, set lastNonce

FEE = 10**15                       # 0.001 MON per action (illustrative)
def fee_cfg(per, cap, enabled, accrued): return per | (cap << 72) | (int(enabled) << 144) | (accrued << 152)
def fee_acc(bal, thr, token=0, low=False): return bal | (thr << 96) | (token << 192) | (int(low) << 200)

rows = []
for s in dep["settlements"]:
    fx = json.load(open(os.path.join(ROOT, s["fixture"])))
    n = fx["n"]; batch = bytes.fromhex(fx["batch"][2:]); proof = bytes.fromhex(fx["proof"][2:])
    data = "0x" + (keccak(text="settle(uint64,bytes,bytes)")[:4] + encode(["uint64", "bytes", "bytes"], [fx["batchId"], batch, proof])).hex()
    pre = (0, 0) if s["batchId"] == 1 else (5, 10)          # agents' lastNonce before this batch on Solonet
    old = {slot(1, OLD_AGENT_STATE): h32(agent(1, pre[0])), slot(2, OLD_AGENT_STATE): h32(agent(2, pre[1]))}
    new = {slot(1, OLD_AGENT_STATE): h32(0), slot(2, OLD_AGENT_STATE): h32(0),
           slot(1, L["agentState"]): h32(agent(1, pre[0])), slot(2, L["agentState"]): h32(agent(2, pre[1]))}
    on = dict(new)
    on[slot(0, L["feeConfig"])] = h32(fee_cfg(FEE, 0, True, 1))           # accrued already non-zero (steady state)
    on[slot(1, L["feeAccount"])] = h32(fee_acc(10**18, 10**17))
    on[slot(2, L["feeAccount"])] = h32(fee_acc(10**18, 10**17))
    alert = dict(on)
    alert[slot(1, L["feeAccount"])] = h32(fee_acc(10**18, 10**18 - FEE))  # agent 1 crosses its threshold
    scen = [
        ("baseline: deployed pre-fee code", {S: {"stateDiff": old}}),
        ("fee code, fees off (fee = 0)", {S: {"code": new_rt, "stateDiff": new}}),
        ("fee code, native fee on, 2 agents charged", {S: {"code": new_rt, "stateDiff": on}}),
        ("fee code, native fee on + 1 LowFeeBalance alert", {S: {"code": new_rt, "stateDiff": alert}}),
    ]
    base = None
    for label, ov in scen:
        g = int(rpc("eth_estimateGas", [{"from": FROM, "to": S, "data": data}, "latest", ov]), 16)
        base = g if base is None else base
        r = {"N": n, "scenario": label, "eth_estimateGas": g, "per_order": round(g / n, 1), "delta_vs_baseline": g - base}
        rows.append(r); print(json.dumps(r))
res = {"note": "eth_estimateGas on local Monad Solonet (chain 20143) with state overrides against the live settlement; "
               "Monad charges the gas limit, so estimate = what a sender would pay. Real SP1 Groth16 proofs, real verifier. "
               "Fee value 0.001 MON/action is illustrative; gas does not depend on it.", "rows": rows}
open(os.path.join(ROOT, "results", "solonet", "fee-gas.json"), "w").write(json.dumps(res, indent=2) + "\n")
