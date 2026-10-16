#!/usr/bin/env python3
"""CI check: the precomputed selectors/topic in fee_watcher.py match the compiled BatchSettlementV2 ABI."""
import json, os, re, subprocess, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
src = open(os.path.join(ROOT, "watcher", "fee_watcher.py")).read()
def inspect(what):
    out = subprocess.run(["forge", "inspect", "BatchSettlementV2", what, "--json"], cwd=os.path.join(ROOT, "contracts"),
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)
methods, events = inspect("methodIdentifiers"), inspect("events")
want = {
    "LOW_TOPIC": events["LowFeeBalance(uint32,uint256,uint256)"].lower(),
    "SEL_TOPUP": "0x" + methods["topUp(uint32)"],
    "SEL_FEEACCOUNT": "0x" + methods["feeAccount(uint32)"],
    "SEL_AUTOTOPUP": "0x" + methods["autoTopUp(uint32)"],
    "SEL_REMAINING": "0x" + methods["remainingActions(uint32)"],
}
bad = 0
for name, val in want.items():
    got = re.search(rf'^{name} = "(0x[0-9a-f]+)"', src, re.M).group(1)
    ok = got == (val if val.startswith("0x") else "0x" + val)
    print(f"{'ok ' if ok else 'BAD'} {name} {got}")
    bad += not ok
sys.exit(1 if bad else 0)
