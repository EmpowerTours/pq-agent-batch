#!/usr/bin/env python3
"""Low-fee-balance watcher for BatchSettlementV2 (AgentFees).

Polls `LowFeeBalance(uint32 indexed agentId, uint256 balance, uint256 threshold)` logs from a settlement
contract, prints each alert, optionally POSTs it to a webhook, and optionally calls the permissionless
`topUp(agentId)` keeper function for agents that configured auto top-up.

usage:
  SETTLEMENT=0x... [RPC=http://localhost:8080] python3 watcher/fee_watcher.py [--from-block N] [--once]

env:
  SETTLEMENT     settlement contract address (required)
  RPC            JSON-RPC endpoint (default http://localhost:8080)
  WEBHOOK_URL    optional; each alert is POSTed as JSON (Slack/Discord-style {"text": ...} plus raw fields)
  AUTO_TOPUP=1   optional; call topUp(agentId) on each alert when the agent has auto top-up configured
  KEY_FILE       keeper key file (needed only with AUTO_TOPUP=1; any funded account, it pays only gas;
                 the top-up itself is pulled from the agent owner's pre-approved allowance)
  POLL_SECONDS   poll interval (default 5)
  CHUNK          max blocks per eth_getLogs call (default 500)
  AGENTS         optional comma list of agent ids; prints their balance / remaining actions at start

Only the Python standard library is needed to watch and alert; AUTO_TOPUP also needs eth-account
(`pip install eth-account`) to sign the keeper transaction.
"""
import json, os, sys, time, urllib.request

RPC = os.environ.get("RPC", "http://localhost:8080")
SETTLEMENT = os.environ.get("SETTLEMENT", "")
WEBHOOK = os.environ.get("WEBHOOK_URL", "")
AUTO = os.environ.get("AUTO_TOPUP", "") == "1"
POLL = float(os.environ.get("POLL_SECONDS", "5"))
CHUNK = int(os.environ.get("CHUNK", "500"))

# keccak256 of the event / function signatures, precomputed so watching needs no crypto library.
# CI-independent check: `forge inspect BatchSettlementV2 methodIdentifiers` / `events`.
LOW_TOPIC = "0xebe8649c12c35f90e2b9e8f755f673520e7b18ad0dbef321fc5d59b8d0bb49c5"  # LowFeeBalance(uint32,uint256,uint256)
SEL_TOPUP = "0xecc4828b"        # topUp(uint32)
SEL_FEEACCOUNT = "0xa172108a"   # feeAccount(uint32)
SEL_AUTOTOPUP = "0x70a28102"    # autoTopUp(uint32)
SEL_REMAINING = "0x49e2b903"    # remainingActions(uint32)


def rpc(method, params):
    req = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                 {"content-type": "application/json"})
    out = json.load(urllib.request.urlopen(req, timeout=60))
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def u32(x): return "%064x" % x
def words(hexdata): d = hexdata[2:]; return [int(d[i:i + 64], 16) for i in range(0, len(d), 64)]


def call(selector, agent_id):
    return words(rpc("eth_call", [{"to": SETTLEMENT, "data": selector + u32(agent_id)}, "latest"]))


def fee_account(agent_id):
    bal, thr, token, low = call(SEL_FEEACCOUNT, agent_id)[:4]
    return {"balance": bal, "threshold": thr, "token": token, "low": bool(low)}


def post_webhook(payload):
    if not WEBHOOK:
        return
    body = dict(payload, text=f"[pq-agent-batch] agent {payload['agentId']} fee balance {payload['balance']} "
                              f"< threshold {payload['threshold']} (~{payload['remainingActions']} actions left)")
    try:
        req = urllib.request.Request(WEBHOOK, json.dumps(body).encode(), {"content-type": "application/json"})
        urllib.request.urlopen(req, timeout=15).read()
    except Exception as e:  # alerts must not kill the watcher
        print(f"  webhook failed: {e}", file=sys.stderr)


def try_top_up(agent_id):
    frm, amount = call(SEL_AUTOTOPUP, agent_id)[:2]
    acc = fee_account(agent_id)
    if amount == 0:
        return "auto top-up not configured"
    if acc["token"] == 0:
        return "fee token is native MON: owner must deposit manually"
    if acc["balance"] >= acc["threshold"]:
        return "already back above threshold"
    from eth_account import Account
    key = open(os.environ["KEY_FILE"]).read().strip()
    me = Account.from_key(key).address
    data = SEL_TOPUP + u32(agent_id)
    try:
        gas = int(rpc("eth_estimateGas", [{"from": me, "to": SETTLEMENT, "data": data}]), 16)
    except RuntimeError as e:   # e.g. owner revoked / lowered the allowance
        return f"topUp would revert: {e}"
    fee = int(rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
    tx = dict(chainId=int(rpc("eth_chainId", []), 16), nonce=int(rpc("eth_getTransactionCount", [me, "pending"]), 16),
              to=SETTLEMENT, data=data, value=0, gas=gas, maxFeePerGas=2 * fee + 10**9, maxPriorityFeePerGas=10**9, type=2)
    raw = Account.sign_transaction(tx, key).raw_transaction.hex()
    h = rpc("eth_sendRawTransaction", ["0x" + raw.removeprefix("0x")])
    return f"topUp sent {h} (pulls {amount} from {hex(frm)})"


def handle(log):
    agent_id = int(log["topics"][1], 16)
    bal, thr = words(log["data"])[:2]
    rem = call(SEL_REMAINING, agent_id)[0]
    rem_s = "unlimited" if rem == 2**256 - 1 else str(rem)
    payload = {"agentId": agent_id, "balance": bal, "threshold": thr, "remainingActions": rem_s,
               "block": int(log["blockNumber"], 16), "tx": log["transactionHash"], "settlement": SETTLEMENT}
    print(f"LOW FEE BALANCE agent={agent_id} balance={bal} threshold={thr} remaining~{rem_s} "
          f"block={payload['block']} tx={payload['tx']}", flush=True)
    post_webhook(payload)
    if AUTO:
        print(f"  {try_top_up(agent_id)}", flush=True)


def main():
    if not SETTLEMENT:
        raise SystemExit("set SETTLEMENT=0x...")
    args = sys.argv[1:]
    head = int(rpc("eth_blockNumber", []), 16)
    start = int(args[args.index("--from-block") + 1]) if "--from-block" in args else head
    for a in filter(None, os.environ.get("AGENTS", "").split(",")):
        acc = fee_account(int(a))
        print(f"agent {a}: {acc}, remainingActions={call(SEL_REMAINING, int(a))[0]}")
    print(f"watching {SETTLEMENT} on {RPC} from block {start} (webhook={'on' if WEBHOOK else 'off'}, auto top-up={'on' if AUTO else 'off'})", flush=True)
    nxt = start
    while True:
        head = int(rpc("eth_blockNumber", []), 16)
        while nxt <= head:
            to = min(head, nxt + CHUNK - 1)
            for log in rpc("eth_getLogs", [{"address": SETTLEMENT, "topics": [LOW_TOPIC], "fromBlock": hex(nxt), "toBlock": hex(to)}]):
                handle(log)
            nxt = to + 1
        if "--once" in args:
            return
        time.sleep(POLL)


if __name__ == "__main__":
    main()
