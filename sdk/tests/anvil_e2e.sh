#!/usr/bin/env bash
# CLI integration test against a throwaway local anvil (CI-safe: no external network, no secrets).
#   init -> register (+ CapsTooHigh negative) -> fund -> deposit -> alert -> sign -> status -> verify -> batch
# and checks the SDK-built batch digest against the deployed contract's own batchDigest().
# Usage: sdk/tests/anvil_e2e.sh [path/to/pqagent]   (default: sdk/target/release/pqagent)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PQ=${1:-$ROOT/sdk/target/release/pqagent}
PQ=$(cd "$(dirname "$PQ")" && pwd)/$(basename "$PQ")
PORT=${ANVIL_PORT:-8547}
RPC=http://127.0.0.1:$PORT
T=$(mktemp -d)
cleanup() { [ -n "${ANVIL_PID:-}" ] && kill "$ANVIL_PID" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
log() { printf '\n=== %s\n' "$*"; }
jget() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval('d'+sys.argv[2]))" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

log "anvil on $RPC"
anvil --port "$PORT" --silent --config-out "$T/anvil.json" >/dev/null 2>&1 &
ANVIL_PID=$!
for _ in $(seq 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done
# anvil's well-known PUBLIC dev accounts, read at runtime (never committed): #0 deployer, #1 agent operator
python3 -c "import json;k=json.load(open('$T/anvil.json'))['private_keys'];open('$T/deployer.key','w').write(k[0]);open('$T/op.key','w').write(k[1])"
chmod 600 "$T"/*.key
OP=$(cast wallet address --private-key "$(cat "$T/op.key")")

log "deploy (DeploySolonet: open registration, 0.1 MON registration fee, 0.001 MON per action)"
cd "$ROOT/contracts"
unset VERIFIER POOL PK_A PK_B FEE_DEPOSIT SELF_CAP_BASE SELF_CAP_QUOTE PQAGENT_RPC PQAGENT_OPERATOR_KEY
BATCH_VKEY=0x0020ed358e42b85560d3f4114c57cd2b767e130766caf8bcaec7842799fd7d9d \
OPEN_REGISTRATION=true REGISTRATION_FEE=100000000000000000 FEE_PER_ACTION=1000000000000000 \
  forge script script/DeploySolonet.s.sol --rpc-url "$RPC" --broadcast --private-key "$(cat "$T/deployer.key")" > "$T/deploy.log" 2>&1 \
  || { cat "$T/deploy.log"; fail "deploy"; }
SETTLEMENT=$(awk '/SETTLEMENT/ {print $2}' "$T/deploy.log" | tail -1)
REGISTRY=$(awk '/REGISTRY/ {print $2}' "$T/deploy.log" | tail -1)
POOL=$(awk '/POOL/ {print $2}' "$T/deploy.log" | tail -1)
echo "settlement $SETTLEMENT registry $REGISTRY pool $POOL"
cd "$T"

export PQAGENT_DIR=$T/agent PQAGENT_PASSPHRASE="e2e passphrase"
log "pqagent init (encrypted keystore)"
"$PQ" init --rpc "$RPC" --settlement "$SETTLEMENT" --model "e2e model v1"
[ "$(stat -c %a "$T/agent")" = 700 ] || fail "dir mode"
[ "$(stat -c %a "$T/agent/key.json")" = 600 ] || fail "key mode"
[ "$(jget "$T/agent/key.json" "['encrypted']")" = True ] || fail "not encrypted"
PKH=$(jget "$T/agent/config.json" "['pkHash']")

log "pqagent register (caps above the registry maximum must revert CapsTooHigh)"
if "$PQ" register --operator-key-file "$T/op.key" --cap-base 10001e18 > "$T/neg.log" 2>&1; then fail "CapsTooHigh not raised"; fi
grep -q CapsTooHigh "$T/neg.log" || { cat "$T/neg.log"; fail "expected CapsTooHigh"; }
"$PQ" register --operator-key-file "$T/op.key" --cap-base 5000e18 --cap-quote 9000e18 | tee "$T/reg.txt"
ID=$(awk -F= '/^AGENT_ID=/ {print $2}' "$T/reg.txt")
[ "$ID" = 3 ] || fail "agent id $ID (TEST agents are 1, 2)"
[ "$(cast call "$REGISTRY" 'accruedRegistrationFees()(uint256)' --rpc-url "$RPC" | awk '{print $1}')" = 100000000000000000 ] || fail "registration fee not accrued"

log "pqagent fund / deposit / alert / balance"
PQAGENT_OPERATOR_KEY=$(cat "$T/op.key") "$PQ" fund --amount 0.01mon   # operator key via env this time
BASE=$(cast call "$SETTLEMENT" 'base()(address)' --rpc-url "$RPC")
QUOTE=$(cast call "$SETTLEMENT" 'quote()(address)' --rpc-url "$RPC")
for tk in "$BASE" "$QUOTE"; do cast send "$tk" 'faucet(uint256)' 1000e18 --private-key "$(cat "$T/op.key")" --rpc-url "$RPC" >/dev/null; done
"$PQ" deposit --operator-key-file "$T/op.key" --base 100e18 --quote 200e18
"$PQ" alert --operator-key-file "$T/op.key" --threshold 0.005mon
"$PQ" balance
"$PQ" --json balance > bal.json
[ "$(jget bal.json "['remainingActions']")" = 10 ] || fail "remainingActions"
[ "$(jget bal.json "['alertThreshold']")" = 5000000000000000 ] || fail "threshold"

log "pqagent sign x3 (+ one with a nonce gap)"
mkdir actions
"$PQ" sign --sell --amount 1e18 --min-out 1 --out actions
"$PQ" sign --buy --amount 2.5e18 --min-out 1 --out actions
"$PQ" sign --sell --amount 1.5e18 --min-out 1 --out actions
"$PQ" sign --buy --amount 1e18 --min-out 1 --nonce 9 --out actions
"$PQ" verify actions/000003-000000000001.json
[ "$(jget actions/000003-000000000003.json "['nonce']")" = 3 ] || fail "auto nonce"

log "pqagent status"
"$PQ" status
"$PQ" --json status > st.json
[ "$(jget st.json "['authorized']")" = True ] || fail "not authorized"
[ "$(jget st.json "['pkHash']")" = "$PKH" ] || fail "pkHash"
[ "$(jget st.json "['nextNonce']")" = 10 ] || fail "nextNonce"

log "pqagent batch (on-chain checks)"
"$PQ" batch --actions actions --batch-id 7 --out input.json
[ "$(jget input.json "['orders']")" = 3 ] || fail "batch orders"
[ "$(jget input.json "['groups'][0]['feeQuote']")" = 3000000000000000 ] || fail "feeQuote"
jget input.json "['excluded'][0]['reason']" | grep -q "not contiguous" || fail "gap not excluded"
ONCHAIN=$(cast call "$SETTLEMENT" 'batchDigest(uint64,bytes)(bytes32)' 7 "$(jget input.json "['batch']")" --rpc-url "$RPC")
[ "$ONCHAIN" = "$(jget input.json "['digest']")" ] || fail "digest mismatch: contract $ONCHAIN"
echo "contract batchDigest == SDK digest: $ONCHAIN"

log "fee balance limits the batch: nonces 1..15 pending, balance pays for 10"
rm actions/000003-000000000009.json
for n in $(seq 4 15); do "$PQ" sign --sell --amount 1e17 --min-out 1 --nonce "$n" --out actions >/dev/null; done
"$PQ" batch --actions actions --batch-id 8 --out input2.json > b2.txt; cat b2.txt
[ "$(jget input2.json "['orders']")" = 10 ] || fail "fee trim"
grep -q "insufficient prepaid fee balance" b2.txt || fail "fee reason"

log "anvil e2e OK"
