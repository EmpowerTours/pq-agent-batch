#!/usr/bin/env bash
# CI integration for the TypeScript SDK + MCP server against a throwaway local anvil
# (no external network, no secrets: anvil's well-known PUBLIC dev keys are read at runtime, never committed).
#   deploy (DeploySolonet) -> TS SDK e2e (register, fund, deposit, alert, sign, status, batch, contract batchDigest
#   [+ Rust batcher parity when PQAGENT_BIN is set]) -> MCP smoke over stdio + streamable HTTP + local mode
# Usage: mcp/scripts/anvil-ci.sh   (needs anvil/forge/cast, node, `npm run build` done; optional PQAGENT_BIN)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PORT=${ANVIL_PORT:-8548}
RPC=http://127.0.0.1:$PORT
T=$(mktemp -d)
cleanup() { [ -n "${ANVIL_PID:-}" ] && kill "$ANVIL_PID" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT

anvil --port "$PORT" --silent --config-out "$T/anvil.json" >/dev/null 2>&1 &
ANVIL_PID=$!
for _ in $(seq 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done
python3 -c "import json;k=json.load(open('$T/anvil.json'))['private_keys'];open('$T/deployer.key','w').write(k[0]);open('$T/op.key','w').write(k[1])"
chmod 600 "$T"/*.key

cd "$ROOT/contracts"
unset VERIFIER POOL PK_A PK_B FEE_DEPOSIT SELF_CAP_BASE SELF_CAP_QUOTE PQAGENT_OPERATOR_KEY
BATCH_VKEY=0x0020ed358e42b85560d3f4114c57cd2b767e130766caf8bcaec7842799fd7d9d \
OPEN_REGISTRATION=true REGISTRATION_FEE=100000000000000000 FEE_PER_ACTION=1000000000000000 \
  forge script script/DeploySolonet.s.sol --rpc-url "$RPC" --broadcast --private-key "$(cat "$T/deployer.key")" > "$T/deploy.log" 2>&1 \
  || { cat "$T/deploy.log"; exit 1; }
SETTLEMENT=$(awk '/SETTLEMENT/ {print $2}' "$T/deploy.log" | tail -1)
REGISTRY=$(awk '/REGISTRY/ {print $2}' "$T/deploy.log" | tail -1)
echo "anvil $RPC settlement $SETTLEMENT registry $REGISTRY"

export PQAGENT_RPC=$RPC PQAGENT_CHAIN_ID=$(cast chain-id --rpc-url "$RPC") PQAGENT_SETTLEMENT=$SETTLEMENT PQAGENT_REGISTRY=$REGISTRY
echo; echo "=== TS SDK end-to-end"
( cd "$ROOT/sdk-ts" && SETTLEMENT=$SETTLEMENT OPERATOR_KEY_FILE=$T/op.key OUT_DIR=$T/e2e node --import tsx scripts/e2e.ts )

AGENT=$(python3 -c "import json;print(json.load(open('$T/e2e/agent.json'))['agentId'])")
PKH=$(python3 -c "import json;print(json.load(open('$T/e2e/agent.json'))['pkHash'])")
echo; echo "=== MCP smoke (stdio + HTTP + local mode) for agent $AGENT"
( cd "$ROOT/mcp" && SMOKE_AGENT_ID=$AGENT SMOKE_PKHASH=$PKH SMOKE_ACTIONS_DIR=$T/e2e/actions SMOKE_BATCH_INPUT=$T/e2e/batch-input.json \
  LOCAL_MODE=1 OPERATOR_KEY_FILE=$T/op.key node --import tsx scripts/smoke.ts > "$T/smoke.log" 2>&1 ) || { cat "$T/smoke.log"; exit 1; }
grep -E "^(tools/list|DNS-rebinding|raw POST|MCP smoke)" "$T/smoke.log" || true
tail -1 "$T/smoke.log"
echo "anvil TS SDK + MCP OK"
