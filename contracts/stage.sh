#!/usr/bin/env bash
# Deploy a fresh registry + BatchSettlementV2 (current source) on Solonet and measure it.
# usage: ./stage.sh <label> N [N...]
set -euo pipefail
cd "$(dirname "$0")"; . measurements/env_v1.sh
LABEL=$1; shift
OUT=$(forge script script/DeployV2.s.sol --rpc-url http://localhost:8080 --private-key "$(cat "${KEY_FILE:-$HOME/.solonet-test.pk}")" \
      --broadcast --slow --gas-estimate-multiplier 300 2>&1)
echo "$OUT" | grep -qiE "error|fail" && { echo "$OUT" | tail -20; exit 1; }
export REGISTRY=$(echo "$OUT" | awk '/REGISTRY/{print $2}') SETTLEMENT=$(echo "$OUT" | awk '/SETTLEMENT/{print $2}')
echo "$LABEL REGISTRY=$REGISTRY SETTLEMENT=$SETTLEMENT" | tee -a measurements/deployments.log
LABEL=$LABEL-warmup BUILD=script/BuildBatchV2.s.sol python3 measure.py 1 2 >/dev/null  # first nonce writes per agent
LABEL=$LABEL BUILD=script/BuildBatchV2.s.sol python3 measure.py 2 "$@" | python3 -c "
import sys,json
for l in sys.stdin:
    r=json.loads(l); print(r['label'],'N=%d'%r['N'],'ok' if r['status'] else 'FAIL',r['gas_limit'],'per_order=%d'%round(r['per_order_charged']),
      'cd_bytes=%d cd=%d ver=%d reg=%d amm=%d logic=%d'%(r['calldata_bytes'],r['calldata_gas_16_4'],r['verifier_frame'],r['registry_calls'],r['amm_frames']+r['token_transfer_to_amm'],r['settlement_logic_rest']))"
