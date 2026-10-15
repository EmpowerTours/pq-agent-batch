#!/usr/bin/env bash
# Local pre-push verifier: same checks as .github/workflows/ci.yml (minus the SP1 guest build).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
( cd contracts && forge test )
( cd zk-batch && cargo test -p agent-batch-lib --release )
