# Results

Real artifacts from the prove workflow and the live devnet settlements. All keys involved are deterministic **TEST** keys. Tx hashes are on a **local** Monad devnet (Solonet, chain 20143), so no public explorer has them.

| File | What |
|---|---|
| `solonet/b1-n10/groth16-batch-fixture.json` | Real SP1 Groth16 proof, N=10, batchId 1, nonces 1–10, bound to settlement `0x46658F50…Ab3e` on chain 20143 ([prove run](https://github.com/EmpowerTours/pq-agent-batch/actions/runs/38787797233)) |
| `solonet/b2-n100/groth16-batch-fixture.json` | Real SP1 Groth16 proof, N=100, batchId 2, nonces 6–105, same settlement ([prove run](https://github.com/EmpowerTours/pq-agent-batch/actions/runs/38787815547)) |
| `solonet/settlements.json` | Deployed addresses, both settlement receipts (tx, block, gas, calldata, per-call gas breakdown) |
| `solonet/fee-gas.json` | Gas of the fee path on Monad pricing: real N=10/N=100 proofs, `eth_estimateGas` with state overrides against the live settlement (`contracts/script/measure_fee_gas.py`) |
| `solonet/fee-watcher-demo.json` | End-to-end watcher run on Solonet: LowFeeBalance → webhook → keeper `topUp` |
| `proving.json` | Prove-step wall time and peak memory for both runs (`/usr/bin/time -v`) |
| `history/gas-measurements.jsonl` | Every raw gas row collected while building the project, including the early **stand-in** verifier rows (S1–S6) and the real rows (`REAL-*`). Labels say which is which. |

Each fixture holds: `vkey`, `publicValues` (= `digest`), `proof` (SP1 Groth16, selector `0x4388a21c`), the packed `batch`, and the bound `chainId`, `settlement`, `batchId`, `nonceBase`.

`contracts/test/RealGroth16Settle.t.sol` replays both fixtures against the real SP1 v6.1.0 verifier bytecode on every CI run. The fixtures are not just stored; CI checks them.
