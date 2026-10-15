# pq-agent-batch

Settles **post-quantum-signed AI-agent orders in batches on Monad.** One SP1 Groth16 proof covers a whole batch of ML-DSA-65 (FIPS 204) signed orders. The settlement contract verifies that single proof, enforces the agent registry, nets buys against sells, and sends only the residual to an AMM.

It grew out of [EmpowerTours/quantum-portfolio](https://github.com/EmpowerTours/quantum-portfolio) (`zk-mldsa`, single-order proofs). This repo is the batched version.

> **Status:** research prototype. Not audited. All keys in this repo are **deterministic TEST keys**. Gas numbers come from a local Monad devnet (Solonet). The on-chain proof check in those numbers used a clearly labelled **stand-in** (see below). The `prove` workflow exists to produce the first real batch proof.

## Layout
| Path | What |
|---|---|
| `zk-batch/program` | SP1 guest. Parses a packed batch, checks `sha256(pk) == group.pkHash` once per agent, verifies every order's ML-DSA-65 signature, and commits `abi.encode(batchDigest)`. |
| `zk-batch/lib` | Packed format, the signed-message builder, and the digest. Mirrors the Solidity byte for byte. Has unit tests. |
| `zk-batch/script` | Host. Derives 2 deterministic TEST ML-DSA-65 keys (seeded from public strings), builds and signs a batch, then `--execute` (cycle count) or `--prove` (Groth16). Also `vkey`. |
| `zk-batch/vendor/keccak` | Copied from quantum-portfolio: the keccak crate patched to use SP1's keccak precompile (MIT/Apache-2.0, licences included). |
| `contracts/src/BatchSettlementV2.sol` | **Current settlement.** One proof per batch, packed calldata (82 B agent header + 25 B per order), nonce-based replay protection, one storage slot per agent. |
| `contracts/src/BatchSettlement.sol` | v1 baseline (ABI-encoded orders), kept for comparison. |
| `contracts/src/AgentRegistry.sol` | Agents with ML-DSA key-commitment sets, stake, per-batch caps, kill switch, admin and guardian. |
| `contracts/src/dex/` | MiniAMM and MockToken, from quantum-portfolio. |
| `contracts/test/` | Forge tests: v1 21, v2 29 (including fuzzing of the packed decoder), a Rust-guest parity fixture, and a gas probe. |
| `contracts/test/helpers/` | **Not for deployment.** `HashBoundMockVerifier` (test-only mock SNARK) and `StandInGroth16Verifier` (gas stand-in, **not sound**). |
| `contracts/script/`, `measure.py`, `stage.sh` | Solonet deploy and gas measurement. They need a local devnet key in `$KEY_FILE`, which is never committed. |
| `contracts/measurements/` | Raw gas results (`results.jsonl`, with tx hashes on the local devnet). |

## Batch format (v2)
```
batch := group+                                   (no trailing bytes)
group := agentId u32 | count u16 | firstNonce u64 | expiry u32 | pkHash b32 | modelHash b32   (82 B)
         order[count]
order := flags u8 (bit0 = buyBase) | amountIn u96 | minAmountOut u96                          (25 B)
signed msg (133 B) = keccak("EmpowerTours.AgentOrder.v2") | chainid u64 | settlement | agentId u32 |
                     nonce u64 (= firstNonce + j) | expiry u32 | modelHash | order
digest = keccak256(abi.encode(keccak("EmpowerTours.AgentBatch.v2"), chainid, settlement, batchId, keccak256(batch)))
```

## Results (local Monad Solonet)
Each tx was sent with gas limit = `eth_estimateGas` (Monad charges the limit). Two agents, mixed buy and sell.

**The proof check is a stand-in:** `StandInGroth16Verifier` calls the real SP1 v6 Groth16 verifier bytecode with a real single-order proof from quantum-portfolio. Pairing cost is the same as for a real batch proof, but it does not bind the batch. A real batch proof is what the `prove` workflow is for.

| N | v1 gas per order | v2 gas per order | v2 non-proof gas per order |
|---|---|---|---|
| 1 | 1,331,933 | 1,287,199 | 212,144 |
| 10 | 141,348 | 132,689 | 25,184 |
| 100 | 18,874 | **13,914** | **3,164** |
| 250 | 10,709 | 5,995 | 1,695 |
| 500 | 7,987 | **3,356** | 1,206 |

Breakdown at N=100 (v2):

| component | gas | share |
|---|---|---|
| proof check | 1,075,055 | 77% |
| settlement logic (includes ~12k of estimate headroom) | 141,296 | 10% |
| AMM | 91,611 | 7% |
| registry | 34,602 | 2.5% |
| calldata (3,236 B) | 27,848 | 2% |
| intrinsic | 21,000 | — |

Guest cycles (SP1 6.3.1 executor): about **1.19M cycles per order** at N ≥ 100. Total is 119.4M at N=100 and 590M at N=500. The v1 guest needed 2.04M per order.

## Run the tests
```bash
cd contracts
forge install foundry-rs/forge-std@v1.16.1 --shallow --no-git
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1 --shallow --no-git
forge test                                     # 80 passing (v1 21, v2 29, probe suite re-runs v2 + 1)

cd ../zk-batch
cargo test -p agent-batch-lib --release        # packed-parser tests
# Guest (needs protoc + SP1 toolchain: curl -L https://sp1up.succinct.xyz | bash && sp1up --version v6.3.1)
cargo build --release
./target/release/batch --execute -n 100        # cycle count
./target/release/batch --execute -n 4 --tamper # must be rejected (exit 2)
```
CI (`.github/workflows/ci.yml`) runs all of this on every push. *(Workflow files pending: see note at the bottom.)*

## Generate a real Groth16 proof (GitHub Actions)
`.github/workflows/prove.yml`. Trigger it from **Actions → prove → Run workflow**, or with `gh workflow run prove.yml -f n=10`.

What the workflow does:
- Frees disk space and adds a 32 GB swap file (the runner has 16 GB RAM).
- Installs protoc and the SP1 v6.3.1 toolchain, then builds the guest.
- Executes once, then proves with `SP1_PROVER=cpu`. The Groth16 wrap runs locally through gnark/docker. **No prover network and no credentials are used.**
- Uploads `proof-out/` as an artifact:
  - `groth16-batch-fixture.json`: vkey, publicValues, proof, digest, batch, plus the bound chainId, settlement and batchId
  - `proof.bin`
  - `batch.json`
  - `vkey.txt`
  - `prove.log`

The default settlement address `0x5e77…5E77` is the fixed address that the forge tests deploy to, so the proof can be checked against the real SP1 verifier in a test. Proving can take hours on a free runner, and the 6-hour job limit may not be enough for large N.

## Security notes
- **Replay:** per-agent nonces. Every batch has ≥1 group, each group must start above its agent's lastNonce, and settling advances it. There is no per-batch nullifier, and `batchId` is bound into the digest but is not unique on chain.
- **Per-group fields:** expiry and modelHash are per agent group.
- **Types:** amounts and balances are uint96, expiry is uint32.
- **Shared decoder:** the contract and guest decode the packed format with identical strict rules, covered by malformed-input tests on both sides, a no-panic fuzz test, and a parity fixture.
- **Not for deployment:** `test/helpers/*`.

## License
MIT, matching quantum-portfolio. `zk-batch/vendor/keccak` keeps its upstream MIT/Apache-2.0 licences.

## Note: workflow files pending
`.github/workflows/ci.yml` and `prove.yml` are written and committed on the local `with-workflows` branch, but they are not in this repo yet. The push token used to create the repo lacks GitHub's `workflow` OAuth scope, and GitHub refuses workflow files without it.
