# pq-agent-batch: free-tooling security audit

**Scope:** `contracts/src/` at `e5aa627`: `AgentRegistry.sol`, `BatchSettlementV2.sol`, `AgentFees.sol`, plus `dex/MiniAMM.sol` / `dex/MockToken.sol` (production dependency check), `script/DeploySolonet.s.sol`, the SP1 verifier wiring and vkey pinning, and the SP1 guest (`zk-batch/program`, `zk-batch/lib`). Also the off-chain signing defaults in the SDK, CLI and MCP server where they affect on-chain safety.
**Date:** 2026-10-16 (box-local America/Mexico_City).
**Method:** Slither 0.11.6, Aderyn 0.6.8, Mythril 0.24.8 (runtime bytecode), Halmos 0.3.3, Foundry 1.8.5 fuzz and invariant tests, read-only `eth_call` probes against Monad mainnet (Monad/0.16.4, chain 143), and a line-by-line manual review. No transactions were sent to any network.

> This is **not** a professional audit. It is a structured self-review with free tools, done to remove the obvious problems before paying for one. See [What a paid audit should focus on](#what-a-paid-audit-should-focus-on).

## Summary

| Severity | Found | Fixed | Mitigated / partly fixed | Open (accepted or deferred) |
|---|---|---|---|---|
| Critical | 0 | – | – | – |
| High | 0 | – | – | – |
| Medium | 4 | 2 (M-01, M-02) | 2 (M-03, M-04) | 0 |
| Low | 12 | 7 | – | 5 |
| Info | 10 | – | – | 10 (by design or documented) |

**No soundness bug was found in the guest, the digest binding or the verifier wiring. The guest program is unchanged, so the vkey and all existing proofs are unchanged.** The committed real N=10 and N=100 Groth16 proofs still settle in CI against the fixed contract.

**What changes for deployment:** the contract bytecode and ABI changed. There is a new `GroupSkipped` event, new errors, `AgentRegistry.agentStatus`, `transferAdmin` and `acceptAdmin`, and the constructor now validates its inputs. Settlement semantics also changed (M-01): a group that cannot settle is now skipped instead of reverting the whole batch. Any deployment needs the new contracts, which every mainnet deployment would be anyway. The packed batch format, the signed message, the digest and the vkey are all unchanged. There is a new script, `script/DeployMainnetLimited.s.sol`, for a limited mainnet launch.

## Findings

| ID | Severity | Title | Location | Status |
|---|---|---|---|---|
| M-01 | Medium | Any agent in a batch could revert the whole already-proved batch | `BatchSettlementV2.settle/_debitGroup`, `AgentFees._chargeFee` | **Fixed** |
| M-02 | Medium | SDK, CLI and MCP signed orders with `minAmountOut = 0` by default (sandwichable) | `sdk/src/bin/pqagent.rs`, `mcp/src/server.ts` | **Fixed** |
| M-03 | Medium | Clearing uses the spot price of a self-deployed MiniAMM; production depends on the "test helper" AMM | `BatchSettlementV2.settle`, `dex/MiniAMM.sol` | **Mitigated** (per-order `minOut` now required; near-zero caps for the limited launch); open for full launch |
| M-04 | Medium | Centralized admin powers, and admin was not transferable | `AgentRegistry`, `AgentFees` | **Partly fixed** (two-step transfer; the mainnet script requires contract admin, guardian and treasury); timelock is a deployment step |
| L-01 | Low | Admin can raise `registrationFee` in front of a `selfRegister`, taking part of the intended bond | `AgentRegistry._register` | Open (timelock, or a `maxFee` argument in a later ABI) |
| L-02 | Low | Fee-on-transfer / short-delivering tokens credited at face value (insolvency) | `deposit`, `depositFeeToken`, `topUp` | **Fixed** |
| L-03 | Low | Deposits accepted for unregistered (future) agent ids | `BatchSettlementV2.deposit` | **Fixed** |
| L-04 | Low | `admin` could never change (no handover to a multisig or timelock) | `AgentRegistry` | **Fixed** |
| L-05 | Low | Constructor did not validate verifier, registry, pool or vkey | `BatchSettlementV2.constructor` | **Fixed** |
| L-06 | Low | Dust AMM residual (zero output) reverted the whole batch (`swap(0,0)`) | `BatchSettlementV2.settle` | **Fixed** |
| L-07 | Low | Payouts to `address(0)` possible (withdraw, fee withdrawal, slash) | `withdraw`, `requestFeeWithdrawal`, `slash` | **Fixed** |
| L-08 | Low | Model hash is signed but not registered or enforced on-chain | `AgentRegistry`, `settle` | Open (contract-only change, no vkey change) |
| L-09 | Low | Caps are per batch, not per time window | `_debitGroup` | Open |
| L-10 | Low | Operators cannot exit their bond; only the admin can retire or slash | `AgentRegistry.retire/slash` | Open |
| L-11 | Low | Monad reserve-balance rule can revert back-to-back value transactions from small EOAs | SDK flows (`register` → `fund`) | Open (documented; SDK change suggested) |
| L-12 | Low | `feeWithdrawDelay` defaults to 0 (devnet script never sets it) | `DeploySolonet.s.sol` | **Fixed** for mainnet (new script defaults to 1 day) |
| I-01 | Info | `retire` and `slash` push MON; a reverting operator blocks its own retire | `AgentRegistry` | Accepted |
| I-02 | Info | Key registration has no proof of possession | `AgentRegistry` | Accepted (signatures are bound to `agentId`) |
| I-03 | Info | `ml-dsa` 0.1.1 is past both published advisories | `zk-batch/lib` | No action; add `cargo audit` |
| I-04 | Info | Settlement is permissionless; whoever submits chooses the timing | `settle` | By design |
| I-05 | Info | A skipped group can settle later from the same proof (until its expiry) | `settle` | By design, documented and tested |
| I-06 | Info | Monad USDC is upgradeable and blacklistable; as base/quote it could brick trading | deployment | Use it as a fee token only, or accept |
| I-07 | Info | Gas: Monad charges the gas **limit**; worst case is about 400 distinct-agent groups under 30M | `settle` | Documented |
| I-08 | Info | Event coverage: unindexed address params; no event on `revive` of an inactive id | `AgentRegistry` | Accepted |
| I-09 | Info | No upgradeability; vkey, verifier and pool are immutable | all | By design (trust); plan a migration path |
| I-10 | Info | Solonet vs mainnet differences checked | – | See [Monad specifics](#monad-specifics-checked-on-mainnet-read-only) |

### M-01: any agent could grief a proved batch (Fixed)

**Before:** `settle` reverted the *whole* batch if any one group failed an agent-state check: killed, unknown or revoked key, stale nonce, over caps, short trading balance, short fee balance, or expired. Each of these can change *after* the batch is proved. The operator can `withdraw` its trading balance with no delay, `kill` itself, or `revokeKey`, and with open registration anyone can become an operator for a 1 MON bond. One griefer per batch therefore wasted every proof (24–165 min of free-runner proving) and blocked every other agent in it. The fee-withdrawal delay only covered one of these vectors. Reproduced on `e5aa627`: `settle` reverts `InsufficientBalance(1)` after agent 1 withdraws.

**Fix:** pass 1 now classifies each group. A group that cannot settle *because of agent state* is skipped: no trade, no fee, no nonce change, and `GroupSkipped(batchId, agentId, reason)` is emitted, where `reason` is the abi-encoded custom error. The rest of the batch settles. Framing errors, a bad proof and slippage still revert the whole batch. If no group can settle (e.g. a replayed batch), `settle` reverts with the first group's error, so single-agent behaviour and error data are unchanged. The registry gained a non-reverting `agentStatus(id, pkHash)`. Gas is unchanged within noise: the real N=100 proof settles for 434,010 forge gas, versus 434,839 before.

**Tests:** `test/audit/AuditFixes.t.sol` `test_M01_*` (withdraw, self-kill, revoked key and expiry after proving; skipped group settles once on resubmission; a bad proof still reverts everything), updated `BatchSettlementV2.t.sol` / `AgentFees.t.sol` cases, and the invariant campaign (a settleable group always settles, an unsettleable one never moves).

**Trade-off (I-05):** a skipped group's signed orders stay valid until their expiry. Resubmitting the same proof later can settle that group alone. Each group can still settle at most once, because nonces are enforced. This is what the agent signed, and `minOut` bounds the price.

### M-02: zero slippage bound by default (Fixed)

`pqagent sign` defaulted `--min-out` to 0, and the MCP `sign_action` tool made `minAmountOut` optional with a default of 0. An order with `minOut = 0` that is settled against a manipulable spot price (M-03) can be sandwiched for almost all of its value. **Fix:** the CLI now requires `--min-out` (an explicit `--no-slippage-limit` is the only way to sign 0), and the MCP schema requires `minAmountOut`. The CI e2e scripts were updated. The contract still enforces each order's `minOut`.

### M-03: spot-price clearing against MiniAMM (Mitigated; open for full launch)

`BatchSettlementV2` takes `MiniAMM` in its constructor (immutable). It nets buyers and sellers at the pool's **spot** reserves ratio and sends the residual to that pool. MiniAMM is labelled a test helper, but **production depends on it**: mainnet needs a MiniAMM instance with real tokens and real liquidity. Anyone can move the spot price in the same block before a settlement and back after it. The only defence is each order's `minOut`. **Mitigation now:** M-02 forces a slippage bound, and for the limited launch, trading caps stay near zero (`SELF_CAP_* = 1e15` default in the mainnet script). **Before a real trading launch:** bound the clearing price against a TWAP or oracle, or route through an established DEX with an adapter, and add per-batch price-impact limits. `MockToken` is used only by tests and `DeploySolonet`; the mainnet script never deploys it.

### M-04: centralization (Partly fixed)

The admin can register agents with any caps, `setCaps`, `revive`, set fees per action up to `uint72` with no cap (which can drain prepaid fee balances in the next batch an agent is in), set the treasury, `slash` any amount of any bond to any address, and `retire`. The guardian can only kill. `admin` was fixed at construction, so a deployer EOA could never hand control to a multisig. **Fixed:** two-step `transferAdmin` / `acceptAdmin` (L-04). `DeployMainnetLimited.s.sol` refuses EOA admin, guardian and treasury and ends by proposing the multisig. **Required at deployment:** admin = a Safe behind a `TimelockController` (for example a 48 h delay for fees, caps, slash and treasury), guardian = a separate fast Safe for kill only, treasury = a Safe.

### Low findings (summary)

- **L-01:** `_register` takes the *current* fee out of `msg.value`. If the admin raises the fee just before a `selfRegister`, the user's bond shrinks, though it stays at least `minStake`. Use a timelock now; a later ABI could take `maxFee`.
- **L-02 (fixed):** `_pullExact` checks the balance delta and reverts `UnsupportedToken(expected, received)`. Tests: `test_L02_*`.
- **L-03 (fixed):** `deposit` requires a registered id. Before, funds sent to id N+1 belonged to whoever registered next. Reproduced on `e5aa627`. Test: `test_L03_*`.
- **L-04 (fixed):** two-step admin transfer; `AgentFees.onlyAdmin` follows `registry.admin()`. Test: `test_L04_*`.
- **L-05 (fixed):** the constructor reverts `BadConfig` for a zero vkey or a codeless verifier, registry or pool. Test: `test_L05_*`.
- **L-06 (fixed):** when the AMM output rounds to 0, the dust input stays in the contract instead of calling `swap(0,0)`, which reverted `InsufficientOutput`. Reproduced on `e5aa627`. Tests: `test_L06_*`, `testFuzz_ResidualNeverBricks`.
- **L-07 (fixed):** zero-address checks on `withdraw`, `requestFeeWithdrawal` and `slash`. Test: `test_L07_*`.
- **L-08:** the batch header's `modelHash` is signed by the agent and bound by the proof, but the registry stores no model hash. "Registered model hash" is therefore only a self-claim today. Storing it in the registry and checking it in `agentStatus` is a contract-only change, since the header offset is known; the vkey does not change.
- **L-09:** caps limit each batch, not each hour or day. A stolen agent key can trade the agent's whole deposited balance over several batches, bounded by the `minOut` it chooses itself. Funds can only leave via the operator's `withdraw`. Add per-epoch caps before larger balances.
- **L-10:** bonds leave only through admin `retire` (to the operator) or `slash` (anywhere). Operators cannot exit on their own. Add an operator-initiated retire with a delay during which the admin can still slash.
- **L-11 (Monad):** under Monad's reserve-balance rules, a transaction whose *value* transfer leaves an EOA under 10 MON reverts. The exception is an "emptying" transaction from an undelegated EOA with no transactions in the previous 3 blocks; EIP-7702-delegated EOAs never get that exception. `pqagent register` (1.1 MON) followed immediately by `pqagent fund` from a small wallet can therefore revert on mainnet, which Solonet with its rich test accounts never showed. The SDK should wait more than 3 blocks between value-carrying transactions, or tell users to keep at least 10 MON.
- **L-12 (fixed for mainnet):** the devnet script leaves `feeWithdrawDelay = 0`; the mainnet script defaults it to 1 day. After M-01 the delay matters less, because a short fee balance now only skips that agent.

### Info (summary)

I-01: a reverting operator can only block its own `retire`, and slash to another address still works. I-02: registering someone else's `pkHash` gains nothing, because signed messages include `agentId`. I-03: `ml-dsa` 0.1.1 is past RUSTSEC-2025-0144 (signing timing, fixed in rc.3) and CVE-2026-24850 (duplicate hint indices, fixed in rc.4); add `cargo audit` to CI. I-04: anyone can submit a published proof, and the submitter picks the timing, e.g. after one group expires; acceptable after M-01. I-05: see M-01. I-06: Monad USDC is an upgradeable proxy with a blacklist; as base or quote, a blacklisted pool or settlement would brick trading. I-07: see gas below. I-08: `GuardianSet`, `TreasurySet` and `RegistrationFeesSwept` addresses are unindexed; `revive` emits on inactive ids. I-09: everything is immutable, so a fix means redeploying and migrating agents (re-register, withdraw and deposit); keep that runbook ready. I-10: see below.

## Guest program and proof binding (manual review; no change)

- **Signature check:** `parse_batch` applies the same framing rules as the contract (strictly ascending `agentId`, `count ≥ 1`, flags ≤ 1, nonce overflow, no trailing bytes). For each group, the guest checks `sha256(pk) == pkHash` and then ML-DSA-65-verifies every order over `ORDER_TAG_V2 | chainid | settlement | agentId | nonce | expiry | modelHash | order`. That gives domain separation by chain, contract, agent, nonce and expiry. Any failure panics, so no proof can be produced.
- **Digest binding:** the public value is `keccak256(abi.encode(BATCH_TAG_V2, chainid, settlement, batchId, keccak256(batch)))`. The contract recomputes it from its *own* `block.chainid` and `address(this)` and the exact calldata bytes, so a proof cannot be moved to another chain, contract, batch id or byte string. Existing tests cover tampered bytes, wrong id, wrong chain and a tampered proof, and the new `test_DomainSeparation_*` covers another contract address.
- **Order decoding:** the contract's `calldataload` reads 7 bytes past each 25-byte order, but those bits are masked off, and the offsets are bounds-checked first.
- **On-chain only:** nonces, caps, expiry, zero amounts and registry status are enforced only on-chain, by design. Pass-1 reads all of them, and the guest commits to the bytes they come from.
- **Vkey pinning:** `batchProgramVKey` and `verifier` are immutable, and the constructor now rejects a zero vkey or a codeless verifier. The verifier runtime is byte-identical to Succinct's Monad mainnet `V6_1_0_SP1_VERIFIER_GROTH16` at `0xb69f2584…f4e2`. The mainnet script also checks `VERSION()` and `VERIFIER_HASH()`.
- **Verdict:** no guest change needed. The vkey and existing proofs are unchanged.

## Monad specifics (checked on mainnet, read-only)

| Check | Result |
|---|---|
| Real N=100 Groth16 proof against Succinct's **mainnet** verifier via `eth_call` | **Valid** on Monad/0.16.4; a tampered proof reverts `0x7fcdd1f4`. `eth_estimateGas` = **1,129,190** (5× ecPairing pricing included) |
| `TSTORE`/`TLOAD` (transient reentrancy guard), `MCOPY`, `BLOBBASEFEE` via `eth_call` creation probe | All work on 0.16.4 (chain id 143) |
| Full limited deployment, simulated with `forge script --fork-url https://rpc.monad.xyz` (no broadcast) | Succeeds; about 11.5M gas (forge estimate), so about 2.3 MON at 100 gwei base + 2 gwei tip. Output: `tool-output/mainnet-deploy-dryrun.txt` |
| Gas limit is charged, not gas used | `settle_proof.py` already uses `eth_estimateGas`. Keep the margin at ≤ 10%; the devnet `--gas-estimate-multiplier 300` would triple deployment cost on mainnet |
| 30M per-tx cap | Local worst case (every order from a different agent): 25k gas per group under EVM pricing (`test/audit/GasLimits.t.sol`). With Monad's higher cold-access pricing, assume about 60–70k per group, plus about 1.1M for the proof and about 0.3M base. That is roughly 400 distinct-agent groups max per batch. Same-agent orders cost about 0.7k each locally (13.8k per order measured on Solonet at N=100). Proving time (165 min for N=100), not gas, is the binding limit |
| Parallel execution | No ordering assumptions in the contracts. Settlements touching the same agents simply serialize |
| Reserve balance | See L-11 (affects EOAs sending value, not the contracts) |
| Solonet 0.16.5 vs mainnet 0.16.4 | No behavioural difference found for the opcodes, precompiles and verifier used. The remaining risk is gas pricing only, so re-measure the first mainnet settlement |

## Tool results and triage

Raw outputs are in `audits/tool-output/`.

### Slither (`slither-baseline.txt` = e5aa627, 31 results; `slither-final.txt` = fixed, 17 results, `--fail-medium` passes; CI job added)

| Detector (impact) | Where | Triage |
|---|---|---|
| arbitrary-send-erc20 (High) | `AgentFees.topUp` pulls from `cfg.from` | **False positive.** `cfg.from` is the operator that configured auto top-up (`msg.sender` in `setAutoTopUp`), and the amount is exactly what they set, credited to their own agent. Covered by `test_TopUp_CannotPullForOtherAgents`. After the L-02 refactor the call moved into `_pullExact` and is no longer flagged |
| arbitrary-send-eth (High) | `AgentRegistry.sweepRegistrationFees` | **False positive / accepted.** It pays the admin-set treasury exactly `accruedRegistrationFees`. Suppressed inline (S-02). Halmos `check_bondsOnlyLeaveViaAdmin` proves non-admin calls can't move bonds |
| reentrancy-no-eth (Medium) | `settle` writes `agentState` / `feeAccount` after `pool.swap` | **False positive.** Pool and tokens are immutable and trusted, and every state-changing entrypoint holds the transient `nonReentrant` lock (tests `test_Reentrancy_*`). Suppressed with a reason (S-05) |
| divide-before-multiply, incorrect-equality (Medium) | `MiniAMM` | **False positive.** These are the standard Uniswap-V2 quote rounding and intended zero checks. Suppressed (S-03, S-04) |
| unused-return (Medium) | `registry.agents()` tuple destructuring | **False positive.** Only the needed fields are used. Suppressed (S-06) |
| missing-zero-check (Low) | `slash` `to` (baseline); `transferAdmin(next)` (final) | `slash`: **true positive, fixed (L-07)**. `transferAdmin(0)` is the intended "cancel" |
| calls-loop (Low) | `registry.agentStatus` per group | **Accepted.** One trusted view call per agent group, bounded by calldata and gas (I-07) |
| timestamp (Low) | expiry, withdrawal delay | **Accepted.** Second-level precision is fine for minute-to-day windows |
| assembly, low-level-calls, cyclomatic-complexity, naming, immutable-states (Info) | various | **Accepted.** Calldata decoding is assembly by design and bounds-checked. `admin` "could be immutable" was superseded by L-04 |
| unindexed-event-address (Info) | registry events | **Accepted (I-08)** |

### Aderyn (`aderyn-baseline.md`, `aderyn-final.md`)

| Issue | Triage |
|---|---|
| H-1 ETH transferred without address checks (`sweepFees`, `sweepRegistrationFees`) | **False positive.** The destination is `registry.treasury()`, which `setTreasury` keeps non-zero |
| H-2 state change after external call (`deposit`, `withdraw`, `settle`, constructor) | **False positive.** Calls go to the immutable registry (views), pool and tokens, all under `nonReentrant`. The constructor case reads `pool.token0/1` |
| L-1 costly ops in loop, L-6 revert in loop | **Accepted.** Per-group work is inherent; the reverts are framing checks |
| L-2/L-3 literals, L-5 PUSH0, L-9 pragma | **Accepted.** Monad supports PUSH0 (Cancun, verified by the probe); `ISP1Verifier` keeps Succinct's `^0.8.20` |
| L-4 shadowing (`AgentState.base/quote` vs `base()/quote()`, MiniAMM `_totalSupply`) | **Accepted.** These are struct field names; no confusion in the code |
| L-7 address set without checks (`pendingAdmin`) | **Accepted.** Zero cancels a pending transfer |
| L-8 uninitialized local | **False positive.** The zero default is intended (`ammOut`, cursors) |

### Mythril (`mythril-AgentRegistry.txt`, `mythril-BatchSettlementV2.txt`; runtime bytecode, 2-tx depth, 1,500 s budget each)

- **SWC-101 integer overflow, 39 + 37 hits:** **all false positives.** Every flagged PC is the ABI decoder's `add(calldatasize(), 0xff…fc)` length check that via-IR emits for each function (verified by disassembly). That is intentional wrapping arithmetic in Solidity 0.8.
- **SWC-114 transaction-order dependence on `sweepRegistrationFees`:** **accepted.** It pays whatever has accrued to the treasury; ordering doesn't matter.
- **SWC-123 requirement violation in the fallback:** **false positive.** There is no fallback, so it reverts by design.
- Mythril found nothing the other tools missed. (Mythril needed Python 3.11 with `setuptools<70`; the Python 3.13 build of `ckzg` fails.)

### Halmos (`halmos.txt`; `test/audit/Halmos.t.sol`, also a CI job)

All 5 symbolic checks pass with no bounds hit:
- `check_bondsOnlyLeaveViaAdmin`: arbitrary calldata to the registry from any non-admin never reduces its MON below `balance − accruedRegistrationFees`.
- `check_onlyOperatorWithdraws`: any non-operator `withdraw` reverts.
- `check_agentStatusMatchesIsAuthorized`: settlement and apps agree after a kill or key rotation.
- `check_feeQuoteBounded`: the fee is never above the cap and is linear below it.
- `check_singleOrderSettle`: with a symbolic nonce, side, amount and minOut, success implies the nonce strictly increased to `firstNonce`, the amount was within the cap and the balance, and the same batch can never settle again. Failure implies no state change.

### Foundry fuzz and invariants (`forge-deep.txt`)

There are 83 tests: the 64 existing ones (updated for M-01) and 19 new ones in `test/audit/`. The deep profile was run locally (`FOUNDRY_PROFILE=deep`: 50,000 fuzz runs per property, and an invariant campaign of 1,000 runs × 500 calls = 500,000 calls). **All pass.** CI runs the default profile (256 fuzz runs; invariants 64 × 250).

Invariants (`test/audit/Invariants.t.sol`). A handler drives deposits, withdrawals, fee deposits and withdrawals, sweeps, kill and revive, cap and fee changes, random batches (stale nonces, over-cap, killed and short agents) and replays of earlier batches:
- **No agent spends past its caps per batch:** a settleable group always settles, and an over-cap, killed, unknown-key, stale-nonce or short group never moves.
- **Nonces strictly increase and replays fail:** a replayed batch never re-executes a settled group.
- **Fee conservation (exact):** contract MON = Σ fee balances + accrued = deposits − withdrawals − sweeps.
- **Trading solvency:** token balance ≥ Σ agent balances (dust may accrue, never a deficit).
- **Bond conservation (exact):** registry MON = Σ stakes + unswept registration fees.

A coverage probe confirms that settlements, skips and replays all occur within the first ~550 calls. Property fuzzing covers `testFuzz_CapsEnforcedPerBatch` and `testFuzz_ResidualNeverBricks`. The existing fuzzers (`AnyByteFlipRejected`, `RandomBlobNeverPanics`, `WellFormedBatchesSolvent`, `FeeMathAndSolvency`, `SequenceSolvency`) cover digest malleation and solvency. "Only a valid proof for the pinned vkey settles" is covered by the real-proof tests (`RealGroth16Settle.t.sol`): a tampered proof, a wrong id or chain, and tampered bytes are all rejected by the real verifier.

### Ultrafuzz (monad-developers/ultrafuzz): **not run**

I cloned it to `/workspace/ultrafuzz` (commit `81aec3b`; release tags v0.1.0–v0.1.4) and read the README, `ultrafuzz.toml`, `docs/config.md` and `docs/security.md` before running anything. It is an orchestrator that runs LLM coding agents. Every supported agent needs a paid model:
- `CodexAgent`: the default, `gpt-5.5`, needs `OPENAI_API_KEY`.
- `ClaudeAgent`: a logged-in Claude Code subscription, or `ANTHROPIC_API_KEY`.
- `KimiAgent`: a Kimi Code subscription or `KIMI_API_KEY`.
- `DeepSeekAgent`: `DEEPSEEK_API_KEY`.
- `OpenRouterAgent`, `PiAgent` and `OpenCodeAgent`: `OPENROUTER_API_KEY`.

There is no local or free model option. Its own security note also says agents run in "skip-permissions" mode and recommends **only ephemeral, disposable VMs**. This box is persistent and shared. I did not install its dependencies, sign up for anything, or give it any key or token, so it **produced no findings**. To run it later, you need one of the keys above and a throwaway VM, and you should use a release tag that is at least 7 days old.

Its checked-in strategy prompts (packed-action parity, batch atomicity, externalized-state accounting, admin-config boundaries, payable accounting) were used as a manual checklist. The "batch atomicity" lens corresponds to M-01, which the manual review had already found. **Nothing new was attributed to Ultrafuzz.**

## Readiness verdict: limited mainnet launch

**Ready for a *limited* launch once the deployment conditions below are met. Not ready for a real-money trading launch.**

Conditions:
1. Deploy with `script/DeployMainnetLimited.s.sol`, after a fork dry run (done once here) and a review of the exact env values.
2. Admin = a Safe behind a TimelockController (≥ 24–48 h), which then calls `acceptAdmin()`. Guardian = a separate Safe (kill only). Treasury = a Safe.
3. Keep trading near zero: `SELF_CAP_*` ≈ 1e15, admin-registered caps tiny, and a seeded MiniAMM with only token amounts you can afford to lose. Alternatively, launch registry, fees and proof-checking only, and leave the pool unseeded.
4. Small `minStake` and `registrationFee`, `FEE_WITHDRAW_DELAY` ≥ 1 day, `maxFeePerBatch` set.
5. Settle with gas limit = estimate + ≤ 10%. Re-measure the first mainnet settlement. Keep the settler and operator wallets ≥ 10 MON (L-11).
6. Monitor `GroupSkipped`, `Killed` and `LowFeeBalance`, and have a kill runbook.

Before larger balances: fix M-03 (price guard), L-08 (model hash on-chain), L-09 (per-epoch caps) and L-10 (operator exit with delay), and get a paid audit.

## What a paid audit should focus on

1. The `BatchSettlementV2.settle` assembly decoder and two-pass accounting, including the new skip path: pro-rata rounding, the `pot` and residual math, and the `uint96` casts.
2. Economic and MEV design of spot-price netting against MiniAMM (M-03), and the oracle or TWAP guard that replaces it.
3. Guest ↔ contract parity: the framing rules, the signed-message layout, and the ML-DSA crate's FIPS 204 conformance (context string, hint encoding). Also the SP1 toolchain and vkey reproducibility (rebuilding the guest gives the same vkey).
4. Admin and timelock configuration, slashing policy, and the bond lifecycle (L-01, L-10).
5. Fee accounting across multiple fee tokens, the top-up and allowance model, and withdrawal timing.
6. Monad-specific gas, reserve-balance behaviour and parallel-execution assumptions on the deployed configuration.

## Reproduce

```bash
cd contracts
forge test                                   # 83 tests (CI profile)
FOUNDRY_PROFILE=deep forge test              # 50k fuzz runs, 1000x500 invariant calls
halmos --match-contract HalmosAudit --solver-timeout-assertion 60000 --loop 4
slither . --filter-paths "lib/|test/|script/|src/dex/MockToken.sol" --exclude-dependencies --fail-medium
aderyn . --src src -x "dex/MockToken.sol"
```
