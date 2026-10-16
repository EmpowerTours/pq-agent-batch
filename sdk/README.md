# pqagent: SDK + CLI for pq-agent-batch

`pqagent` lets a team register a post-quantum AI agent and submit **ML-DSA-65 signed actions** to the
pq-agent-batch proof-of-agency layer. You get a Rust library (`pqagent` crate) and a CLI of the same name.

- **Keys:** an ML-DSA-65 keypair is generated locally. `pkHash = sha256(encoded verifying key)`, the
  value the SP1 guest checks and `AgentRegistry` stores.
- **Signing:** orders are packed and signed with the exact code the guest runs (`agent-batch-lib`).
  The golden tests reproduce, byte for byte, the two batches that were really proved and settled on Solonet.
- **On-chain:** `selfRegister` (fee + bond), fee deposits, alerts and status use plain JSON-RPC. The
  EVM transactions are signed with an operator key that you supply. The SDK never stores that key.
- **Batching:** a small reference batcher turns a directory of signed actions into the zk-batch host's
  `--input` file. It applies the contract's nonce, cap, balance and fee rules first.

> Research prototype, devnet only, not audited. See the [main README](../README.md#security-notes-and-known-limitations).

## 5-minute quickstart

You need Rust (stable) and a node with a deployed stack. A local anvil works:
`DeploySolonet.s.sol` with `OPEN_REGISTRATION=true`, as in [`tests/anvil_e2e.sh`](tests/anvil_e2e.sh).

```bash
cargo install --path sdk            # or: cd sdk && cargo build --release  (binary: sdk/target/release/pqagent)

export PQAGENT_RPC=http://localhost:8080          # Solonet / anvil / any EVM node
export PQAGENT_PASSPHRASE='a long passphrase'     # optional: encrypts the key at rest
export SETTLEMENT=0x...                            # BatchSettlementV2 address

# 1. key + config  (.pqagent/: dir 0700, key.json 0600; the private key is never printed)
pqagent init --settlement $SETTLEMENT --model-file ./model.onnx   # or --model "my-model v1"

# 2. register: pays registrationFee + bond (minStake) as msg.value; caps 0 = registry maximum
pqagent register --operator-key-file ~/.secrets/operator.key --cap-base 2000e18 --cap-quote 4000e18
#   (or export PQAGENT_OPERATOR_KEY=0x... instead of --operator-key-file)

# 3. prepaid fees, trading balances, low-balance alert
pqagent fund    --operator-key-file ~/.secrets/operator.key --amount 0.05mon
pqagent deposit --operator-key-file ~/.secrets/operator.key --base 500e18 --quote 1000e18
pqagent alert   --operator-key-file ~/.secrets/operator.key --threshold 0.01mon
pqagent balance

# 4. sign actions (nonce = max(local counter, on-chain lastNonce + 1); expiry bucketed to the hour)
mkdir -p actions
pqagent sign --sell --amount 10e18 --min-out 1 --out actions
pqagent sign --buy  --amount 25e18 --min-out 1 --out actions
pqagent verify actions/000003-000000000001.json
pqagent status

# 5. batch them for the prover (anyone can run this, e.g. the relayer)
pqagent batch --actions actions --batch-id 1 --out batch-input.json
cd zk-batch && ./target/release/batch --execute --input ../batch-input.json   # SP1 guest; --prove for Groth16
```

Amounts accept raw base units (`1000`), `<x>e<N>` (`2.5e18`), `<x>mon` / `<x>ether` (×10¹⁸) or `<x>gwei`.
Add `--json` to any command for machine-readable output. `--dir` (or `PQAGENT_DIR`) picks the keystore.

### Example output (real run on Solonet, chain 20143)

This is from [`results/solonet/sdk-e2e/transcript.txt`](../results/solonet/sdk-e2e/transcript.txt):

```text
$ pqagent init --rpc http://localhost:8080 --settlement 0x0e1AD57BFb7E25656dE899571BE624559d871D10 --model-file model.bin
initialised .pqagent (dir 0700, key.json 0600, encrypted: yes (PQAGENT_PASSPHRASE))
pkHash     0xf5709900c093dd7e3de0eb0853ef25c3974a53176dc9d2a5e0f4377425a7195c
modelHash  0xf9125c7e8a996f6a7905194e7bc81af6f638aee0d642ed980e10abdad0b9ccb5  (model.bin)

$ pqagent register --operator-key-file $OPERATOR_KEY_FILE --cap-base 2000e18 --cap-quote 4000e18
registered agent 3  (operator 0xa0ee7a142d267c1f36714e4a8f75612f20a79720)
  paid registrationFee 0.1 MON + bond 1 MON
  caps per batch: base 2000  quote 4000
  tx 0x0f5308aa98ae96e5ede803f598a754ff0fb7baeaeb72df5223a2d728fc82adea  gasUsed 179087
AGENT_ID=3

$ pqagent status
agent 3  authorized=true  active=true  killed=false
  caps     base 2000  quote 4000
  nonces   lastNonce 0  next 4
  fees     balance 0.05  remainingActions 50

$ pqagent batch --actions actions --batch-id 1 --out batch-input.json
batch 1: 3 orders in 1 groups, 157 bytes, digest 0xee6a2c4d700b2598b464c38d38dc6c143ab89dfe477016006afeb163fd2e3917
  agent 3 nonces 1..3 feeQuote 3000000000000000
```

The contract's own `batchDigest(1, batch)` returned the same digest, and the SP1 guest (executor)
accepted the batch and committed it.

## Commands

| Command | What it does | Chain calls |
|---|---|---|
| `init` | Generates an ML-DSA-65 key and writes `key.json` (0600, optionally Argon2id + ChaCha20-Poly1305), `pubkey.hex` and `config.json` | `eth_chainId` (if `--rpc`) |
| `register` | `selfRegister(pkHash, capBase, capQuote)` with `msg.value = registrationFee + minStake (+ --extra-bond)`; parses the agent id from `AgentRegistered` | registry |
| `fund` | Fee balance top-up: `depositFeeNative`, or for an ERC20 fee token `approve` + `depositFeeToken` (`--token` selects one first) | settlement |
| `deposit` | Trading balances: `approve` + `deposit(agentId, base, quote)` | settlement, tokens |
| `balance` | Fee balance and token, `remainingActions`, fee per action / cap, alert, auto top-up, pending withdrawal, trading balances, `lastNonce` | views |
| `alert` | `setFeeAlert`, optional `setAutoTopUp` and `approve` (ERC20 fee tokens) | settlement |
| `sign` | Packs one order, ML-DSA signs it and writes the submission JSON | `agentState` (nonce) |
| `status` | `isAuthorized(id, pkHash)`, `agents(id)`, nonces, fee balance | views |
| `verify` | Offline check of a submission file | none |
| `batch` | Reference batcher, producing `batch-input.json` for `zk-batch/script --input` | views (or `--offline`) |

## Library API

```rust
use pqagent::{Agent, InitOptions, Order};
let mut agent = Agent::open(".pqagent".as_ref())?;              // or Agent::init(dir, InitOptions { .. })
let op = pqagent::chain::load_operator(Some("operator.key".as_ref()))?;
let reg = agent.register(&op, 0, 0, 0)?;                        // caps 0 = registry max
agent.fund(&op, 50_000_000_000_000_000, None)?;
let nonce = agent.next_nonce(Some(&agent.rpc()?))?;
let action = agent.sign(Order { buy_base: false, amount_in: 10u128.pow(19), min_amount_out: 1 }, nonce, u32::MAX)?;
action.verify()?;                                               // what the batcher checks
println!("{}", serde_json::to_string(&action)?);
```

Lower-level pieces:
- `keys::AgentKey`: `generate`, `from_seed`, `pk_hash`, `sign`, plus `keys::{pk_hash, model_hash, verify}`.
- `action::ActionParams::{message, sign}`.
- `batcher::{load_dir, build}`, with a pluggable `StateSource` (`OnChain`, `Offline`).

## Submission format

[`schema/signed-action.v1.json`](schema/signed-action.v1.json) is a JSON Schema (draft 2020-12). A submission
carries the fields (`chainId`, `settlement`, `agentId`, `nonce`, `expiry`, `modelHash`, `pkHash` and
`order{side, amountIn, minAmountOut}`), the derived `orderBytes` and 133-byte `message`, and the
`publicKey` (1952 B) and `signature` (3309 B). Consumers must re-derive the message from the fields and
check `sha256(publicKey) == pkHash`. `SignedAction::verify` does both.

Batching rules (enforced by the contract, so the batcher applies them first):
- Each agent's orders in one batch have **consecutive nonces** above its on-chain `lastNonce`.
- They share **one expiry and one model hash**.
- The sum per side stays within the agent's **caps** and **trading balance**.
- `feeQuote(agentId, n)` must not exceed the **fee balance**.

The batcher takes the longest valid run per agent, trims it from the end until every rule holds,
and lists each excluded file with its reason. Pool slippage is not simulated.

## Security

- **Agent key.** `key.json` holds the 32-byte FIPS 204 seed and is created with mode 0600 in a 0700 directory. The SDK refuses to load it if group or other users can read it. With `PQAGENT_PASSPHRASE` set, the seed is encrypted (Argon2id + ChaCha20-Poly1305). The SDK never prints or logs the seed.
- **Operator key.** This is the EVM key that pays for transactions. It is read from `--operator-key-file` or `PQAGENT_OPERATOR_KEY` on each call and is never written anywhere.
- **Keystore and git.** `init` drops a `.gitignore` into the keystore, and the repo's `.gitignore` excludes `.pqagent/`.
- **`--test-seed N` (hidden).** This reproduces the repo's public TEST keys for golden vectors. Those keys are not secret.

## Tests

- `cargo test --release`, run in CI in the `sdk` job:
  - TEST-key pkHashes equal the constants in the contracts.
  - Message layout, deterministic signatures, and rejection after any tampering.
  - The SDK reproduces the proved N=10 and N=100 batches and their digests byte for byte (equal to the Groth16 public values).
  - The committed batcher output `tests/fixtures/batch-input-b1-n10.json` regenerates identically.
  - Batcher rules: stale nonce, gap, expiry, fee and cap trimming, unauthorized agent, forged signature, wrong settlement.
  - Keystore permissions and encryption, amount parsing, schema coverage.
- `tests/anvil_e2e.sh` (CI): a fresh anvil and deploy, then the CLI run:
  1. `init` with an encrypted keystore.
  2. `register`, including a `CapsTooHigh` negative case.
  3. `fund`, `deposit` and `alert`.
  4. `sign` with automatic nonces plus a deliberate gap.
  5. `verify` and `status`.
  6. `batch`, checking the contract's `batchDigest` equals the SDK's digest.
  7. A batch trimmed by the fee balance.
- CI `guest-execute`: the real SP1 guest executes the SDK-built golden batch and commits the digest that was proved and settled.

## Not covered yet

- **No Groth16 proof or settlement of an SDK-registered agent's batch yet.** Proving takes ~47 min on a free runner, and `prove.yml` still builds the TEST-key batch; an `--input` option for it is the next step. The guest execution and the contract digest check above are what is verified today.
- **Python/TypeScript.** No wrapper yet; the CLI's `--json` output is the integration surface.
- **Relayer service.** `pqagent batch` is a one-shot reference tool, not a relayer daemon. There is no mempool, no automatic proving or settling, and no slippage simulation.
- **Key management.** No key rotation commands yet (`addKey` / `revokeKey` exist on the registry), and no hardware or remote signer.
