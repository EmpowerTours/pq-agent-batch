# @empowertours/pqagent (TypeScript SDK)

TypeScript SDK for the pq-agent-batch proof-of-agency layer on Monad. It does the same things as the Rust [`pqagent`](../sdk/README.md) SDK and CLI: post-quantum (ML-DSA-65) agent keys, registration, prepaid fees, signed actions and the reference batcher. Chain calls use [viem](https://viem.sh); ML-DSA-65 uses [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) (pure JS, audited noble family, pinned to `0.7.1`).

Not published to npm yet. Use it from this repo (npm workspaces):

```bash
npm ci && npm run build          # repo root: builds sdk-ts and mcp
npm test -w sdk-ts               # golden parity + batcher + keystore tests
PQAGENT_BIN=$PWD/sdk/target/release/pqagent npm test -w sdk-ts   # + cross-checks against the Rust CLI
```

## Byte-for-byte parity with the Rust SDK and the SP1 guest

All of these are exact, with no exceptions, and CI tests each one:

| What | How it is checked |
|---|---|
| Keys: FIPS 204 KeyGen from a 32-byte seed | TEST keys 1 and 2 reproduce the `pkHash`es that `DeploySolonet` registers |
| `pkHash = sha256(publicKey)`, `modelHash = keccak256(artifact)` | golden values |
| The 133-byte signed message | field-by-field layout test |
| **Signatures**: FIPS 204 *deterministic* ML-DSA-65 with an empty context | TS signs the proved N=10 batch's 10 signatures **identically** to Rust. The whole `batch-input-b1-n10.json` the Rust batcher wrote is reproduced byte for byte |
| Packed batch + digest | the proved **N=10** and **N=100** batches (SP1 Groth16 public values) and the SDK agent 4 batch that was proved and settled live, all rebuilt exactly |
| Rust verifies TS signatures | `pqagent verify` on a fresh random TS key (deterministic and hedged) |
| Rust batcher == TS batcher | `pqagent batch --offline` and the on-chain mode both produce JSON identical to `buildBatch` |
| Keystore | TS opens an encrypted `key.json` written by the Rust CLI. The Rust CLI signs with a keystore written by TS (Argon2id m=19456,t=2,p=1 + ChaCha20-Poly1305) |
| `config.json` | the same keys in the same order as `pqagent init` |

`signAction(..., { randomized: true })` produces hedged FIPS 204 signatures. These are valid for the guest and the contracts but cannot be reproduced. The default is deterministic, as in Rust.

The v1 JSON stores `nonce` and `chainId` as JSON numbers, so the TS SDK refuses values above 2^53. Rust accepts the full u64.

## API

```ts
import { promises as fs } from 'node:fs';
import { Agent, AgentKey, PqClient, SOLONET, operatorAccount, parseAmount, buildBatch, OnChainState, loadActionDir,
         signAction, verifySignedAction, batchDigest } from '@empowertours/pqagent';

// 1. keys + keystore (same .pqagent/ layout as the Rust CLI; encrypted when a passphrase / PQAGENT_PASSPHRASE is set)
const agent = await Agent.init('.pqagent', { chainId: 20143, rpc: 'http://localhost:8080', settlement: SOLONET.settlement,
  model: await fs.readFile('model.bin'), passphrase: process.env.PQAGENT_PASSPHRASE });
agent.config.pkHash; agent.config.modelHash;

// 2. register / fund / deposit / alert, either with a local operator account (env PQAGENT_OPERATOR_KEY, never stored) ...
const op = operatorAccount();
const reg = await agent.register(op, { capBaseIn: parseAmount('2000e18'), capQuoteIn: parseAmount('4000e18') });
await agent.fund(op, parseAmount('0.05mon'));
await agent.depositTrading(op, parseAmount('500e18'), parseAmount('1000e18'));
await agent.setAlert(op, parseAmount('0.01mon'));
// ... or as unsigned txs { chainId, to, data, value } for any wallet:
const tx = await agent.prepareRegister({ capBaseIn: 0n });              // 0 = registry maximum
const txs = await agent.client().buildFundTxs(reg.agentId, parseAmount('0.05mon'));

// 3. sign (writes the v1 submission JSON, schema sdk/schema/signed-action.v1.json)
const { action, path } = await agent.sign({ buyBase: false, amountIn: parseAmount('10e18'), minAmountOut: 1n }, { out: 'actions/' });
verifySignedAction(action);                                            // throws with a reason

// 4. status / balance / isAuthorized
await agent.status();                     // authorized, caps, lastNonce, nextNonce, fee balance, remainingActions
await agent.balance();                    // fee token, threshold, low, remainingActions, auto top-up, trading balances
const c = new PqClient({ ...SOLONET });   // keyless reads for any agent
await c.isAuthorized(4, '0x7c2c…1602');

// 5. batch (same acceptance rules as settle(): authorization, nonces, caps, balances, prepaid fees)
const b = await buildBatch(await loadActionDir('actions'), { chainId: 20143, settlement: SOLONET.settlement, batchId: 1 }, new OnChainState(c));
b.digest === await c.batchDigest(1, b.batch);   // == the SP1 proof's public values
```

Secret handling: the ML-DSA seed and expanded secret key are `#private` fields. `JSON.stringify(key)`, `console.log(key)` and `String(key)` show only the pkHash, and a test enforces this. `key.json` is written 0600 in a 0700 directory, and loading refuses a group- or world-readable file. The operator EVM key goes straight into a viem `Account` and is never written anywhere. JavaScript cannot guarantee that every copy of a secret is erased, so `AgentKey.destroy()` zeroes the buffers on a best-effort basis.

## End-to-end script

`scripts/e2e.ts` runs init → register → fund → deposit → alert → balance → sign ×3 (+1 with a gap) → status → on-chain batch, then checks that the contract's `batchDigest` equals the SDK digest. If `PQAGENT_BIN` is set, it also checks that the Rust batcher output is byte-identical.

```bash
PQAGENT_RPC=http://localhost:8080 SETTLEMENT=0x0e1A…1D10 OPERATOR_KEY_FILE=op.key OUT_DIR=out node --import tsx sdk-ts/scripts/e2e.ts
```

Live Solonet run (agent 5 registered by the TS SDK): [`results/solonet/ts-mcp/sdk-e2e/`](../results/solonet/ts-mcp/sdk-e2e/sdk-e2e-transcript.txt).
