/**
 * Golden parity with the Rust SDK + SP1 guest: keys / pkHashes the contracts know, the message layout,
 * deterministic signatures, and the batches that were really proved (SP1 Groth16) and settled on Solonet.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { keccak_256 } from '@noble/hashes/sha3.js';
import {
  AgentKey, BATCH_INPUT_SCHEMA, OfflineState, SCHEMA_ID, actionMessage, batchDigest, batchInputJson, buildBatch, decodeOrder,
  encodeOrder, hex0x, modelHash, parseBatch, pkHash, signAction, unhex, verifyBatch, verifySignedAction,
  type SignedAction, type StateSource, type Submission,
} from '../src/index.js';

const ROOT = join(import.meta.dirname, '..', '..');
// contracts/script/DeploySolonet.s.sol TEST_PK_A / TEST_PK_B
const PK_A = '0x8b1551c421b573beeaebb39debb1e0371e13c93155a7a5be60b29dd691095b05';
const PK_B = '0x62d3462f41b0be23edd19e0aa7477bf95edcf207d9d325ddd73298cb14a946e3';
const MODEL = 'quantum-portfolio model v1 (test)';
const json = (p: string) => JSON.parse(readFileSync(join(ROOT, p), 'utf8'));
const fixture = (name: string) => json(`results/solonet/${name}/groth16-batch-fixture.json`);

describe('keys', () => {
  it('TEST keys reproduce the pkHashes registered by DeploySolonet', () => {
    expect(AgentKey.testKey(1).pkHashHex).toBe(PK_A);
    expect(AgentKey.testKey(2).pkHashHex).toBe(PK_B);
    const k = AgentKey.testKey(1);
    expect(k.publicKey.length).toBe(1952);
    expect(hex0x(pkHash(k.publicKey))).toBe(PK_A);
  });
  it('modelHash = keccak256(artifact)', () => {
    expect(hex0x(modelHash(MODEL))).toBe(hex0x(keccak_256(new TextEncoder().encode(MODEL))));
    expect(hex0x(modelHash(new TextEncoder().encode(MODEL)))).toBe(hex0x(modelHash(MODEL)));
  });
  it('never exposes the secret key through JSON / inspect / toString', async () => {
    const k = AgentKey.testKey(1);
    const seedHex = Buffer.from(keccak_256(new Uint8Array([...new TextEncoder().encode('EmpowerTours test agent seed '), 1]))).toString('hex');
    const { inspect } = await import('node:util');
    for (const s of [JSON.stringify(k), inspect(k, { depth: 10, showHidden: true }), String(k)]) {
      expect(s).not.toContain(seedHex);
      expect(s.length).toBeLessThan(200);
    }
    // only public material is reachable as properties (seed + expanded secret key are #private fields)
    expect(Object.keys(k).sort()).toEqual(['pkHash', 'publicKey']);
  });
});

describe('message + signature', () => {
  const k = AgentKey.testKey(1);
  const p = { chainId: 20143, settlement: '0x' + '46'.repeat(20), agentId: 7, nonce: 42, expiry: 1_800_000_000,
    modelHash: '0x' + 'ab'.repeat(32), order: { buyBase: true, amountIn: 5n, minAmountOut: 3n } };
  it('133-byte layout identical to the guest', () => {
    const m = actionMessage(p);
    expect(m.length).toBe(133);
    expect(hex0x(m.subarray(0, 32))).toBe(hex0x(keccak_256(new TextEncoder().encode('EmpowerTours.AgentOrder.v2'))));
    expect(Buffer.from(m.subarray(32, 40)).toString('hex')).toBe('0000000000004eaf');
    expect(Buffer.from(m.subarray(40, 60)).toString('hex')).toBe('46'.repeat(20));
    expect(Buffer.from(m.subarray(60, 64)).toString('hex')).toBe('00000007');
    expect(Buffer.from(m.subarray(64, 72)).toString('hex')).toBe('000000000000002a');
    expect(Buffer.from(m.subarray(72, 76)).toString('hex')).toBe((1_800_000_000).toString(16).padStart(8, '0'));
    expect(Buffer.from(m.subarray(76, 108)).toString('hex')).toBe('ab'.repeat(32));
    expect(Buffer.from(m.subarray(108)).toString('hex')).toBe('01000000000000000000000005000000000000000000000003');
  });
  it('deterministic FIPS 204 signing, offline verification, tamper detection', () => {
    const s = signAction(p, k);
    expect(unhex(s.signature).length).toBe(3309);
    verifySignedAction(s);
    expect(signAction(p, k).signature).toBe(s.signature);
    // hedged signatures differ but still verify (guest accepts both)
    const r = signAction(p, k, { randomized: true });
    expect(r.signature).not.toBe(s.signature);
    verifySignedAction(r);
    const bad: [string, (t: SignedAction) => void][] = [
      ['nonce', (t) => { t.nonce = 43; }], ['amount', (t) => { t.order.amountIn = '6'; }],
      ['pkHash', (t) => { t.pkHash = PK_B; }], ['publicKey', (t) => { t.publicKey = hex0x(AgentKey.testKey(2).publicKey); }],
      ['unknown field', (t) => { (t as any).extra = 1; }], ['schema', (t) => { t.schema = 'x'; }],
    ];
    for (const [, f] of bad) { const t = structuredClone(s); f(t); expect(() => verifySignedAction(t)).toThrow(); }
    expect(() => encodeOrder({ buyBase: false, amountIn: 0n, minAmountOut: 0n })).toThrow();
    expect(() => encodeOrder({ buyBase: false, amountIn: 1n << 96n, minAmountOut: 0n })).toThrow();
    expect(decodeOrder(encodeOrder(p.order))).toEqual(p.order);
  });
  it('output matches the v1 JSON schema (required fields, patterns, const)', () => {
    const schema = json('sdk/schema/signed-action.v1.json');
    const s = signAction({ chainId: 1, settlement: '0x' + '01'.repeat(20), agentId: 1, nonce: 1, expiry: 1, modelHash: '0x' + '00'.repeat(32),
      order: { buyBase: false, amountIn: 1n, minAmountOut: 0n } }, k);
    expect(Object.keys(s)).toEqual(schema.required);
    expect(s.schema).toBe(schema.properties.schema.const);
    expect(s.schema).toBe(SCHEMA_ID);
    for (const [key, v] of Object.entries(s)) {
      const pat = schema.properties[key].pattern;
      if (pat) expect(new RegExp(pat).test(v as string), key).toBe(true);
    }
    for (const [key, v] of Object.entries(s.order)) expect(new RegExp(schema.properties.order.properties[key].pattern ?? '.').test(v)).toBe(true);
  });
});

/** Sign the zk-batch host's deterministic order pattern (same as sdk/tests/golden.rs::sdk_batch). */
async function sdkBatch(n: number, nonceBase: number, batchId: number, chainId: number, settlement: string) {
  const keys = [AgentKey.testKey(1), AgentKey.testKey(2)];
  const mh = modelHash(MODEL);
  const half = Math.ceil(n / 2);
  const actions: Submission[] = [];
  for (let i = 0; i < n; i++) {
    const g = i >= half ? 1 : 0;
    const buy = i % 2 === 0;
    const amt = (buy ? 2_000_000_000_000_000_000n : 1_000_000_000_000_000_000n) + BigInt(i) * 1_000_000_000_000_000n;
    const s = signAction({ chainId, settlement, agentId: g + 1, nonce: nonceBase + i + 1, expiry: 0xffffffff, modelHash: mh,
      order: { buyBase: buy, amountIn: amt, minAmountOut: 1n } }, keys[g]);
    actions.push([`${String(i).padStart(3, '0')}.json`, JSON.parse(JSON.stringify(s))]);
  }
  const b = await buildBatch(actions, { chainId, settlement, batchId, minValiditySecs: 0, maxOrders: 10_000 }, new OfflineState(1_700_000_000));
  b.stateChecks = 'offline (signatures and framing only)';
  return b;
}

async function reproduce(name: string) {
  const fx = fixture(name);
  const b = await sdkBatch(fx.n, fx.nonceBase, fx.batchId, fx.chainId, fx.settlement);
  expect(b.excluded).toEqual([]);
  expect(b.batch, `${name}: packed batch`).toBe(fx.batch);
  expect(b.digest, `${name}: digest`).toBe(fx.digest);
  expect(b.digest, `${name}: proof public values`).toBe(fx.publicValues);
  expect(batchDigest(fx.chainId, fx.settlement, fx.batchId, fx.batch)).toBe(fx.digest);
  return b;
}

describe('proved batches (SP1 Groth16, settled on Solonet)', () => {
  it('b1-n10: batch, digest and the full Rust batcher output, byte for byte (incl. all 10 signatures)', async () => {
    const b = await reproduce('b1-n10');
    expect(b.orders).toBe(10);
    expect(b.schema).toBe(BATCH_INPUT_SCHEMA);
    expect(batchInputJson(b)).toBe(readFileSync(join(ROOT, 'sdk/tests/fixtures/batch-input-b1-n10.json'), 'utf8'));
  });
  it('b2-n100: batch + digest', async () => {
    const b = await reproduce('b2-n100');
    expect(b.orders).toBe(100);
    expect(b.groups.map((g) => g.firstNonce)).toEqual([6, 56]);
    const pg = parseBatch(b.batch);
    expect(pg.map((g) => [g.agentId, g.count])).toEqual([[1, 50], [2, 50]]);
  });
  it('SDK agent 4 (Rust-signed, real random key) batch settled live: rebuilt identically from its signed actions', async () => {
    const dir = join(ROOT, 'results/solonet/sdk-e2e/a4-b1-n3');
    const want = readFileSync(join(dir, 'batch-input.json'), 'utf8');
    const wantJ = JSON.parse(want);
    const acts: Submission[] = readdirSync(join(dir, 'actions')).sort().map((f) => [f, JSON.parse(readFileSync(join(dir, 'actions', f), 'utf8'))]);
    for (const [, a] of acts) verifySignedAction(a as SignedAction); // Rust signatures verify in TS
    // state as it was at batching time (fee 0.001 MON/action, lastNonce 0, ample caps/balances)
    const st: StateSource = {
      agent: async () => ({ authorized: true, lastNonce: 0n, base: 500n * 10n ** 18n, quote: 1000n * 10n ** 18n,
        capBaseIn: 2000n * 10n ** 18n, capQuoteIn: 4000n * 10n ** 18n, feeBalance: 5n * 10n ** 16n }),
      feeQuote: async (_id, n) => BigInt(n) * 10n ** 15n,
      now: async () => 1_792_000_000n,
    };
    const b = await buildBatch(acts, { chainId: wantJ.chainId, settlement: wantJ.settlement, batchId: wantJ.batchId }, st);
    b.stateChecks = wantJ.stateChecks;
    expect(batchInputJson(b)).toBe(want);
    const settled = json('results/solonet/sdk-e2e/a4-b1-n3/groth16-batch-fixture.json');
    expect(b.digest).toBe(settled.digest ?? settled.publicValues);
    expect(verifyBatch(b.chainId, b.settlement, b.batchId, b.batch, b.groups.map((g) => g.publicKey), b.groups.flatMap((g) => g.signatures))).toBe(b.digest);
  });
});
