/**
 * Cross-implementation checks against the Rust `pqagent` binary (set PQAGENT_BIN; CI builds it):
 *  - signatures from a fresh random TS key are accepted by `pqagent verify`
 *  - `pqagent batch --offline` over TS-signed actions == the TS batcher, byte for byte
 *  - a TS-written encrypted keystore is loaded and used by `pqagent sign`, and vice versa the result verifies in TS
 */
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Agent, AgentKey, OfflineState, batchInputJson, buildBatch, loadActionDir, signAction, verifySignedAction } from '../src/index.js';

const BIN = process.env.PQAGENT_BIN;
const S = '0x0e1ad57bfb7e25656de899571be624559d871d10';

describe.skipIf(!BIN)('cross-verification with the Rust pqagent CLI', () => {
  it('Rust verifies TS signatures; Rust and TS batchers agree byte for byte', async () => {
    const d = mkdtempSync(join(tmpdir(), 'pqx-'));
    const acts = join(d, 'actions'); mkdirSync(acts);
    const k1 = AgentKey.generate(); const k2 = AgentKey.generate();
    let n = 0;
    for (const [k, id] of [[k1, 11], [k2, 12]] as const) {
      for (let i = 1; i <= 4; i++) {
        const s = signAction({ chainId: 20143, settlement: S, agentId: id, nonce: i, expiry: 4_000_000_000, modelHash: '0x' + '5a'.repeat(32),
          order: { buyBase: i % 2 === 0, amountIn: BigInt(i) * 10n ** 18n, minAmountOut: 1n } }, k, { randomized: id === 12 });
        writeFileSync(join(acts, `${id}-${i}.json`), JSON.stringify(s, null, 2) + '\n'); n++;
      }
    }
    const out = execFileSync(BIN!, ['--json', 'verify', join(acts, '11-2.json')], { encoding: 'utf8' });
    expect(JSON.parse(out).valid).toBe(true);
    const rustOut = join(d, 'rust-batch.json');
    execFileSync(BIN!, ['--dir', join(d, 'none'), '--json', 'batch', '--offline', '--actions', acts, '--batch-id', '9', '--chain-id', '20143',
      '--settlement', S, '--out', rustOut], { encoding: 'utf8' });
    const ts = await buildBatch(await loadActionDir(acts), { chainId: 20143, settlement: S, batchId: 9 }, new OfflineState(Math.floor(Date.now() / 1000)));
    ts.stateChecks = 'offline (signatures and framing only)';
    expect(ts.orders).toBe(n);
    expect(batchInputJson(ts)).toBe(readFileSync(rustOut, 'utf8'));
  });

  it('keystores are interchangeable (TS init -> Rust sign -> TS verify)', async () => {
    const d = join(mkdtempSync(join(tmpdir(), 'pqx-')), '.pqagent');
    const a = await Agent.init(d, { chainId: 20143, settlement: S, model: 'xmodel', agentId: 21, passphrase: 'ts pass' });
    const out = execFileSync(BIN!, ['--dir', d, 'sign', '--sell', '--amount', '3e18', '--min-out', '1', '--nonce', '5', '--expiry', '4000000000'],
      { encoding: 'utf8', env: { ...process.env, PQAGENT_PASSPHRASE: 'ts pass' } });
    const s = JSON.parse(out);
    expect(s.pkHash).toBe(a.config.pkHash);
    verifySignedAction(s);
    // deterministic: TS signs the same bytes
    const again = await (await Agent.open(d, { passphrase: 'ts pass' })).sign({ buyBase: false, amountIn: 3n * 10n ** 18n, minAmountOut: 1n }, { nonce: 5, expiry: 4_000_000_000 });
    expect(again.action).toEqual(s);
  });
});
