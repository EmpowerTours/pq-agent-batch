import { describe, expect, it } from 'vitest';
import { copyFileSync, chmodSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Agent, AgentKey, loadKey, saveKey, ensurePrivateDir, parseAmount, fmtUnits } from '../src/index.js';

const FX = join(import.meta.dirname, 'fixtures', 'rust-keystore');
const FX_PASS = 'rust keystore fixture (TEST key 1, public)';

describe('keystore (Rust-compatible key.json)', () => {
  it('decrypts a key.json written by the Rust CLI (Argon2id + ChaCha20-Poly1305)', async () => {
    const d = mkdtempSync(join(tmpdir(), 'pqks-'));
    copyFileSync(join(FX, 'key.TEST-KEY-1.json'), join(d, 'key.json')); chmodSync(join(d, 'key.json'), 0o600);
    copyFileSync(join(FX, 'config.json'), join(d, 'config.json'));
    const k = await loadKey(join(d, 'key.json'), FX_PASS);
    expect(k.pkHashHex).toBe(AgentKey.testKey(1).pkHashHex);
    await expect(loadKey(join(d, 'key.json'), 'wrong')).rejects.toThrow(/wrong PQAGENT_PASSPHRASE/);
    await expect(loadKey(join(d, 'key.json'))).rejects.toThrow(/encrypted/);
    // the whole Rust keystore dir opens as an Agent and signs
    const a = await Agent.open(d, { passphrase: FX_PASS });
    const { action } = await a.sign({ buyBase: true, amountIn: 1n, minAmountOut: 0n }, { nonce: 1, expiry: 2_000_000_000 });
    expect(action.pkHash).toBe(k.pkHashHex);
    expect(action.agentId).toBe(1);
  });
  it('writes 0600 files in a 0700 dir, encrypts, and refuses world-readable keys', async () => {
    const d = join(mkdtempSync(join(tmpdir(), 'pqks-')), 'ks');
    await ensurePrivateDir(d);
    const k = AgentKey.generate();
    await saveKey(join(d, 'plain.json'), k);
    await saveKey(join(d, 'enc.json'), k, 'correct horse');
    expect(statSync(d).mode & 0o777).toBe(0o700);
    expect(statSync(join(d, 'plain.json')).mode & 0o777).toBe(0o600);
    expect(statSync(join(d, 'enc.json')).mode & 0o777).toBe(0o600);
    expect((await loadKey(join(d, 'plain.json'))).pkHashHex).toBe(k.pkHashHex);
    expect((await loadKey(join(d, 'enc.json'), 'correct horse')).pkHashHex).toBe(k.pkHashHex);
    expect(JSON.parse(readFileSync(join(d, 'enc.json'), 'utf8')).seed).toBeUndefined();
    chmodSync(join(d, 'plain.json'), 0o644);
    await expect(loadKey(join(d, 'plain.json'))).rejects.toThrow(/group\/others/);
  });
  it('Agent.init writes the same files as `pqagent init` and refuses to overwrite', async () => {
    const d = join(mkdtempSync(join(tmpdir(), 'pqag-')), '.pqagent');
    const a = await Agent.init(d, { chainId: 20143, settlement: '0x0e1AD57BFb7E25656dE899571BE624559d871D10', model: 'fixture model',
      agentId: 1, testSeed: 1, passphrase: 'p' });
    const rust = JSON.parse(readFileSync(join(FX, 'config.json'), 'utf8'));
    const ts = JSON.parse(readFileSync(join(d, 'config.json'), 'utf8'));
    expect(Object.keys(ts)).toEqual(Object.keys(rust));
    expect(ts).toEqual({ ...rust, keyEncrypted: true });
    expect(readFileSync(join(d, '.gitignore'), 'utf8')).toContain('*');
    expect(readFileSync(join(d, 'pubkey.hex'), 'utf8').trim().length).toBe(3904);
    await expect(Agent.init(d, { chainId: 1, settlement: '0x' + '00'.repeat(20), model: 'x' })).rejects.toThrow(/already exists/);
    expect(a.defaultExpiry(1000, 3600)).toBe(7200);
  });
});

describe('amounts (same grammar as the Rust CLI)', () => {
  it('parses and formats', () => {
    expect(parseAmount('1000')).toBe(1000n);
    expect(parseAmount('0.05mon')).toBe(50_000_000_000_000_000n);
    expect(parseAmount('2.5ether')).toBe(2_500_000_000_000_000_000n);
    expect(parseAmount('3gwei')).toBe(3_000_000_000n);
    expect(parseAmount('1_000e18')).toBe(1000n * 10n ** 18n);
    expect(() => parseAmount('1.5')).toThrow();
    expect(parseAmount('1e17')).toBe(10n ** 17n);
    expect(parseAmount('2.5e6')).toBe(2_500_000n);
    expect(() => parseAmount('1.25e1')).toThrow();
    expect(() => parseAmount('abc')).toThrow();
    expect(fmtUnits(1_234_500_000_000_000_000n)).toBe('1.2345');
    expect(fmtUnits(5n * 10n ** 18n)).toBe('5');
  });
});
