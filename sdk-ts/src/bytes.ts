/** Hex / big-endian helpers shared by the SDK (no secrets ever pass through logging here). */

export type Hex = `0x${string}`;

export function hex0x(b: Uint8Array): Hex {
  return `0x${Buffer.from(b).toString('hex')}` as Hex;
}

export function unhex(s: string): Uint8Array {
  const t = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  if (t.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(t)) throw new Error(`bad hex: ${s.slice(0, 20)}…`);
  return new Uint8Array(Buffer.from(t, 'hex'));
}

export function unhexN(s: string, n: number, what = 'value'): Uint8Array {
  const b = unhex(s);
  if (b.length !== n) throw new Error(`${what}: expected ${n} bytes, got ${b.length}`);
  return b;
}

/** Unsigned big-endian encoding of `v` into exactly `len` bytes (throws on overflow). */
export function be(v: bigint | number, len: number): Uint8Array {
  let x = BigInt(v);
  if (x < 0n) throw new Error('negative');
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  if (x !== 0n) throw new Error(`value does not fit in ${len} bytes`);
  return out;
}

export function readBe(b: Uint8Array): bigint {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
