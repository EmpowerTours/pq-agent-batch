/**
 * Amount parsing identical to the Rust CLI (`sdk/src/config.rs`): plain integer = base units (wei);
 * `<decimal>mon` / `<decimal>ether` / `<decimal>e<N>` = × 10^N; `<decimal>gwei` = × 10^9.
 * Examples: `0.05mon`, `2.5ether`, `1e17`, `1000`.
 */
export function parseAmount(s: string | number | bigint): bigint {
  if (typeof s === 'bigint') { if (s < 0n) throw new Error('negative amount'); return s; }
  if (typeof s === 'number') {
    if (!Number.isSafeInteger(s) || s < 0) throw new Error(`amount ${s}: pass a string (e.g. "0.05mon") or bigint`);
    return BigInt(s);
  }
  const t = s.trim().toLowerCase().replace(/_/g, '');
  let num: string; let dec: number;
  const unit = t.match(/^(.*?)(mon|ether)$/);
  if (unit) { num = unit[1].trim(); dec = 18; }
  else if (t.endsWith('gwei')) { num = t.slice(0, -4).trim(); dec = 9; }
  else if (t.includes('e')) {
    const [n, e] = t.split('e', 2);
    const ev = /^\d+$/.test(e) ? Number(e) : NaN;
    if (!(ev <= 36)) throw new Error(`bad exponent in ${JSON.stringify(s)}`);
    num = n.trim(); dec = ev;
  } else { num = t; dec = 0; }
  const [i, f = ''] = num.split('.', 2);
  if (i === '' && f === '') throw new Error(`bad amount ${JSON.stringify(s)}`);
  if (f.length > dec) throw new Error(`amount ${JSON.stringify(s)} has more than ${dec} decimals`);
  if (!/^\d*$/.test(i) || !/^\d*$/.test(f)) throw new Error(`bad amount ${JSON.stringify(s)}`);
  const digits = (i + f + '0'.repeat(dec - f.length)).replace(/^0+/, '');
  return digits === '' ? 0n : BigInt(digits);
}

/** `1234500000000000000n` -> `"1.2345"` (18 decimals, trailing zeros trimmed). */
export function fmtUnits(v: bigint, decimals = 18): string {
  const d = 10n ** BigInt(decimals);
  const i = v / d; const f = v % d;
  if (f === 0n) return i.toString();
  return `${i}.${f.toString().padStart(decimals, '0').replace(/0+$/, '')}`;
}
