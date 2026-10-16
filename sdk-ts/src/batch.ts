/**
 * Packed batch format, digest, and the reference batcher (port of `sdk/src/batcher.rs`).
 *
 *   batch  = group*,  group = header (82 B) | count × order (25 B)
 *   header = agentId u32 | count u16 | firstNonce u64 | expiry u32 | pkHash (32) | modelHash (32)
 *   digest = keccak256(abi.encode(BATCH_TAG_V2, chainId, settlement, batchId, keccak256(batch)))
 *          == BatchSettlementV2.batchDigest(batchId, batch) == the SP1 proof's public values
 *
 * The batcher applies the contract's settle-time acceptance rules (signature, chain/settlement, expiry,
 * nonce > lastNonce and contiguous, registry authorization, per-batch caps, trading balances, prepaid
 * fee balance) so a batch it emits does not revert for those reasons. Pool slippage is NOT simulated.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { be, concat, equalBytes, hex0x, readBe, unhex, unhexN, type Hex } from './bytes.js';
import { ORDER_LEN, ORDER_TAG_V2, actionMessage, decodeOrder, encodeOrder, verifySignedAction, type SignedAction } from './action.js';
import { pkHash as pkHashOf, verifySignature } from './keys.js';
import type { PqClient } from './chain.js';

export const BATCH_INPUT_SCHEMA = 'pq-agent-batch/batch-input/v1';
export const HEADER_LEN = 82;
export const BATCH_TAG_V2 = keccak_256(new TextEncoder().encode('EmpowerTours.AgentBatch.v2'));

export function batchDigest(chainId: bigint | number, settlement: string, batchId: bigint | number, batch: Uint8Array | string): Hex {
  const b = typeof batch === 'string' ? unhex(batch) : batch;
  return hex0x(keccak_256(concat(BATCH_TAG_V2, be(chainId, 32), concat(new Uint8Array(12), unhexN(settlement, 20, 'settlement')),
    be(batchId, 32), keccak_256(b))));
}

export interface ParsedGroup {
  agentId: number; count: number; firstNonce: number; expiry: number; pkHash: Hex; modelHash: Hex;
  orders: { side: 'buy' | 'sell'; amountIn: string; minAmountOut: string }[];
  /** byte offset of the first order */
  ordersAt: number;
}

/** Decode a packed batch (throws on malformed framing, like the contract's Malformed(offset)). */
export function parseBatch(batch: Uint8Array | string): ParsedGroup[] {
  const b = typeof batch === 'string' ? unhex(batch) : batch;
  const out: ParsedGroup[] = [];
  let o = 0;
  while (o < b.length) {
    if (o + HEADER_LEN > b.length) throw new Error(`malformed batch: truncated header at offset ${o}`);
    const h = b.subarray(o, o + HEADER_LEN);
    const count = Number(readBe(h.subarray(4, 6)));
    if (count === 0) throw new Error(`malformed batch: empty group at offset ${o}`);
    const ordersAt = o + HEADER_LEN;
    const end = ordersAt + count * ORDER_LEN;
    if (end > b.length) throw new Error(`malformed batch: truncated orders at offset ${ordersAt}`);
    const orders = [];
    for (let j = 0; j < count; j++) {
      const ord = decodeOrder(b.subarray(ordersAt + j * ORDER_LEN, ordersAt + (j + 1) * ORDER_LEN));
      orders.push({ side: ord.buyBase ? 'buy' as const : 'sell' as const, amountIn: ord.amountIn.toString(), minAmountOut: ord.minAmountOut.toString() });
    }
    out.push({
      agentId: Number(readBe(h.subarray(0, 4))), count, firstNonce: Number(readBe(h.subarray(6, 14))), expiry: Number(readBe(h.subarray(14, 18))),
      pkHash: hex0x(h.subarray(18, 50)), modelHash: hex0x(h.subarray(50, 82)), orders, ordersAt,
    });
    o = end;
  }
  if (out.length === 0) throw new Error('empty batch');
  return out;
}

/**
 * The guest's check: every group's sha256(pk) == pkHash and every order's ML-DSA-65 signature verifies
 * over its 133-byte message. `publicKeys` one per group, `signatures` one per order (batch order).
 * Returns the digest; throws on the first failure.
 */
export function verifyBatch(chainId: number, settlement: string, batchId: number | bigint, batch: Uint8Array | string,
  publicKeys: (Uint8Array | string)[], signatures: (Uint8Array | string)[]): Hex {
  const groups = parseBatch(batch);
  if (groups.length !== publicKeys.length) throw new Error(`need ${groups.length} public keys, got ${publicKeys.length}`);
  const total = groups.reduce((a, g) => a + g.count, 0);
  if (signatures.length !== total) throw new Error(`need ${total} signatures, got ${signatures.length}`);
  let k = 0;
  groups.forEach((g, gi) => {
    const pk = typeof publicKeys[gi] === 'string' ? unhex(publicKeys[gi] as string) : publicKeys[gi] as Uint8Array;
    if (!equalBytes(pkHashOf(pk), unhex(g.pkHash))) throw new Error(`group ${gi}: sha256(publicKey) != pkHash`);
    g.orders.forEach((o, j) => {
      const msg = actionMessage({ chainId, settlement, agentId: g.agentId, nonce: BigInt(g.firstNonce) + BigInt(j), expiry: g.expiry,
        modelHash: g.modelHash, order: { buyBase: o.side === 'buy', amountIn: BigInt(o.amountIn), minAmountOut: BigInt(o.minAmountOut) } });
      const s = signatures[k++];
      if (!verifySignature(pk, msg, typeof s === 'string' ? unhex(s) : s)) throw new Error(`group ${gi} order ${j}: bad signature`);
    });
  });
  return batchDigest(chainId, settlement, batchId, batch);
}

// ---------------------------------------------------------------- batcher

export interface AgentOnChain {
  authorized: boolean; lastNonce: bigint; base: bigint; quote: bigint; capBaseIn: bigint; capQuoteIn: bigint; feeBalance: bigint;
}

export interface StateSource {
  agent(id: number, pkHash: Hex): Promise<AgentOnChain>;
  /** settlement.feeQuote(id, actions) */
  feeQuote(id: number, actions: number): Promise<bigint>;
  /** chain time, unix seconds */
  now(): Promise<bigint>;
}

const BIG = (1n << 255n);
/** No chain access: everyone authorized, lastNonce 0, unlimited caps/balances, zero fees. */
export class OfflineState implements StateSource {
  constructor(private readonly t: bigint | number) {}
  async agent(): Promise<AgentOnChain> { return { authorized: true, lastNonce: 0n, base: BIG, quote: BIG, capBaseIn: BIG, capQuoteIn: BIG, feeBalance: BIG }; }
  async feeQuote(): Promise<bigint> { return 0n; }
  async now(): Promise<bigint> { return BigInt(this.t); }
}

/** Live state from the settlement contract and its registry. */
export class OnChainState implements StateSource {
  constructor(private readonly c: PqClient) {}
  async agent(id: number, pkHash: Hex): Promise<AgentOnChain> {
    const s = await this.c.agentStatus(id, pkHash);
    return { authorized: !!s.authorized, lastNonce: BigInt(s.lastNonce), base: BigInt(s.tradingBase), quote: BigInt(s.tradingQuote),
      capBaseIn: BigInt(s.capBaseIn), capQuoteIn: BigInt(s.capQuoteIn), feeBalance: BigInt(s.feeBalance) };
  }
  feeQuote(id: number, actions: number) { return this.c.feeQuote(id, actions); }
  now() { return this.c.now(); }
}

export interface GroupInput { agentId: number; firstNonce: number; count: number; pkHash: string; feeQuote: string; publicKey: string; signatures: string[] }
export interface Excluded { source: string; agentId?: number; nonce?: number; reason: string }
/** Prover input (`zk-batch` host `--input`). Same JSON as the Rust batcher. */
export interface BatchInput {
  schema: string; chainId: number; settlement: string; batchId: number; orders: number; stateChecks: string;
  batch: Hex; digest: Hex; groups: GroupInput[]; excluded: Excluded[];
}

export interface BatchOptions {
  chainId: number; settlement: string; batchId: number;
  /** drop actions expiring sooner than now + this (time to prove and land) */
  minValiditySecs?: number;
  /** stop adding orders beyond this many (default 1000) */
  maxOrders?: number;
}

/** A submission: a parsed SignedAction or the reason it could not be parsed. */
export type Submission = [source: string, action: SignedAction | Error];

/** Load every `*.json` in `dir` (sorted by name) as a signed action. */
export async function loadActionDir(dir: string): Promise<Submission[]> {
  const names = (await fs.readdir(dir)).filter((n) => n.endsWith('.json')).sort();
  return Promise.all(names.map(async (n): Promise<Submission> => {
    try { return [n, JSON.parse(await fs.readFile(join(dir, n), 'utf8')) as SignedAction]; }
    catch (e) { return [n, e as Error]; }
  }));
}

interface Cand { src: string; a: SignedAction; order: Uint8Array; buy: boolean; amount: bigint }

export async function buildBatch(actions: Submission[], opt: BatchOptions, state: StateSource): Promise<BatchInput> {
  const now = await state.now();
  const minValidity = BigInt(opt.minValiditySecs ?? 0);
  const maxOrders = opt.maxOrders ?? 1000;
  const settlement = hex0x(unhexN(opt.settlement, 20, 'settlement'));
  const excluded: Excluded[] = [];
  const ex = (src: string, a: SignedAction | undefined, reason: string) =>
    excluded.push(a ? { source: src, agentId: a.agentId, nonce: a.nonce, reason } : { source: src, reason });
  const byAgent = new Map<number, Cand[]>();
  for (const [src, r] of actions) {
    if (r instanceof Error) { ex(src, undefined, `unparseable: ${r.message}`); continue; }
    const a = r;
    let p;
    try { p = verifySignedAction(a); } catch (e) { ex(src, a, `invalid: ${(e as Error).message}`); continue; }
    if (BigInt(p.chainId) !== BigInt(opt.chainId) || String(p.settlement) !== settlement) { ex(src, a, 'signed for a different chainId/settlement'); continue; }
    if (BigInt(p.expiry) < now + minValidity) { ex(src, a, `expires at ${p.expiry} (< now ${now} + ${minValidity}s)`); continue; }
    const list = byAgent.get(p.agentId) ?? [];
    list.push({ src, a, order: encodeOrder(p.order), buy: p.order.buyBase, amount: p.order.amountIn });
    byAgent.set(p.agentId, list);
  }

  const parts: Uint8Array[] = []; const groups: GroupInput[] = []; const pks: string[] = []; const sigs: string[] = [];
  let total = 0;
  for (const id of [...byAgent.keys()].sort((x, y) => x - y)) {
    const cs = byAgent.get(id)!.sort((x, y) => x.a.nonce - y.a.nonce || (x.src < y.src ? -1 : x.src > y.src ? 1 : 0));
    const uniq: Cand[] = [];
    for (const c of cs) {
      if (uniq.length && uniq[uniq.length - 1].a.nonce === c.a.nonce) ex(c.src, c.a, 'duplicate nonce (kept the first file)');
      else uniq.push(c);
    }
    const pkh = hex0x(unhexN(uniq[0].a.pkHash, 32));
    const st = await state.agent(id, pkh);
    let run: Cand[] = [];
    for (const c of uniq) {
      if (BigInt(c.a.nonce) <= st.lastNonce) { ex(c.src, c.a, `nonce <= on-chain lastNonce ${st.lastNonce}`); continue; }
      const l = run[run.length - 1];
      const fits = !l || (c.a.nonce === l.a.nonce + 1 && c.a.expiry === l.a.expiry && c.a.modelHash === l.a.modelHash
        && c.a.pkHash === l.a.pkHash && run.length < 0xffff);
      if (fits && total + run.length < maxOrders) run.push(c);
      else ex(c.src, c.a, "not contiguous with this batch's run (gap / different expiry, model or key / size limit); deferred");
    }
    if (!run.length) continue;
    const rpkh = hex0x(unhexN(run[0].a.pkHash, 32));
    const auth = rpkh === pkh ? st.authorized : (await state.agent(id, rpkh)).authorized;
    if (!auth) { for (const c of run) ex(c.src, c.a, 'registry: agent not active / killed / key not authorized'); continue; }
    let fee = 0n;
    while (run.length) {
      let b = 0n; let q = 0n;
      for (const c of run) { if (c.buy) q += c.amount; else b += c.amount; }
      fee = await state.feeQuote(id, run.length);
      const why = b > st.capBaseIn || q > st.capQuoteIn ? 'per-batch cap exceeded'
        : b > st.base || q > st.quote ? 'insufficient trading balance on the settlement'
        : fee > st.feeBalance ? 'insufficient prepaid fee balance (feeQuote > feeAccount.balance)' : undefined;
      if (!why) break;
      const c = run.pop()!; ex(c.src, c.a, why);
    }
    if (!run.length) continue;
    const f = run[0].a;
    parts.push(be(id, 4), be(run.length, 2), be(f.nonce, 8), be(f.expiry, 4), unhexN(rpkh, 32), unhexN(f.modelHash, 32));
    for (const c of run) parts.push(c.order);
    pks.push(f.publicKey);
    for (const c of run) sigs.push(c.a.signature);
    total += run.length;
    groups.push({ agentId: id, firstNonce: f.nonce, count: run.length, pkHash: f.pkHash, feeQuote: fee.toString(), publicKey: f.publicKey,
      signatures: run.map((c) => c.a.signature) });
  }
  const batch = concat(...parts);
  // same check the guest performs; must hold for anything we emit
  const digest = batch.length === 0 ? hex0x(new Uint8Array(32)) : verifyBatch(opt.chainId, settlement, opt.batchId, batch, pks, sigs);
  return { schema: BATCH_INPUT_SCHEMA, chainId: opt.chainId, settlement, batchId: opt.batchId, orders: total, stateChecks: '',
    batch: hex0x(batch), digest, groups, excluded };
}

/** Pretty JSON exactly as the Rust CLI writes it (2-space indent + trailing newline). */
export function batchInputJson(b: BatchInput): string {
  return JSON.stringify(b, null, 2) + '\n';
}
