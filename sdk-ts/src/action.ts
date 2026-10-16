/**
 * Signed actions: the packed 25-byte order, the exact 133-byte message the SP1 guest verifies, and the
 * JSON submission format accepted by the batcher (`sdk/schema/signed-action.v1.json`). Mirrors
 * `sdk/src/action.rs` byte for byte.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { AgentKey, PUBLIC_KEY_LEN, SIGNATURE_LEN, pkHash as pkHashOf, verifySignature } from './keys.js';
import { be, concat, equalBytes, hex0x, readBe, unhex, unhexN, type Hex } from './bytes.js';

export const SCHEMA_ID = 'pq-agent-batch/signed-action/v1';
export const ORDER_LEN = 25;
export const MESSAGE_LEN = 133;
export const MAX_U96 = (1n << 96n) - 1n;
export const ORDER_TAG_V2 = keccak_256(new TextEncoder().encode('EmpowerTours.AgentOrder.v2'));

/** One order. `buyBase = true` spends quote for base (flags bit0 = 1); false sells base for quote. */
export interface Order { buyBase: boolean; amountIn: bigint; minAmountOut: bigint }

/** 25-byte packed order: flags u8 | amountIn u96 | minAmountOut u96 (big-endian). */
export function encodeOrder(o: Order): Uint8Array {
  if (o.amountIn <= 0n) throw new Error('amountIn must be > 0 (contract: ZeroAmount)');
  if (o.amountIn > MAX_U96 || o.minAmountOut > MAX_U96 || o.minAmountOut < 0n) throw new Error('amounts must fit in uint96');
  return concat(Uint8Array.of(o.buyBase ? 1 : 0), be(o.amountIn, 12), be(o.minAmountOut, 12));
}

export function decodeOrder(b: Uint8Array): Order {
  if (b.length !== ORDER_LEN || b[0] > 1) throw new Error('bad order encoding');
  return { buyBase: b[0] === 1, amountIn: readBe(b.subarray(1, 13)), minAmountOut: readBe(b.subarray(13, 25)) };
}

/** Everything bound into one signature. */
export interface ActionParams {
  chainId: bigint | number;
  settlement: Hex | string; // 20-byte address
  agentId: number;
  nonce: bigint | number;
  expiry: number; // unix seconds, u32
  modelHash: Hex | string | Uint8Array; // 32 bytes
  order: Order;
}

/**
 * The exact signed message (133 B):
 * ORDER_TAG_V2 | chainId u64 | settlement (20) | agentId u32 | nonce u64 | expiry u32 | modelHash | order (25).
 * (pkHash is bound by the batch header + registry, not by the message.)
 */
export function actionMessage(p: ActionParams): Uint8Array {
  const mh = typeof p.modelHash === 'string' ? unhexN(p.modelHash, 32, 'modelHash') : p.modelHash;
  if (mh.length !== 32) throw new Error('modelHash must be 32 bytes');
  if (!Number.isInteger(p.agentId) || p.agentId < 0) throw new Error('agentId must be a u32');
  if (!Number.isInteger(p.expiry) || p.expiry < 0) throw new Error('expiry must be a u32');
  return concat(ORDER_TAG_V2, be(p.chainId, 8), unhexN(p.settlement, 20, 'settlement'), be(p.agentId, 4),
    be(p.nonce, 8), be(p.expiry, 4), mh, encodeOrder(p.order));
}

/** JSON submission (schema `pq-agent-batch/signed-action/v1`). Field order matches the Rust SDK output. */
export interface SignedAction {
  schema: typeof SCHEMA_ID | string;
  chainId: number;
  settlement: string;
  agentId: number;
  nonce: number;
  expiry: number;
  modelHash: string;
  pkHash: string;
  order: { side: 'buy' | 'sell' | string; amountIn: string; minAmountOut: string };
  orderBytes: string;
  message: string;
  publicKey: string;
  signature: string;
}

function lowerAddr(a: string): string { return hex0x(unhexN(a, 20, 'settlement')); }

/** Sign one action with an agent key (deterministic FIPS 204 by default, like the Rust SDK). */
export function signAction(p: ActionParams, key: AgentKey, opts: { randomized?: boolean } = {}): SignedAction {
  const msg = actionMessage(p);
  const sig = opts.randomized ? key.signRandomized(msg) : key.sign(msg);
  const nonce = BigInt(p.nonce); const chainId = BigInt(p.chainId);
  if (nonce > BigInt(Number.MAX_SAFE_INTEGER) || chainId > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('nonce/chainId above 2^53 cannot be represented in the v1 JSON number fields');
  }
  return {
    schema: SCHEMA_ID,
    chainId: Number(chainId),
    settlement: lowerAddr(String(p.settlement)),
    agentId: p.agentId,
    nonce: Number(nonce),
    expiry: p.expiry,
    modelHash: typeof p.modelHash === 'string' ? hex0x(unhexN(p.modelHash, 32)) : hex0x(p.modelHash),
    pkHash: key.pkHashHex,
    order: { side: p.order.buyBase ? 'buy' : 'sell', amountIn: p.order.amountIn.toString(), minAmountOut: p.order.minAmountOut.toString() },
    orderBytes: hex0x(encodeOrder(p.order)),
    message: hex0x(msg),
    publicKey: hex0x(key.publicKey),
    signature: hex0x(sig),
  };
}

const DEC = /^(0|[1-9][0-9]*)$/;

export function actionParams(a: SignedAction): ActionParams {
  const side = a.order?.side;
  if (side !== 'buy' && side !== 'sell') throw new Error(`side must be buy|sell, got ${side}`);
  if (!DEC.test(a.order.amountIn)) throw new Error('amountIn: not a decimal integer');
  if (!DEC.test(a.order.minAmountOut)) throw new Error('minAmountOut: not a decimal integer');
  for (const k of ['chainId', 'agentId', 'nonce', 'expiry'] as const) {
    if (!Number.isSafeInteger(a[k]) || a[k] < 0) throw new Error(`${k} must be a non-negative integer`);
  }
  if (a.agentId > 0xffffffff || a.expiry > 0xffffffff) throw new Error('agentId/expiry must fit u32');
  return {
    chainId: a.chainId, settlement: hex0x(unhexN(a.settlement, 20, 'settlement')), agentId: a.agentId, nonce: a.nonce,
    expiry: a.expiry, modelHash: hex0x(unhexN(a.modelHash, 32, 'modelHash')),
    order: { buyBase: side === 'buy', amountIn: BigInt(a.order.amountIn), minAmountOut: BigInt(a.order.minAmountOut) },
  };
}

const FIELDS = ['schema', 'chainId', 'settlement', 'agentId', 'nonce', 'expiry', 'modelHash', 'pkHash', 'order', 'orderBytes', 'message', 'publicKey', 'signature'];

/**
 * Full offline check, identical to Rust `SignedAction::verify`: schema, no unknown fields, field
 * consistency, sha256(publicKey) == pkHash, ML-DSA-65 signature over the re-derived message.
 * Throws with a reason; returns the parsed params on success.
 */
export function verifySignedAction(a: SignedAction): ActionParams {
  if (typeof a !== 'object' || a === null) throw new Error('not an object');
  const extra = Object.keys(a).filter((k) => !FIELDS.includes(k));
  if (extra.length) throw new Error(`unknown field(s): ${extra.join(', ')}`);
  const missing = FIELDS.filter((k) => !(k in a));
  if (missing.length) throw new Error(`missing field(s): ${missing.join(', ')}`);
  if (a.schema !== SCHEMA_ID) throw new Error(`unknown schema ${a.schema}`);
  if (!(a.agentId > 0)) throw new Error('agentId must be > 0');
  const p = actionParams(a);
  const pk = unhex(a.publicKey);
  if (pk.length !== PUBLIC_KEY_LEN) throw new Error(`publicKey must be ${PUBLIC_KEY_LEN} bytes`);
  const pkh = unhexN(a.pkHash, 32, 'pkHash');
  if (!equalBytes(pkHashOf(pk), pkh)) throw new Error('pkHash != sha256(publicKey)');
  if (!equalBytes(unhex(a.orderBytes), encodeOrder(p.order))) throw new Error('orderBytes inconsistent with order');
  const msg = actionMessage(p);
  if (!equalBytes(unhex(a.message), msg)) throw new Error('message inconsistent with fields');
  const sig = unhex(a.signature);
  if (sig.length !== SIGNATURE_LEN) throw new Error(`signature must be ${SIGNATURE_LEN} bytes`);
  if (!verifySignature(pk, msg, sig)) throw new Error('ML-DSA-65 signature does not verify');
  return p;
}

/** Non-throwing variant for tools/UIs. */
export function checkSignedAction(a: SignedAction): { valid: true; params: ActionParams } | { valid: false; reason: string } {
  try { return { valid: true, params: verifySignedAction(a) }; }
  catch (e) { return { valid: false, reason: (e as Error).message }; }
}
