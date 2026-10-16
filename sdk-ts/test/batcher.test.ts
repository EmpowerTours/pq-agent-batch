import { describe, expect, it } from 'vitest';
import { AgentKey, OfflineState, buildBatch, signAction, type AgentOnChain, type StateSource, type Submission } from '../src/index.js';

const BIG = 1n << 200n;
function fake(o: { last: bigint; feePer: bigint; feeBal: bigint; auth: boolean; cap: bigint }): StateSource {
  return {
    agent: async (): Promise<AgentOnChain> => ({ authorized: o.auth, lastNonce: o.last, base: BIG, quote: BIG, capBaseIn: o.cap, capQuoteIn: o.cap, feeBalance: o.feeBal }),
    feeQuote: async (_id, n) => BigInt(n) * o.feePer,
    now: async () => 1000n,
  };
}

describe('batcher rules (port of sdk/tests/golden.rs::batcher_rules)', () => {
  const k = AgentKey.testKey(1);
  const S9 = '0x' + '09'.repeat(20);
  const mk = (nonce: number, expiry: number, amt: bigint, settlement = S9): Submission => [`${nonce}-${expiry}.json`, signAction({
    chainId: 1, settlement, agentId: 5, nonce, expiry, modelHash: '0x' + '01'.repeat(32), order: { buyBase: false, amountIn: amt, minAmountOut: 0n } }, k)];
  const opt = { chainId: 1, settlement: S9, batchId: 3, minValiditySecs: 60, maxOrders: 100 };
  const set = () => [mk(2, 5000, 10n), mk(3, 5000, 10n), mk(4, 5000, 10n), mk(6, 5000, 10n), mk(5, 9000, 10n), mk(7, 1030, 10n)];

  it('stale nonce, expiry mismatch, gap, too-soon expiry', async () => {
    const b = await buildBatch(set(), opt, fake({ last: 2n, feePer: 1n, feeBal: 100n, auth: true, cap: 1000n }));
    expect([b.orders, b.groups[0].firstNonce]).toEqual([2, 3]);
    expect(b.excluded.length).toBe(4);
  });
  it('fee balance trims the run', async () => {
    const b = await buildBatch(set(), opt, fake({ last: 2n, feePer: 7n, feeBal: 10n, auth: true, cap: 1000n }));
    expect(b.orders).toBe(1);
    expect(b.excluded.some((e) => e.reason.includes('fee balance'))).toBe(true);
  });
  it('cap trims the run', async () => {
    const b = await buildBatch(set(), opt, fake({ last: 2n, feePer: 0n, feeBal: 0n, auth: true, cap: 15n }));
    expect(b.orders).toBe(1);
  });
  it('unauthorized agent -> nothing', async () => {
    const b = await buildBatch(set(), opt, fake({ last: 2n, feePer: 0n, feeBal: 0n, auth: false, cap: 1000n }));
    expect(b.orders).toBe(0);
    expect(b.digest).toBe('0x' + '00'.repeat(32));
  });
  it('forged signature and wrong settlement rejected; unparseable reported', async () => {
    const forged = mk(3, 5000, 10n); (forged[1] as any).order.amountIn = '11';
    const wrong = mk(3, 5000, 1n, '0x' + '08'.repeat(20));
    const b = await buildBatch([['f.json', forged[1]], ['w.json', wrong[1]], ['x.json', new Error('Unexpected token')]], opt, new OfflineState(0));
    expect(b.orders).toBe(0);
    expect(b.excluded.map((e) => e.reason.split(':')[0])).toEqual(['invalid', 'signed for a different chainId/settlement', 'unparseable']);
  });
});
