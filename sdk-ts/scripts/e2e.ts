/**
 * TS SDK end-to-end against a live deployment (Monad Solonet, or a throwaway anvil in CI):
 *   init (encrypted keystore) -> register -> fund -> faucet + deposit -> alert -> balance -> sign x3 (+gap)
 *   -> status -> on-chain batcher -> contract batchDigest == SDK digest [-> Rust batcher agrees]
 *
 * env: PQAGENT_RPC, SETTLEMENT, OPERATOR_KEY_FILE (or PQAGENT_OPERATOR_KEY), [PQAGENT_BIN], [OUT_DIR], [BATCH_ID]
 * The operator key is read into memory only; it is never printed or written anywhere.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseAbi, type Address } from 'viem';
import {
  Agent, OnChainState, batchInputJson, buildBatch, fmtUnits, loadActionDir, operatorAccount, parseAmount,
} from '../src/index.js';

const rpc = process.env.PQAGENT_RPC ?? 'http://localhost:8080';
const settlement = process.env.SETTLEMENT ?? '0x0e1AD57BFb7E25656dE899571BE624559d871D10';
const keyFile = process.env.OPERATOR_KEY_FILE;
const op = operatorAccount(keyFile ? readFileSync(keyFile, 'utf8') : undefined);
const outDir = process.env.OUT_DIR ? resolve(process.env.OUT_DIR) : undefined;
const batchId = Number(process.env.BATCH_ID ?? 7);

const lines: string[] = [];
const say = (s = '') => { console.log(s); lines.push(s); };
const fail = (m: string): never => { say(`FAIL: ${m}`); throw new Error(m); };
const now = () => {
  const d = new Date();
  const local = d.toLocaleString('sv-SE', { timeZone: 'America/Mexico_City' });
  return `${local} CST (America/Mexico_City, UTC-6) = ${d.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
};

const work = mkdtempSync(join(tmpdir(), 'pqagent-ts-e2e-'));
const dir = join(work, '.pqagent');
const actions = join(work, 'actions');
process.env.PQAGENT_PASSPHRASE ??= `ts e2e ${Date.now()}`; // throwaway agent key

say(`# TS SDK (@empowertours/pqagent) end-to-end, started ${now()}`);
say(`# rpc ${rpc}  settlement ${settlement}  operator ${op.address}`);

say('\n$ Agent.init (fresh ML-DSA-65 key, encrypted keystore)');
const agent = await Agent.init(dir, { chainId: Number(await (await import('viem')).createPublicClient({ transport: (await import('viem')).http(rpc) }).getChainId()),
  settlement, rpc, model: 'ts-sdk e2e model v1' });
say(`pkHash    ${agent.config.pkHash}`);
say(`modelHash ${agent.config.modelHash}  (${agent.config.modelSource})`);
say(`dir mode ${(statSync(dir).mode & 0o777).toString(8)}  key.json mode ${(statSync(join(dir, 'key.json')).mode & 0o777).toString(8)}  encrypted ${agent.config.keyEncrypted}`);

const c = agent.client();
const info = await c.registryInfo();
say(`\n$ registryInfo: registry ${info.registry} open=${info.openRegistration} fee ${fmtUnits(BigInt(info.registrationFee))} MON bond ${fmtUnits(BigInt(info.minStake))} MON agents ${info.agentCount}`);

say('\n$ agent.prepareRegister (unsigned tx any wallet can sign)');
const utx = await agent.prepareRegister({ capBaseIn: parseAmount('2000e18'), capQuoteIn: parseAmount('4000e18') });
say(JSON.stringify({ ...utx, data: utx.data.slice(0, 74) + '…' }));

say('\n$ agent.register (local operator key)');
const reg = await agent.register(op, { capBaseIn: parseAmount('2000e18'), capQuoteIn: parseAmount('4000e18') });
say(`registered agent ${reg.agentId}  tx ${reg.txHash}  gasUsed ${reg.gasUsed}`);
say(`  paid registrationFee ${fmtUnits(BigInt(reg.registrationFee))} MON + bond ${fmtUnits(BigInt(reg.bond))} MON; caps base ${fmtUnits(BigInt(reg.capBaseIn))} quote ${fmtUnits(BigInt(reg.capQuoteIn))}`);

say('\n$ agent.fund 0.05mon');
for (const t of await agent.fund(op, parseAmount('0.05mon'))) say(`  tx ${t.txHash} gasUsed ${t.gasUsed}  ${t.description}`);

say('\n$ faucet 1000 BASE + 1000 QUOTE (MockToken), agent.depositTrading 500 / 1000');
const faucetAbi = parseAbi(['function faucet(uint256)']);
const { createWalletClient, http } = await import('viem');
const w = createWalletClient({ account: op, chain: c.chain, transport: http(rpc) });
const info2 = await c.registryInfo();
for (const tok of [info2.base, info2.quote] as Address[]) {
  const h = await w.writeContract({ address: tok, abi: faucetAbi, functionName: 'faucet', args: [parseAmount('1000e18')], chain: c.chain, account: op });
  await c.public.waitForTransactionReceipt({ hash: h });
}
for (const t of await agent.depositTrading(op, parseAmount('500e18'), parseAmount('1000e18'))) say(`  tx ${t.txHash} gasUsed ${t.gasUsed}  ${t.description}`);

say('\n$ agent.setAlert 0.01mon');
for (const t of await agent.setAlert(op, parseAmount('0.01mon'))) say(`  tx ${t.txHash} gasUsed ${t.gasUsed}  ${t.description}`);

say('\n$ agent.balance');
const bal = await agent.balance();
say(JSON.stringify(bal, null, 2));
if (bal.remainingActions !== '50') fail(`remainingActions ${bal.remainingActions}`);

say('\n$ agent.sign x3 (+ one with a nonce gap)');
for (const [buy, amt] of [[false, '10e18'], [true, '25e18'], [false, '5e18']] as const) {
  const { action, path } = await agent.sign({ buyBase: buy, amountIn: parseAmount(amt), minAmountOut: 1n }, { ttl: 2_592_000, out: actions + '/' });
  say(`signed agent ${action.agentId} nonce ${action.nonce} expiry ${action.expiry} ${action.order.side} ${action.order.amountIn} -> ${path?.replace(work + '/', '')}`);
}
await agent.sign({ buyBase: true, amountIn: parseAmount('1e18'), minAmountOut: 1n }, { nonce: 9, ttl: 2_592_000, out: actions + '/' });
say('signed nonce 9 (gap: must be deferred by the batcher)');

say('\n$ agent.status');
const st = await agent.status();
say(JSON.stringify(st, null, 2));
if (!st.authorized) fail('not authorized');
if (st.nextNonce !== 10) fail(`nextNonce ${st.nextNonce}`);

say(`\n$ buildBatch (on-chain checks) batchId ${batchId}`);
const b = await buildBatch(await loadActionDir(actions), { chainId: agent.config.chainId, settlement, batchId }, new OnChainState(c));
b.stateChecks = `on-chain via ${rpc} (registry ${(await c.registry()).toLowerCase()})`;
say(`batch ${batchId}: ${b.orders} orders in ${b.groups.length} groups, ${(b.batch.length - 2) / 2} bytes, digest ${b.digest}`);
for (const g of b.groups) say(`  agent ${g.agentId} nonces ${g.firstNonce}..${g.firstNonce + g.count - 1} feeQuote ${g.feeQuote}`);
for (const e of b.excluded) say(`  excluded ${e.source}: ${e.reason}`);
if (b.orders !== 3) fail('expected 3 orders');
if (b.groups[0].feeQuote !== '3000000000000000') fail('feeQuote');
const onchain = await c.batchDigest(batchId, b.batch);
say(`contract batchDigest(${batchId}, batch) = ${onchain}`);
if (onchain !== b.digest) fail('digest mismatch');
say('contract batchDigest == TS SDK digest: OK');

if (process.env.PQAGENT_BIN) {
  say('\n$ Rust `pqagent batch` over the same TS-signed actions (on-chain checks)');
  const rustOut = join(work, 'rust-batch-input.json');
  execFileSync(process.env.PQAGENT_BIN, ['--dir', dir, '--rpc', rpc, '--json', 'batch', '--actions', actions, '--batch-id', String(batchId), '--out', rustOut]);
  const same = readFileSync(rustOut, 'utf8') === batchInputJson(b);
  say(`Rust batch-input.json == TS batch-input.json byte for byte: ${same}`);
  if (!same) fail('Rust/TS batcher mismatch');
}

say(`\n# finished ${now()}  -- OK`);
if (outDir) {
  mkdirSync(join(outDir, 'actions'), { recursive: true });
  writeFileSync(join(outDir, 'sdk-e2e-transcript.txt'), lines.join('\n') + '\n');
  writeFileSync(join(outDir, 'batch-input.json'), batchInputJson(b));
  for (const [n, a] of await loadActionDir(actions)) writeFileSync(join(outDir, 'actions', n), JSON.stringify(a, null, 2) + '\n');
  writeFileSync(join(outDir, 'agent.json'), JSON.stringify({ agentId: reg.agentId, pkHash: agent.config.pkHash, modelHash: agent.config.modelHash,
    operator: op.address, registerTx: reg.txHash, batchId, digest: b.digest, contractDigest: onchain }, null, 2) + '\n');
}
