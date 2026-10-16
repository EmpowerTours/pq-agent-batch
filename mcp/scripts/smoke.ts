/**
 * MCP smoke test with the official MCP client over BOTH transports (stdio + streamable HTTP), against a
 * live deployment (Monad Solonet, or anvil in CI). Optionally (LOCAL_MODE=1) exercises the local-only
 * tools: a fresh keystore registers itself via prepare_register{broadcast}, funds, signs and verifies.
 *
 * env: PQAGENT_RPC, PQAGENT_CHAIN_ID, PQAGENT_SETTLEMENT, [PQAGENT_REGISTRY]
 *      SMOKE_AGENT_ID, SMOKE_PKHASH                 agent expected to be authorized
 *      [SMOKE_ACTIONS_DIR] [SMOKE_BATCH_INPUT]      signed actions / batch-input.json of that agent
 *      [LOCAL_MODE=1 + OPERATOR_KEY_FILE]           local stdio signing + broadcast
 *      [OUT_DIR]                                    write transcripts
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { spawn } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Agent } from '@empowertours/pqagent';

const CLI = resolve(import.meta.dirname, '..', 'dist', 'cli.js');
const OUT = process.env.OUT_DIR ? resolve(process.env.OUT_DIR) : undefined;
const AGENT = Number(process.env.SMOKE_AGENT_ID ?? 4);
const PKH = process.env.SMOKE_PKHASH ?? '0x7c2c8a8b98c34df4a50204357e33cdd8155a64be11ac2fcd2c7b395d13271602';
const ACTIONS = process.env.SMOKE_ACTIONS_DIR;
const BATCH = process.env.SMOKE_BATCH_INPUT;
const baseEnv: Record<string, string> = {};
for (const k of ['PATH', 'HOME', 'PQAGENT_RPC', 'PQAGENT_CHAIN_ID', 'PQAGENT_SETTLEMENT', 'PQAGENT_REGISTRY']) if (process.env[k]) baseEnv[k] = process.env[k]!;

const stamp = () => {
  const d = new Date();
  return `${d.toLocaleString('sv-SE', { timeZone: 'America/Mexico_City' })} CST (America/Mexico_City) = ${d.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
};
const short = (v: unknown): unknown => typeof v === 'string' && v.length > 180 ? `${v.slice(0, 120)}…(${v.length} chars)` :
  Array.isArray(v) ? v.map(short) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, short(x)])) : v;
function assert(c: unknown, m: string): asserts c { if (!c) throw new Error(`ASSERT: ${m}`); }

async function session(name: string, client: Client, log: string[], local = false) {
  const say = (s: string) => { log.push(s); console.log(s); };
  const call = async (tool: string, args: Record<string, unknown> = {}, expectError = false) => {
    say(`\n>>> tools/call ${tool} ${JSON.stringify(short(args))}`);
    const r: any = await client.callTool({ name: tool, arguments: args });
    const text = r.content?.[0]?.text ?? '';
    let parsed: any; try { parsed = JSON.parse(text); } catch { parsed = text; }
    say(`<<< ${r.isError ? 'ERROR ' : ''}${typeof parsed === 'string' ? parsed : JSON.stringify(short(parsed), null, 2)}`);
    assert(!!r.isError === expectError, `${tool}: isError=${r.isError}`);
    return parsed;
  };
  say(`# ${name} — ${stamp()}`);
  const info = client.getServerVersion();
  say(`server ${info?.name} ${info?.version}`);
  const { tools } = await client.listTools();
  say(`tools/list -> ${tools.length} tools: ${tools.map((t) => t.name).join(', ')}`);
  for (const t of tools) say(`  - ${t.name}${t.annotations?.readOnlyHint ? ' [read-only]' : ''}: ${t.description?.slice(0, 110)}…`);
  for (const must of ['network_info', 'agent_status', 'is_authorized', 'fee_quote', 'fee_balance', 'verify_signed_action', 'batch_digest', 'build_batch',
    'prepare_register', 'prepare_fund', 'prepare_deposit', 'prepare_set_alert']) assert(tools.some((t) => t.name === must), `missing ${must}`);
  assert(local === tools.some((t) => t.name === 'sign_action'), 'sign_action only in local mode');

  const ni = await call('network_info');
  assert(ni.chainId > 0 && ni.openRegistration !== undefined, 'network_info');
  const st = await call('agent_status', { agentId: AGENT, pkHash: PKH });
  assert(st.authorized === true && st.registered, 'agent authorized');
  const au = await call('is_authorized', { agentId: AGENT, pkHash: PKH });
  assert(au.authorized === true, 'is_authorized');
  const bad = await call('is_authorized', { agentId: AGENT, pkHash: '0x' + '11'.repeat(32) });
  assert(bad.authorized === false, 'wrong key must be unauthorized');
  const nobody = await call('is_authorized', { agentId: 999_999, pkHash: PKH });
  assert(nobody.authorized === false && /unknown/.test(nobody.reason), 'unknown agent');
  await call('fee_quote', { agentId: AGENT, actions: 3 });
  const fb = await call('fee_balance', { agentId: AGENT });
  assert(typeof fb.remainingActions === 'string', 'fee_balance');
  if (ACTIONS) {
    const f = readdirSync(ACTIONS).filter((x) => x.endsWith('.json')).sort();
    const a = JSON.parse(readFileSync(join(ACTIONS, f[0]), 'utf8'));
    const v = await call('verify_signed_action', { action: a });
    assert(v.valid === true && v.onChain, 'verify ok');
    const t = structuredClone(a); t.order.amountIn = String(BigInt(t.order.amountIn) + 1n);
    const vb = await call('verify_signed_action', { action: t, checkOnChain: false });
    assert(vb.valid === false, 'tampered action must fail');
    const bb = await call('build_batch', { actions: f.map((x) => JSON.parse(readFileSync(join(ACTIONS, x), 'utf8'))), batchId: 99, onChainChecks: false });
    assert(bb.orders >= 1, 'build_batch');
  }
  if (BATCH) {
    const bi = JSON.parse(readFileSync(BATCH, 'utf8'));
    const d = await call('batch_digest', { batchId: bi.batchId, batch: bi.batch });
    assert(d.digest === bi.digest && d.matchesContract === true, 'batch_digest == contract == batcher');
  }
  await call('batch_digest', { batchId: 1, batch: '0x00' }, true); // malformed -> tool error
  const pr = await call('prepare_register', { pkHash: '0x' + 'ab'.repeat(32), capBaseIn: '100e18', capQuoteIn: '200e18' });
  assert(pr.unsignedTransactions?.length === 1 && pr.unsignedTransactions[0].data.startsWith('0x4f5a81df'), 'selfRegister calldata');
  const pf = await call('prepare_fund', { agentId: AGENT, amount: '0.01mon' });
  assert(pf.unsignedTransactions[0].value === '10000000000000000', 'fund value');
  await call('prepare_deposit', { agentId: AGENT, base: '1e18' });
  await call('prepare_set_alert', { agentId: AGENT, threshold: '0.01mon' });
  return { client, call, say };
}

async function viaStdio(env: Record<string, string>, name: string, log: string[], local = false, extra?: (c: any) => Promise<void>) {
  const client = new Client({ name: 'pqagent-smoke', version: '0.1.0' });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI], env, stderr: 'pipe' }));
  try { const s = await session(name, client, log, local); if (extra) await extra(s); } finally { await client.close(); }
}

async function viaHttp(log: string[]) {
  const port = 3300 + Math.floor(Math.random() * 500);
  const proc = spawn(process.execPath, [CLI, '--http', '--port', String(port)], { env: baseEnv, stdio: ['ignore', 'ignore', 'pipe'] });
  let err = '';
  await new Promise<void>((res, rej) => {
    const t = setTimeout(() => rej(new Error(`http server did not start: ${err}`)), 15_000);
    proc.stderr.on('data', (d) => { err += d; if (err.includes('streamable HTTP on')) { clearTimeout(t); res(); } });
    proc.on('exit', (c) => rej(new Error(`http server exited ${c}: ${err}`)));
  });
  try {
    const url = `http://127.0.0.1:${port}/mcp`;
    log.push(`server: ${err.trim().split('\n').join(' | ')}`);
    // raw JSON-RPC (what any HTTP client can do, no SDK): tools/list in one POST
    const raw = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'is_authorized', arguments: { agentId: AGENT, pkHash: PKH } } }) });
    const rj: any = await raw.json();
    log.push(`raw POST ${url} tools/call is_authorized -> HTTP ${raw.status}: ${rj.result.content[0].text.replace(/\s+/g, ' ')}`);
    assert(raw.status === 200 && JSON.parse(rj.result.content[0].text).authorized === true, 'raw http');
    // fetch() cannot override Host, so use node:http for the DNS-rebinding check
    const evil = await new Promise<{ status: number }>((res, rej) => {
      const rq = httpRequest({ host: '127.0.0.1', port, path: '/mcp', method: 'POST',
        headers: { host: 'evil.example', 'content-type': 'application/json', accept: 'application/json, text/event-stream' } },
        (r) => { r.resume(); res({ status: r.statusCode ?? 0 }); });
      rq.on('error', rej); rq.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }));
    });
    log.push(`DNS-rebinding check: POST with Host: evil.example -> HTTP ${evil.status}`);
    assert(evil.status === 403, 'host allow-list');
    const client = new Client({ name: 'pqagent-smoke', version: '0.1.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(url)));
    try { await session(`streamable HTTP ${url}`, client, log); } finally { await client.close(); }
  } finally { proc.kill(); }
}

const logs: Record<string, string[]> = { stdio: [], http: [], local: [] };
await viaStdio(baseEnv, 'stdio (read-only + unsigned tx)', logs.stdio);
await viaHttp(logs.http);

// HTTP must refuse an operator key (fail closed)
const refuse = spawn(process.execPath, [CLI, '--http', '--port', '0'], { env: { ...baseEnv, PQAGENT_MCP_ENABLE_SEND: '1', PQAGENT_OPERATOR_KEY: '0x' + '01'.repeat(32) } });
let refuseErr = ''; refuse.stderr.on('data', (d) => { refuseErr += d; });
const code = await new Promise((r) => refuse.on('exit', r));
logs.http.push(`\nHTTP + PQAGENT_MCP_ENABLE_SEND=1 -> exit ${code}: ${refuseErr.trim()}`);
assert(code === 1 && /only allowed with the local stdio/.test(refuseErr), 'http must refuse operator key');

if (process.env.LOCAL_MODE === '1') {
  const keyFile = process.env.OPERATOR_KEY_FILE;
  assert(keyFile, 'LOCAL_MODE needs OPERATOR_KEY_FILE');
  const dir = join(mkdtempSync(join(tmpdir(), 'pqmcp-')), '.pqagent');
  const pass = `mcp local ${Date.now()}`;
  const ag = await Agent.init(dir, { chainId: Number(process.env.PQAGENT_CHAIN_ID ?? 20143), settlement: process.env.PQAGENT_SETTLEMENT ?? '0x0e1AD57BFb7E25656dE899571BE624559d871D10',
    model: 'mcp local-mode model', passphrase: pass });
  const env = { ...baseEnv, PQAGENT_DIR: dir, PQAGENT_PASSPHRASE: pass, PQAGENT_MCP_ENABLE_SEND: '1', PQAGENT_OPERATOR_KEY_FILE: keyFile };
  await viaStdio(env, `stdio LOCAL MODE (keystore ${ag.config.pkHash.slice(0, 10)}…, broadcast enabled)`, logs.local, true, async ({ call }) => {
    const before = await call('local_agent');
    assert(before.agentId === undefined && before.authorized === false, 'fresh keystore');
    const reg = await call('prepare_register', { capBaseIn: '100e18', capQuoteIn: '200e18', broadcast: true });
    assert(reg.agentId > 0 && reg.keystoreUpdated, 'registered from MCP');
    const fund = await call('prepare_fund', { agentId: reg.agentId, amount: '0.005mon', broadcast: true });
    assert(fund.receipts[0].status === 'success', 'funded');
    const s = await call('sign_action', { side: 'sell', amountIn: '1e18', minAmountOut: '1', ttlSecs: 7200 });
    assert(s.signedAction.nonce === 1 && s.signedAction.agentId === reg.agentId, 'signed');
    const v = await call('verify_signed_action', { action: s.signedAction });
    assert(v.valid && v.onChain.authorized && v.onChain.settleable, 'settleable');
    const fb = await call('fee_balance', { agentId: reg.agentId });
    assert(fb.remainingActions === '5' || BigInt(fb.feeBalance) === 5_000_000_000_000_000n, 'fee balance');
  });
}

console.log('\nMCP smoke OK');
if (OUT) {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'mcp-stdio-transcript.txt'), logs.stdio.join('\n') + '\n');
  writeFileSync(join(OUT, 'mcp-http-transcript.txt'), logs.http.join('\n') + '\n');
  if (logs.local.length) writeFileSync(join(OUT, 'mcp-stdio-local-mode-transcript.txt'), logs.local.join('\n') + '\n');
}
