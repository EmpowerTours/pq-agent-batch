/** Offline MCP server tests (in-memory transport, no chain needed). */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/server.js';
import { loadConfig, redactRpc } from '../src/config.js';

const ROOT = join(import.meta.dirname, '..', '..');
const fx = JSON.parse(readFileSync(join(ROOT, 'results/solonet/b1-n10/groth16-batch-fixture.json'), 'utf8'));
const bi = JSON.parse(readFileSync(join(ROOT, 'sdk/tests/fixtures/batch-input-b1-n10.json'), 'utf8'));

async function connect(env: Record<string, string> = {}, transport: 'stdio' | 'http' = 'http') {
  const cfg = loadConfig(transport, { PQAGENT_RPC: 'http://127.0.0.1:9', ...env });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const server = createServer(cfg);
  await server.connect(a);
  const client = new Client({ name: 't', version: '0' });
  await client.connect(b);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r: any = await client.callTool({ name, arguments: args });
    return { isError: !!r.isError, body: (() => { try { return JSON.parse(r.content[0].text); } catch { return r.content[0].text; } })() };
  };
  return { client, call };
}

describe('pqagent MCP server', () => {
  it('lists the public tools with descriptions and read-only hints; no local tools by default', async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(['network_info', 'agent_status', 'is_authorized', 'fee_quote', 'fee_balance', 'verify_signed_action',
      'batch_digest', 'build_batch', 'prepare_register', 'prepare_fund', 'prepare_deposit', 'prepare_set_alert']);
    for (const t of tools) { expect(t.description!.length).toBeGreaterThan(80); expect(t.annotations?.readOnlyHint).toBe(true); }
    expect(JSON.stringify(tools)).not.toContain('"broadcast"');
  });

  it('batch_digest reproduces the proved N=10 digest (other deployment: no RPC needed)', async () => {
    const { call } = await connect();
    const r = await call('batch_digest', { batchId: fx.batchId, batch: fx.batch, chainId: fx.chainId, settlement: fx.settlement });
    expect(r.isError).toBe(false);
    expect(r.body.digest).toBe(fx.digest);
    expect(r.body.orders).toBe(10);
    expect(r.body.groups.map((g: any) => g.agentId)).toEqual([1, 2]);
    expect((await call('batch_digest', { batchId: 1, batch: '0x0001' })).isError).toBe(true);
  });

  it('verify_signed_action accepts a proved-batch signature and rejects tampering (offline)', async () => {
    const { call } = await connect();
    const g = bi.groups[0];
    const groups = JSON.parse(JSON.stringify((await call('batch_digest', { batchId: fx.batchId, batch: fx.batch, chainId: fx.chainId, settlement: fx.settlement })).body.groups));
    const o = groups[0].orders[0];
    const { signAction, AgentKey, actionMessage, hex0x, encodeOrder } = await import('@empowertours/pqagent');
    const params = { chainId: bi.chainId, settlement: bi.settlement, agentId: 1, nonce: g.firstNonce, expiry: groups[0].expiry, modelHash: groups[0].modelHash,
      order: { buyBase: o.side === 'buy', amountIn: BigInt(o.amountIn), minAmountOut: BigInt(o.minAmountOut) } };
    const a = signAction(params, AgentKey.testKey(1));
    expect(a.signature).toBe(g.signatures[0]); // == the proved signature
    expect(a.message).toBe(hex0x(actionMessage(params)));
    expect(a.orderBytes).toBe(hex0x(encodeOrder(params.order)));
    const ok = await call('verify_signed_action', { action: a, checkOnChain: false });
    expect(ok.body.valid).toBe(true);
    const asText = await call('verify_signed_action', { action: JSON.stringify(a), checkOnChain: false });
    expect(asText.body.valid).toBe(true);
    const bad = await call('verify_signed_action', { action: { ...a, nonce: a.nonce + 1 }, checkOnChain: false });
    expect(bad.body).toEqual({ valid: false, reason: 'message inconsistent with fields' });
  });

  it('chain errors surface as tool errors, not crashes', async () => {
    const { call } = await connect();
    const r = await call('agent_status', { agentId: 1 });
    expect(r.isError).toBe(true);
  });

  it('fails closed: operator key only with stdio, and only when explicitly enabled', () => {
    const key = '0x' + '01'.repeat(32);
    expect(() => loadConfig('http', { PQAGENT_MCP_ENABLE_SEND: '1', PQAGENT_OPERATOR_KEY: key })).toThrow(/only allowed with the local stdio/);
    expect(loadConfig('stdio', { PQAGENT_OPERATOR_KEY: key }).operator).toBeUndefined(); // key present but not enabled
    expect(loadConfig('stdio', { PQAGENT_MCP_ENABLE_SEND: '1', PQAGENT_OPERATOR_KEY: key }).operator?.address).toMatch(/^0x/);
    expect(() => loadConfig('stdio', { PQAGENT_MCP_ENABLE_SEND: '1' })).toThrow(/needs/);
    expect(loadConfig('http', { PQAGENT_DIR: '/tmp/x' }).keystoreDir).toBeUndefined();
  });

  it('local mode adds broadcast / sign_action (stdio only)', async () => {
    const { client } = await connect({ PQAGENT_MCP_ENABLE_SEND: '1', PQAGENT_OPERATOR_KEY: '0x' + '01'.repeat(32), PQAGENT_DIR: '/tmp/none' }, 'stdio');
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain('sign_action');
    expect(tools.find((t) => t.name === 'prepare_fund')!.inputSchema.properties).toHaveProperty('broadcast');
  });

  it('redacts RPC secrets', () => {
    expect(redactRpc('https://monad.example/v1/abcdef?key=1')).toBe('https://monad.example/…');
    expect(redactRpc('https://user:pw@rpc.example')).toBe('https://rpc.example/…');
    expect(redactRpc('http://localhost:8080')).toBe('http://localhost:8080');
  });
});
