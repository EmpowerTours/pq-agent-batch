#!/usr/bin/env node
/**
 * pqagent-mcp — MCP server for the pq-agent-batch proof-of-agency registry.
 *   pqagent-mcp                       stdio (Claude Desktop / Claude Code / Cursor / VS Code)
 *   pqagent-mcp --http [--port 3333] [--host 127.0.0.1] [--allowed-hosts a.example:443,...]
 * Configuration: env PQAGENT_CHAIN_ID, PQAGENT_RPC, PQAGENT_SETTLEMENT, PQAGENT_REGISTRY (Monad Solonet defaults).
 * Local stdio only: PQAGENT_DIR (+ PQAGENT_PASSPHRASE) enables sign_action; PQAGENT_MCP_ENABLE_SEND=1 with
 * PQAGENT_OPERATOR_KEY_FILE (or PQAGENT_OPERATOR_KEY) enables broadcasting prepared transactions.
 * Logs go to stderr (stdout is the MCP channel in stdio mode).
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig, redactRpc } from './config.js';
import { createServer, SERVER_VERSION } from './server.js';
import { startHttp } from './http.js';

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };

if (flag('--help') || flag('-h')) {
  console.error('usage: pqagent-mcp [--http [--port N] [--host H] [--allowed-hosts h1,h2] [--allowed-origins o1,o2]]   (default: stdio)');
  process.exit(0);
}

const http = flag('--http');
try {
  const cfg = loadConfig(http ? 'http' : 'stdio');
  const banner = `pqagent-mcp ${SERVER_VERSION}: chain ${cfg.chainId} rpc ${redactRpc(cfg.rpcUrl)} settlement ${cfg.settlement}`;
  if (http) {
    const port = Number(opt('--port') ?? process.env.PORT ?? 3333);
    const h = await startHttp(cfg, { port, host: opt('--host') ?? process.env.HOST ?? '127.0.0.1',
      allowedHosts: opt('--allowed-hosts')?.split(','), allowedOrigins: opt('--allowed-origins')?.split(',') });
    console.error(`${banner}\nstreamable HTTP on ${h.url} (stateless, read-only + unsigned-tx tools)`);
    const stop = () => { void h.close().then(() => process.exit(0)); };
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
  } else {
    const server = createServer(cfg);
    await server.connect(new StdioServerTransport());
    console.error(`${banner}\nstdio${cfg.keystoreDir ? ' + local signing (sign_action)' : ''}${cfg.operator ? ` + LOCAL BROADCAST as ${cfg.operator.address}` : ''}`);
  }
} catch (e) {
  console.error(`pqagent-mcp: ${(e as Error).message}`);
  process.exit(1);
}
