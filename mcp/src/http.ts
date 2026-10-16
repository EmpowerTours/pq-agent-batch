/**
 * Streamable HTTP transport (stateless: one server + transport per POST, JSON responses), on node:http.
 * Binds 127.0.0.1 by default with DNS-rebinding protection (Host / Origin allow-list). Read-only and
 * unsigned-transaction tools only: config.ts refuses to load an operator key for this transport.
 */
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import type { ServerConfig } from './config.js';

export interface HttpOptions { host?: string; port?: number; path?: string; allowedHosts?: string[]; allowedOrigins?: string[]; maxBodyBytes?: number }

function readBody(req: IncomingMessage, limit: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => { n += c.length; if (n > limit) { reject(Object.assign(new Error('request body too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : undefined); } catch { reject(Object.assign(new Error('invalid JSON'), { status: 400 })); } });
    req.on('error', reject);
  });
}

const rpcError = (res: ServerResponse, status: number, message: string) => {
  res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }));
};

export async function startHttp(cfg: ServerConfig, o: HttpOptions = {}): Promise<{ server: Server; url: string; close: () => Promise<void> }> {
  const host = o.host ?? '127.0.0.1';
  const port = o.port ?? 3333;
  const path = o.path ?? '/mcp';
  const local = ['127.0.0.1', 'localhost', '::1'].includes(host);
  const allowedHosts = o.allowedHosts ?? (local ? [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`] : undefined);
  const limit = o.maxBodyBytes ?? 4 * 1024 * 1024;

  const http = createHttpServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    if (url.pathname === '/healthz') { res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok: true, name: 'pqagent-mcp', chainId: cfg.chainId })); return; }
    if (url.pathname !== path) { res.writeHead(404).end(); return; }
    if (req.method !== 'POST') { res.setHeader('allow', 'POST'); rpcError(res, 405, 'stateless server: use POST'); return; }
    let body: unknown;
    try { body = await readBody(req, limit); } catch (e: any) { rpcError(res, e.status ?? 400, e.message); return; }
    const server = createServer(cfg);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, enableJsonResponse: true,
      enableDnsRebindingProtection: !!(allowedHosts || o.allowedOrigins), allowedHosts, allowedOrigins: o.allowedOrigins,
    });
    res.on('close', () => { void transport.close(); void server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (e) {
      if (!res.headersSent) rpcError(res, 500, 'internal error');
      console.error('[pqagent-mcp] request failed:', (e as Error).message);
    }
  });
  await new Promise<void>((r, j) => { http.once('error', j); http.listen(port, host, () => r()); });
  const addr = http.address();
  const realPort = typeof addr === 'object' && addr ? addr.port : port;
  return { server: http, url: `http://${host.includes(':') ? `[${host}]` : host}:${realPort}${path}`,
    close: () => new Promise<void>((r) => http.close(() => r())) };
}
