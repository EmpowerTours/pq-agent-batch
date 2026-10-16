/** Server configuration from environment variables (Monad Solonet defaults). No secrets are stored here. */
import { readFileSync } from 'node:fs';
import { SOLONET, operatorAccount } from '@empowertours/pqagent';
import type { Account } from 'viem';

export type Transport = 'stdio' | 'http';

export interface ServerConfig {
  chainId: number;
  rpcUrl: string;
  settlement: string;
  registry?: string;
  networkName: string;
  transport: Transport;
  /** local stdio only: operator account used to broadcast prepared txs (off unless explicitly enabled) */
  operator?: Account;
  /** local stdio only: keystore dir for sign_action */
  keystoreDir?: string;
  keystorePassphrase?: string;
}

export const ENV = {
  CHAIN_ID: 'PQAGENT_CHAIN_ID',
  RPC: 'PQAGENT_RPC',
  SETTLEMENT: 'PQAGENT_SETTLEMENT',
  REGISTRY: 'PQAGENT_REGISTRY',
  NETWORK_NAME: 'PQAGENT_NETWORK_NAME',
  ENABLE_SEND: 'PQAGENT_MCP_ENABLE_SEND',
  OPERATOR_KEY: 'PQAGENT_OPERATOR_KEY',
  OPERATOR_KEY_FILE: 'PQAGENT_OPERATOR_KEY_FILE',
  DIR: 'PQAGENT_DIR',
  PASSPHRASE: 'PQAGENT_PASSPHRASE',
} as const;

const truthy = (v?: string) => !!v && ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());

export function loadConfig(transport: Transport, env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const chainId = Number(env[ENV.CHAIN_ID] ?? SOLONET.chainId);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error(`${ENV.CHAIN_ID} must be a positive integer`);
  const cfg: ServerConfig = {
    chainId,
    rpcUrl: env[ENV.RPC] ?? SOLONET.rpcUrl,
    settlement: env[ENV.SETTLEMENT] ?? SOLONET.settlement,
    registry: env[ENV.REGISTRY] ?? (env[ENV.SETTLEMENT] ? undefined : SOLONET.registry),
    networkName: env[ENV.NETWORK_NAME] ?? (chainId === 20143 ? 'Monad Solonet (local devnet)' : chainId === 143 ? 'Monad mainnet' : `chain ${chainId}`),
    transport,
  };
  const wantSend = truthy(env[ENV.ENABLE_SEND]);
  if (wantSend) {
    // Fail closed: a network-reachable server must never hold an operator key.
    if (transport !== 'stdio') throw new Error(`${ENV.ENABLE_SEND} is only allowed with the local stdio transport (never over HTTP)`);
    const raw = env[ENV.OPERATOR_KEY_FILE] ? readFileSync(env[ENV.OPERATOR_KEY_FILE]!, 'utf8') : env[ENV.OPERATOR_KEY];
    if (!raw) throw new Error(`${ENV.ENABLE_SEND}=1 needs ${ENV.OPERATOR_KEY_FILE} or ${ENV.OPERATOR_KEY}`);
    cfg.operator = operatorAccount(raw);
  }
  if (transport === 'stdio' && env[ENV.DIR]) {
    cfg.keystoreDir = env[ENV.DIR];
    cfg.keystorePassphrase = env[ENV.PASSPHRASE];
  }
  return cfg;
}

/** RPC URL safe to show to a client: no userinfo, query string or path tokens (API keys often live there). */
export function redactRpc(url: string): string {
  try {
    const u = new URL(url);
    const hidden = u.username || u.password || u.search || (u.pathname && u.pathname !== '/');
    return `${u.protocol}//${u.host}${hidden ? '/…' : ''}`;
  } catch { return '(unparseable rpc url)'; }
}
