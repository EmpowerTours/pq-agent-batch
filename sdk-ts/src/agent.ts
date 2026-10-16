/**
 * High-level API mirroring the Rust `Agent` / `pqagent` CLI. All state lives in a keystore directory
 * (default `.pqagent/`) whose files are identical to the Rust SDK's (key.json 0600, config.json,
 * pubkey.hex), so `pqagent` (Rust) and this package can use the same agent interchangeably.
 */
import { promises as fs, existsSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import type { Account, Address } from 'viem';
import { AgentKey, PASSPHRASE_ENV, ensurePrivateDir, loadKey, modelHash, saveKey } from './keys.js';
import { type Order, type SignedAction, signAction } from './action.js';
import { PqClient, registeredId, type AgentStatus, type FeeBalance, type UnsignedTx } from './chain.js';
import { hex0x, type Hex } from './bytes.js';

export const CONFIG_SCHEMA = 'pq-agent-batch/agent-config/v1';
/** Env var holding the operator's EVM private key (hex) — same as the Rust CLI. Never stored. */
export const OPERATOR_KEY_ENV = 'PQAGENT_OPERATOR_KEY';

export interface AgentConfig {
  schema: string;
  rpc?: string;
  chainId: number;
  settlement: string;
  registry?: string;
  agentId?: number;
  pkHash: Hex;
  modelHash: Hex;
  modelSource: string;
  keyEncrypted: boolean;
  nextNonce: number;
  expiryBucketSecs: number;
}

export interface InitOptions {
  chainId: number;
  settlement: string;
  rpc?: string;
  /** model artifact bytes (modelHash = keccak256(bytes)) or identifier string (keccak256(utf8)) */
  model: Uint8Array | string;
  modelSource?: string;
  /** encrypt key.json (Argon2id + ChaCha20-Poly1305); default: env PQAGENT_PASSPHRASE if set */
  passphrase?: string;
  /** set if the agent is already registered (e.g. by the admin) */
  agentId?: number;
  /** INSECURE: reproduce the repo's public TEST key i (golden vectors / demos) */
  testSeed?: number;
  force?: boolean;
  expiryBucketSecs?: number;
}

export interface Registration { agentId: number; txHash: Hex; registrationFee: string; bond: string; capBaseIn: string; capQuoteIn: string; gasUsed: string }
export interface TxResult { txHash: Hex; gasUsed: string; description: string }

/** Operator EVM account from a hex private key, or from env PQAGENT_OPERATOR_KEY. The key is never logged. */
export function operatorAccount(hexKey?: string): Account {
  const raw = (hexKey ?? process.env[OPERATOR_KEY_ENV] ?? '').trim();
  if (!raw) throw new Error(`no operator key: set ${OPERATOR_KEY_ENV}`);
  const k = (raw.startsWith('0x') ? raw : `0x${raw}`) as Hex;
  if (!/^0x[0-9a-fA-F]{64}$/.test(k)) throw new Error('operator key must be 32 bytes of hex');
  return privateKeyToAccount(k);
}

export class Agent {
  readonly dir: string;
  config: AgentConfig;
  #passphrase?: string;

  private constructor(dir: string, config: AgentConfig, passphrase?: string) {
    this.dir = dir; this.config = config; this.#passphrase = passphrase;
  }

  static keyPath(dir: string) { return join(dir, 'key.json'); }

  /** Generate (or reproduce, with testSeed) an ML-DSA-65 key; write key.json (0600, dir 0700), pubkey.hex, config.json. */
  static async init(dir: string, o: InitOptions): Promise<Agent> {
    if (existsSync(Agent.keyPath(dir)) && !o.force) {
      throw new Error(`${Agent.keyPath(dir)} already exists (use force to overwrite; this destroys the old key)`);
    }
    const pass = o.passphrase ?? process.env[PASSPHRASE_ENV];
    await ensurePrivateDir(dir);
    const key = o.testSeed !== undefined ? AgentKey.testKey(o.testSeed) : AgentKey.generate();
    try {
      await saveKey(Agent.keyPath(dir), key, pass);
      await fs.writeFile(join(dir, 'pubkey.hex'), Buffer.from(key.publicKey).toString('hex') + '\n');
      const config: AgentConfig = {
        schema: CONFIG_SCHEMA, ...(o.rpc ? { rpc: o.rpc } : {}), chainId: o.chainId, settlement: hex0x(Buffer.from(o.settlement.slice(2), 'hex')),
        ...(o.agentId !== undefined ? { agentId: o.agentId } : {}),
        pkHash: key.pkHashHex, modelHash: hex0x(modelHash(o.model)),
        modelSource: o.modelSource ?? (typeof o.model === 'string' ? `string:${o.model}` : 'bytes'), keyEncrypted: pass !== undefined,
        nextNonce: 1, expiryBucketSecs: o.expiryBucketSecs ?? 3600,
      };
      const a = new Agent(dir, config, pass);
      await a.save();
      const gi = join(dir, '.gitignore');
      if (!existsSync(gi)) await fs.writeFile(gi, '# pqagent keystore: never commit\n*\n');
      return a;
    } finally { key.destroy(); }
  }

  /** Open an existing keystore dir (created by this SDK or the Rust CLI). */
  static async open(dir: string, opts: { passphrase?: string; rpc?: string } = {}): Promise<Agent> {
    const p = join(dir, 'config.json');
    let c: AgentConfig;
    try { c = JSON.parse(await fs.readFile(p, 'utf8')); } catch (e) { throw new Error(`read ${p} (run init first): ${(e as Error).message}`); }
    if (c.schema !== CONFIG_SCHEMA) throw new Error(`unknown config schema ${c.schema}`);
    const a = new Agent(dir, c, opts.passphrase ?? process.env[PASSPHRASE_ENV]);
    if (opts.rpc && opts.rpc !== c.rpc) { a.config = reorder({ ...c, rpc: opts.rpc }); await a.save(); }
    return a;
  }

  async save(): Promise<void> {
    await fs.writeFile(join(this.dir, 'config.json'), JSON.stringify(reorder(this.config), null, 2) + '\n');
  }

  /** Load the signing key (decrypting with the passphrase). Caller should `destroy()` it when done. */
  async key(): Promise<AgentKey> {
    const k = await loadKey(Agent.keyPath(this.dir), this.#passphrase);
    if (k.pkHashHex !== this.config.pkHash) { k.destroy(); throw new Error('key.json does not match config.json pkHash'); }
    return k;
  }

  get agentId(): number {
    if (this.config.agentId === undefined) throw new Error('no agentId yet: register first (or init with agentId)');
    return this.config.agentId;
  }

  client(): PqClient {
    if (!this.config.rpc) throw new Error('no rpc configured');
    return new PqClient({ chainId: this.config.chainId, rpcUrl: this.config.rpc, settlement: this.config.settlement, registry: this.config.registry });
  }

  private async ensureRegistry(c: PqClient): Promise<Address> {
    const r = await c.registry();
    if (!this.config.registry) { this.config.registry = r.toLowerCase(); await this.save(); }
    return r;
  }

  /** Unsigned selfRegister tx (for an external wallet). */
  async prepareRegister(o: { capBaseIn?: bigint; capQuoteIn?: bigint; extraBond?: bigint } = {}): Promise<UnsignedTx> {
    return this.client().buildRegisterTx(this.config.pkHash, o);
  }

  /** Self-register with a local operator account: pays registrationFee + bond. cap 0 = registry maximum. */
  async register(op: Account, o: { capBaseIn?: bigint; capQuoteIn?: bigint; extraBond?: bigint } = {}): Promise<Registration> {
    if (this.config.agentId !== undefined) throw new Error(`already registered as agent ${this.config.agentId}`);
    const c = this.client();
    await c.checkChain();
    const reg = await this.ensureRegistry(c);
    const tx = await c.buildRegisterTx(this.config.pkHash, o);
    const [rc] = await c.sendTxs(op, [tx]);
    const id = registeredId(rc, reg);
    if (id === undefined) throw new Error(`no AgentRegistered log in ${rc.transactionHash}`);
    this.config.agentId = id; await this.save();
    const st = await c.agentStatus(id);
    const info = await c.registryInfo();
    return { agentId: id, txHash: rc.transactionHash, registrationFee: info.registrationFee, bond: st.stake,
      capBaseIn: st.capBaseIn, capQuoteIn: st.capQuoteIn, gasUsed: rc.gasUsed.toString() };
  }

  /** Deposit to the prepaid fee balance (native MON, or approve + depositFeeToken for an ERC20 fee token). */
  async fund(op: Account, amount: bigint): Promise<TxResult[]> {
    const c = this.client();
    const txs = await c.buildFundTxs(this.agentId, amount, op.address);
    return toResults(txs, await c.sendTxs(op, txs));
  }

  /** Deposit trading balances (base/quote ERC20s) that orders spend. */
  async depositTrading(op: Account, base: bigint, quote: bigint): Promise<TxResult[]> {
    const c = this.client();
    const txs = await c.buildDepositTxs(this.agentId, base, quote, op.address);
    return toResults(txs, await c.sendTxs(op, txs));
  }

  async balance(): Promise<FeeBalance> { return this.client().feeBalance(this.agentId); }

  /** Low-balance alert threshold (LowFeeBalance event) + optional ERC20 auto top-up. */
  async setAlert(op: Account, threshold: bigint, autoTopUp?: bigint): Promise<TxResult[]> {
    const c = this.client();
    const txs = c.buildSetAlertTxs(this.agentId, threshold, autoTopUp);
    return toResults(txs, await c.sendTxs(op, txs));
  }

  /** Next nonce: max(local counter, on-chain lastNonce + 1) when an rpc is configured. */
  async nextNonce(): Promise<number> {
    let n = this.config.nextNonce;
    if (this.config.rpc && this.config.agentId !== undefined) n = Math.max(n, (await this.client().agentStatus(this.config.agentId)).nextNonce);
    return n;
  }

  /** now + ttl rounded UP to the expiry bucket (orders signed close together share one expiry -> one group). */
  defaultExpiry(nowSecs: number, ttlSecs: number): number {
    const b = Math.max(1, this.config.expiryBucketSecs);
    const e = Math.ceil((nowSecs + ttlSecs) / b) * b;
    if (e > 0xffffffff) throw new Error('expiry overflows u32');
    return e;
  }

  /**
   * ML-DSA sign one order, advance the local nonce counter, and optionally write the v1 submission JSON.
   * `out`: a file path, or a directory (existing, or a new path ending in '/' or without .json) which gets
   * `<agentId:06>-<nonce:012>.json` — same naming as the Rust CLI.
   */
  async sign(order: Order, o: { nonce?: number; expiry?: number; ttl?: number; out?: string } = {}): Promise<{ action: SignedAction; path?: string }> {
    const nonce = o.nonce ?? await this.nextNonce();
    const expiry = o.expiry ?? this.defaultExpiry(Math.floor(Date.now() / 1000), o.ttl ?? 3600);
    const key = await this.key();
    let action: SignedAction;
    try {
      action = signAction({ chainId: this.config.chainId, settlement: this.config.settlement, agentId: this.agentId, nonce, expiry,
        modelHash: this.config.modelHash, order }, key);
    } finally { key.destroy(); }
    this.config.nextNonce = Math.max(this.config.nextNonce, nonce + 1);
    await this.save();
    let path: string | undefined;
    if (o.out) {
      const isDir = (existsSync(o.out) && statSync(o.out).isDirectory()) || (!existsSync(o.out) && (o.out.endsWith('/') || extname(o.out) !== '.json'));
      if (isDir) await fs.mkdir(o.out, { recursive: true });
      path = isDir ? join(o.out, `${String(action.agentId).padStart(6, '0')}-${String(action.nonce).padStart(12, '0')}.json`) : o.out;
      await fs.writeFile(path, JSON.stringify(action, null, 2) + '\n');
    }
    return { action, path };
  }

  /** Registry authorization + agent info for this agent's key. */
  async status(): Promise<AgentStatus & { nextNonce: number }> {
    const c = this.client();
    await this.ensureRegistry(c);
    const s = await c.agentStatus(this.agentId, this.config.pkHash);
    return { ...s, nextNonce: Math.max(this.config.nextNonce, s.lastNonce + 1) };
  }
}

function toResults(txs: UnsignedTx[], rcs: { transactionHash: Hex; gasUsed: bigint }[]): TxResult[] {
  return rcs.map((r, i) => ({ txHash: r.transactionHash, gasUsed: r.gasUsed.toString(), description: txs[i].description }));
}

/** Keep config.json key order identical to the Rust SDK's serde output. */
function reorder(c: AgentConfig): AgentConfig {
  const o: any = { schema: c.schema };
  if (c.rpc !== undefined) o.rpc = c.rpc;
  o.chainId = c.chainId; o.settlement = c.settlement;
  if (c.registry !== undefined) o.registry = c.registry;
  if (c.agentId !== undefined) o.agentId = c.agentId;
  Object.assign(o, { pkHash: c.pkHash, modelHash: c.modelHash, modelSource: c.modelSource, keyEncrypted: c.keyEncrypted,
    nextNonce: c.nextNonce, expiryBucketSecs: c.expiryBucketSecs });
  return o;
}
