/**
 * MCP server for the pq-agent-batch proof-of-agency registry.
 *
 * Read-only tools need no key and are safe to expose publicly. Write tools return UNSIGNED transactions
 * ({ chainId, to, data, value }) for the user's own wallet to sign; the server never holds a user's
 * operator key. Only in local stdio mode, and only when explicitly enabled, can it broadcast those
 * prepared transactions with an operator key from the environment, and sign actions with a local keystore.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  Agent, OfflineState, OnChainState, PqClient, batchDigest, buildBatch, checkSignedAction, fmtUnits, parseAmount, parseBatch,
  registeredId, type SignedAction, type Submission, type UnsignedTx,
} from '@empowertours/pqagent';
import { redactRpc, type ServerConfig } from './config.js';

export const SERVER_NAME = 'pqagent';
export const SERVER_VERSION = '0.1.0';

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };
const ok = (v: unknown): ToolResult => ({ content: [{ type: 'text', text: JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x), 2) }] });
const err = (e: unknown): ToolResult => ({ content: [{ type: 'text', text: `error: ${(e as Error)?.message ?? String(e)}` }], isError: true });
const guard = <A>(f: (a: A) => Promise<unknown>) => async (a: A): Promise<ToolResult> => { try { return ok(await f(a)); } catch (e) { return err(e); } };

const agentId = z.number().int().min(1).max(0xffffffff).describe('Agent id in the AgentRegistry (uint32, starts at 1)');
const pkHash = z.string().regex(/^0x[0-9a-fA-F]{64}$/).describe('sha256 of the agent\'s ML-DSA-65 public key (0x + 64 hex)');
const amount = (what: string) => z.string().min(1).max(64).describe(`${what}. Token base units (wei) as an integer string, or with a unit: "0.05mon", "2.5ether", "1e17", "3gwei"`);
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const READ = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;
const PREP = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;
const SEND = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true } as const;

const unsignedNote = 'Returns UNSIGNED transaction(s) { chainId, to, data, value (wei, decimal string) } in order; sign and send them with the operator\'s own wallet (e.g. eth_sendTransaction, viem walletClient.sendTransaction, cast send --data). This server never sees the operator key.';

export function createServer(cfg: ServerConfig): McpServer {
  const client = new PqClient({ chainId: cfg.chainId, rpcUrl: cfg.rpcUrl, settlement: cfg.settlement, registry: cfg.registry, name: cfg.networkName });
  const canSend = cfg.transport === 'stdio' && !!cfg.operator;
  const canSign = cfg.transport === 'stdio' && !!cfg.keystoreDir;
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION }, {
    instructions: [
      'pq-agent-batch proof-of-agency registry on Monad: AI agents register a post-quantum (ML-DSA-65) key, model hash, per-batch spending caps and a bond;',
      'their signed actions are batched, proved with an SP1 zk proof and settled on chain. Use agent_status / is_authorized to check whether an',
      'agent key is currently allowed to act, verify_signed_action to check a signed action, fee_balance / fee_quote for prepaid settlement fees,',
      'and prepare_* to get unsigned transactions for registering or funding an agent. Amounts are wei strings unless a unit (mon, gwei, e18) is given.',
    ].join(' '),
  });

  const sendIfAsked = async (txs: UnsignedTx[], broadcast?: boolean) => {
    if (!broadcast) return { unsignedTransactions: txs, note: unsignedNote };
    if (!canSend) throw new Error('broadcast is disabled on this server (local stdio + PQAGENT_MCP_ENABLE_SEND=1 only)');
    const rcs = await client.sendTxs(cfg.operator!, txs);
    return { broadcast: true, operator: cfg.operator!.address,
      receipts: rcs.map((r, i) => ({ description: txs[i].description, txHash: r.transactionHash, status: r.status, gasUsed: r.gasUsed.toString(), blockNumber: r.blockNumber.toString() })),
      _rcs: rcs };
  };
  const strip = (o: any) => { if (o && '_rcs' in o) delete o._rcs; return o; };
  const broadcastParam: Record<string, z.ZodTypeAny> = canSend
    ? { broadcast: z.boolean().optional().describe(`LOCAL MODE: true = sign and send with the configured operator ${cfg.operator!.address} instead of returning unsigned txs. Spends real funds on ${cfg.networkName}; confirm with the user first.`) }
    : {};

  // ------------------------------------------------------------------ read-only

  server.registerTool('network_info', {
    title: 'Network and registry info',
    description: `Chain, contract addresses and registry parameters this server reads from (${cfg.networkName}, chain ${cfg.chainId}): whether open self-registration is on, registration fee, minimum bond, maximum per-batch caps, number of agents, settlement fee per action, the SP1 batch program verification key, and which optional local tools are enabled. Call this first to learn the deployment.`,
    inputSchema: {},
    annotations: READ,
  }, guard(async () => {
    const info = await client.registryInfo();
    return {
      network: cfg.networkName, rpc: redactRpc(cfg.rpcUrl), ...info,
      registrationFeeMon: fmtUnits(BigInt(info.registrationFee)), minStakeMon: fmtUnits(BigInt(info.minStake)),
      feePerActionMon: fmtUnits(BigInt(info.feePerActionNative)),
      server: { name: SERVER_NAME, version: SERVER_VERSION, transport: cfg.transport, localBroadcast: canSend, localSigning: canSign },
    };
  }));

  server.registerTool('agent_status', {
    title: 'Agent status',
    description: 'Look up one registered agent: operator, active/killed, bond (stake), per-batch caps, number of keys, last settled nonce (next nonce to sign), prepaid fee balance with remainingActions, and trading balances. Pass pkHash to also get `authorized` (is this exact ML-DSA-65 key currently allowed to act for the agent). Read-only.',
    inputSchema: { agentId, pkHash: pkHash.optional() },
    annotations: READ,
  }, guard(async ({ agentId, pkHash }: { agentId: number; pkHash?: string }) => {
    const s = await client.agentStatus(agentId, pkHash);
    return { ...s, stakeMon: fmtUnits(BigInt(s.stake)), feeBalanceMon: fmtUnits(BigInt(s.feeBalance)) };
  }));

  server.registerTool('is_authorized', {
    title: 'Is this agent key authorized?',
    description: 'The one-call trust check apps should use before acting on an agent\'s request: AgentRegistry.isAuthorized(agentId, pkHash) is true only if the agent is registered, not killed, and pkHash is one of its current keys. Returns the boolean plus the reason when false. Read-only, no key needed.',
    inputSchema: { agentId, pkHash },
    annotations: READ,
  }, guard(async ({ agentId, pkHash }: { agentId: number; pkHash: string }) => {
    const s = await client.agentStatus(agentId, pkHash);
    const reason = s.authorized ? 'registered, active, not killed, key is current'
      : !s.registered ? 'unknown agent id' : s.killed ? 'agent was killed (kill switch)' : !s.active ? 'agent not active (retired)' : 'pkHash is not a current key of this agent';
    return { agentId, pkHash: s.pkHash, authorized: s.authorized, reason, registry: await client.registry(), network: cfg.networkName };
  }));

  server.registerTool('fee_quote', {
    title: 'Settlement fee quote',
    description: 'Prepaid settlement fee the contract would charge agent `agentId` for a batch containing `actions` of its orders (BatchSettlementV2.feeQuote), in the agent\'s fee token (index 0 = native MON). Read-only.',
    inputSchema: { agentId, actions: z.number().int().min(1).max(65535).describe('number of orders in one batch') },
    annotations: READ,
  }, guard(async ({ agentId, actions }: { agentId: number; actions: number }) => {
    const q = await client.feeQuote(agentId, actions);
    const b = await client.feeBalance(agentId);
    return { agentId, actions, fee: q.toString(), feeFormatted: fmtUnits(q), feeToken: b.feeToken, feeBalance: b.feeBalance, affordable: BigInt(b.feeBalance) >= q };
  }));

  server.registerTool('fee_balance', {
    title: 'Prepaid fee balance',
    description: 'An agent\'s prepaid settlement-fee account: balance, fee token, fee per action, remainingActions (how many more actions the balance pays for; "unlimited" if fees are zero), low-balance alert threshold and whether it is currently low (LowFeeBalance fires once when it drops below), auto top-up config, pending withdrawal, and trading balances. Use it to tell an operator when to top up. Read-only.',
    inputSchema: { agentId },
    annotations: READ,
  }, guard(async ({ agentId }: { agentId: number }) => {
    const b = await client.feeBalance(agentId);
    return { ...b, feeBalanceFormatted: fmtUnits(BigInt(b.feeBalance)), alertThresholdFormatted: fmtUnits(BigInt(b.alertThreshold)),
      topUpAdvice: b.low ? 'balance is below the alert threshold: top up with prepare_fund' : b.remainingActions !== 'unlimited' && BigInt(b.remainingActions) < 10n ? 'fewer than 10 actions left: top up soon' : 'ok' };
  }));

  server.registerTool('verify_signed_action', {
    title: 'Verify a signed agent action',
    description: 'Verify a signed-action JSON (schema pq-agent-batch/signed-action/v1, as produced by `pqagent sign`, the TS SDK or sign_action): schema and field consistency, sha256(publicKey) == pkHash, and the ML-DSA-65 (FIPS 204) post-quantum signature over the exact 133-byte message the zk prover checks. With checkOnChain (default true) also checks it targets this chain/settlement, the key is authorized in the registry, the nonce is above the last settled nonce, and it has not expired. Read-only.',
    inputSchema: {
      action: z.union([z.string(), z.record(z.any())]).describe('the signed action object, or its JSON text'),
      checkOnChain: z.boolean().optional().describe('default true'),
    },
    annotations: READ,
  }, guard(async ({ action, checkOnChain }: { action: string | Record<string, unknown>; checkOnChain?: boolean }) => {
    const a = (typeof action === 'string' ? JSON.parse(action) : action) as SignedAction;
    const r = checkSignedAction(a);
    if (!r.valid) return { valid: false, reason: r.reason };
    const out: Record<string, unknown> = { valid: true, signatureValid: true, agentId: a.agentId, nonce: a.nonce, expiry: a.expiry, pkHash: a.pkHash,
      modelHash: a.modelHash, order: a.order, chainId: a.chainId, settlement: a.settlement };
    if (checkOnChain !== false) {
      const sameDeployment = a.chainId === cfg.chainId && a.settlement.toLowerCase() === client.settlement.toLowerCase();
      out.onChain = sameDeployment ? await (async () => {
        const [s, now] = await Promise.all([client.agentStatus(a.agentId, a.pkHash), client.now()]);
        const nonceFresh = a.nonce > s.lastNonce; const notExpired = BigInt(a.expiry) >= now;
        return { authorized: s.authorized, lastNonce: s.lastNonce, nonceFresh, notExpired, chainTime: now.toString(),
          settleable: !!s.authorized && nonceFresh && notExpired };
      })() : { skipped: `action targets chain ${a.chainId} / ${a.settlement}, this server reads chain ${cfg.chainId} / ${client.settlement}` };
    }
    return out;
  }));

  server.registerTool('batch_digest', {
    title: 'Batch digest',
    description: 'Compute the digest of a packed batch exactly as BatchSettlementV2.batchDigest and the SP1 proof\'s public values do (keccak256(abi.encode(BATCH_TAG_V2, chainId, settlement, batchId, keccak256(batch)))), decode its agent groups and orders, and (for this server\'s deployment) compare with the contract\'s own batchDigest. Read-only.',
    inputSchema: {
      batchId: z.number().int().min(0).describe('uint64 batch id'),
      batch: z.string().regex(/^0x([0-9a-fA-F]{2})+$/).describe('packed batch bytes (0x hex): per agent an 82-byte header then 25-byte orders'),
      chainId: z.number().int().min(1).optional().describe('default: this server\'s chain'),
      settlement: address.optional().describe('default: this server\'s settlement'),
    },
    annotations: READ,
  }, guard(async (a: { batchId: number; batch: string; chainId?: number; settlement?: string }) => {
    const chainId = a.chainId ?? cfg.chainId; const settlement = a.settlement ?? client.settlement;
    const groups = parseBatch(a.batch);
    const digest = batchDigest(chainId, settlement, a.batchId, a.batch);
    const same = chainId === cfg.chainId && settlement.toLowerCase() === client.settlement.toLowerCase();
    const contractDigest = same ? await client.batchDigest(a.batchId, a.batch) : undefined;
    return { chainId, settlement, batchId: a.batchId, digest, contractDigest, matchesContract: same ? contractDigest === digest : 'not checked (other deployment)',
      orders: groups.reduce((n, g) => n + g.count, 0), groups: groups.map(({ ordersAt: _o, ...g }) => g) };
  }));

  server.registerTool('build_batch', {
    title: 'Build a batch from signed actions',
    description: 'Reference batcher: takes signed actions (v1 JSON), drops invalid / expired / stale / non-contiguous ones and (with onChainChecks, default true) trims to the registry authorization, per-batch caps, trading balances and prepaid fee balance, then returns the prover input (batch-input/v1: packed batch, digest, groups with public keys and signatures) plus every excluded action with its reason. Read-only (no transaction).',
    inputSchema: {
      actions: z.array(z.union([z.string(), z.record(z.any())])).min(1).max(500).describe('signed action objects or JSON strings'),
      batchId: z.number().int().min(0),
      onChainChecks: z.boolean().optional().describe('default true; false = signatures and framing only'),
      minValiditySecs: z.number().int().min(0).optional().describe('drop actions expiring within this many seconds (time to prove + land)'),
      includeSignatures: z.boolean().optional().describe('default false: omit the large publicKey/signature hex from the response'),
    },
    annotations: READ,
  }, guard(async (a: { actions: (string | Record<string, unknown>)[]; batchId: number; onChainChecks?: boolean; minValiditySecs?: number; includeSignatures?: boolean }) => {
    const subs: Submission[] = a.actions.map((x, i) => {
      try { return [`#${i}`, (typeof x === 'string' ? JSON.parse(x) : x) as SignedAction]; } catch (e) { return [`#${i}`, e as Error]; }
    });
    const on = a.onChainChecks !== false;
    const b = await buildBatch(subs, { chainId: cfg.chainId, settlement: client.settlement, batchId: a.batchId, minValiditySecs: a.minValiditySecs },
      on ? new OnChainState(client) : new OfflineState(Math.floor(Date.now() / 1000)));
    b.stateChecks = on ? `on-chain via ${redactRpc(cfg.rpcUrl)} (registry ${(await client.registry()).toLowerCase()})` : 'offline (signatures and framing only)';
    if (a.includeSignatures) return b;
    return { ...b, groups: b.groups.map((g) => ({ ...g, publicKey: `${g.publicKey.slice(0, 18)}… (${(g.publicKey.length - 2) / 2} bytes)`, signatures: `${g.signatures.length} × 3309-byte ML-DSA-65 signatures (includeSignatures=true to return)` })) };
  }));

  // ------------------------------------------------------------------ write: unsigned transactions

  server.registerTool('prepare_register', {
    title: 'Prepare agent registration',
    description: `Build the AgentRegistry.selfRegister(pkHash, capBaseIn, capQuoteIn) transaction for a new agent key, with msg.value = registration fee + minimum bond (+ extraBond). Caps are per-batch spending limits; 0 = the registry maximum; above the maximum reverts. Checks open registration first. ${unsignedNote} After it confirms, the AgentRegistered event carries the new agentId (or call network_info: agentCount).`,
    inputSchema: {
      pkHash: canSign ? pkHash.optional().describe('agent key hash; default: the local keystore\'s pkHash') : pkHash,
      capBaseIn: amount('Per-batch cap on base token sold (0 = registry maximum)').optional(),
      capQuoteIn: amount('Per-batch cap on quote token spent (0 = registry maximum)').optional(),
      extraBond: amount('Extra bond above the minimum (refunded on retire)').optional(),
      ...broadcastParam,
    },
    annotations: canSend ? SEND : PREP,
  }, guard(async (a: { pkHash?: string; capBaseIn?: string; capQuoteIn?: string; extraBond?: string; broadcast?: boolean }) => {
    let pkh = a.pkHash; let local: Agent | undefined;
    if (!pkh) { if (!canSign) throw new Error('pkHash is required'); local = await Agent.open(cfg.keystoreDir!); pkh = local.config.pkHash; }
    const tx = await client.buildRegisterTx(pkh, { capBaseIn: a.capBaseIn ? parseAmount(a.capBaseIn) : 0n, capQuoteIn: a.capQuoteIn ? parseAmount(a.capQuoteIn) : 0n,
      extraBond: a.extraBond ? parseAmount(a.extraBond) : 0n });
    const r: any = await sendIfAsked([tx], a.broadcast);
    if (r._rcs) {
      const id = registeredId(r._rcs[0], await client.registry());
      r.agentId = id;
      if (local && id !== undefined && local.config.pkHash === pkh && local.config.agentId === undefined) { local.config.agentId = id; await local.save(); r.keystoreUpdated = true; }
    }
    return strip(r);
  }));

  server.registerTool('prepare_fund', {
    title: 'Prepare prepaid fee deposit',
    description: `Build the transaction(s) that add to an agent's prepaid settlement-fee balance: depositFeeNative{value} when the fee token is native MON, or approve + depositFeeToken for an ERC20 fee token (pass operator to skip an approve that is already sufficient). Anyone may fund any agent. ${unsignedNote}`,
    inputSchema: { agentId, amount: amount('Amount to deposit'), operator: address.optional().describe('the address that will sign (used only to check ERC20 allowance)'), ...broadcastParam },
    annotations: canSend ? SEND : PREP,
  }, guard(async (a: { agentId: number; amount: string; operator?: string; broadcast?: boolean }) =>
    strip(await sendIfAsked(await client.buildFundTxs(a.agentId, parseAmount(a.amount), a.operator ?? (a.broadcast ? cfg.operator?.address : undefined)), a.broadcast))));

  server.registerTool('prepare_deposit', {
    title: 'Prepare trading-balance deposit',
    description: `Build approve (as needed) + BatchSettlementV2.deposit(agentId, base, quote) to fund the agent's trading balances that its orders spend. ${unsignedNote}`,
    inputSchema: { agentId, base: amount('Base token amount').optional(), quote: amount('Quote token amount').optional(),
      operator: address.optional().describe('the address that will sign (used only to skip sufficient approvals)'), ...broadcastParam },
    annotations: canSend ? SEND : PREP,
  }, guard(async (a: { agentId: number; base?: string; quote?: string; operator?: string; broadcast?: boolean }) =>
    strip(await sendIfAsked(await client.buildDepositTxs(a.agentId, a.base ? parseAmount(a.base) : 0n, a.quote ? parseAmount(a.quote) : 0n,
      a.operator ?? (a.broadcast ? cfg.operator?.address : undefined)), a.broadcast))));

  server.registerTool('prepare_set_alert', {
    title: 'Prepare low-balance alert',
    description: `Build setFeeAlert(agentId, threshold) (+ optional setAutoTopUp for ERC20 fee tokens): the contract emits LowFeeBalance once when the prepaid balance drops below the threshold, so a watcher or keeper can top up. Must be sent by the agent's operator. ${unsignedNote}`,
    inputSchema: { agentId, threshold: amount('Alert threshold (0 = off)'), autoTopUp: amount('ERC20 auto top-up amount per topUp() (0 = off)').optional(), ...broadcastParam },
    annotations: canSend ? SEND : PREP,
  }, guard(async (a: { agentId: number; threshold: string; autoTopUp?: string; broadcast?: boolean }) =>
    strip(await sendIfAsked(client.buildSetAlertTxs(a.agentId, parseAmount(a.threshold), a.autoTopUp ? parseAmount(a.autoTopUp) : undefined), a.broadcast))));

  // ------------------------------------------------------------------ local keystore (stdio only)

  if (canSign) {
    server.registerTool('local_agent', {
      title: 'Local agent keystore',
      description: 'The local agent keystore this server signs with (PQAGENT_DIR): agentId, pkHash, modelHash, chain/settlement, next nonce, and whether its key is authorized on chain. Never returns key material.',
      inputSchema: {},
      annotations: READ,
    }, guard(async () => {
      const a = await Agent.open(cfg.keystoreDir!);
      const { rpc: _r, ...c } = a.config;
      const st = a.config.agentId !== undefined ? await client.agentStatus(a.config.agentId, a.config.pkHash) : undefined;
      return { ...c, authorized: st?.authorized ?? false, lastNonce: st?.lastNonce, nextNonce: Math.max(a.config.nextNonce, (st?.lastNonce ?? 0) + 1) };
    }));

    server.registerTool('sign_action', {
      title: 'Sign an order with the local agent key',
      description: 'LOCAL MODE: ML-DSA-65 sign one order with the local agent keystore (PQAGENT_DIR, passphrase from PQAGENT_PASSPHRASE) and return the signed-action v1 JSON (public key + signature, never the private key). The nonce defaults to max(local counter, on-chain lastNonce + 1); expiry defaults to now + ttlSecs rounded up to the keystore\'s expiry bucket. Optionally also writes it to outDir as <agentId>-<nonce>.json for the batcher. This commits the agent to the order if submitted: confirm with the user.',
      inputSchema: {
        side: z.enum(['buy', 'sell']).describe('buy = spend quote for base; sell = sell base for quote'),
        amountIn: amount('Order input amount (> 0, < 2^96)'),
        minAmountOut: amount('Slippage bound: minimum output. Required (audit M-02): with 0 the order can be sandwiched for its whole value; pass "0" only deliberately.'),
        nonce: z.number().int().min(1).optional(),
        expiry: z.number().int().min(0).max(0xffffffff).optional().describe('absolute unix seconds'),
        ttlSecs: z.number().int().min(60).max(31_536_000).optional().describe('default 3600'),
        outDir: z.string().optional().describe('directory to also write the JSON into'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    }, guard(async (a: { side: 'buy' | 'sell'; amountIn: string; minAmountOut: string; nonce?: number; expiry?: number; ttlSecs?: number; outDir?: string }) => {
      const ag = await Agent.open(cfg.keystoreDir!, { passphrase: cfg.keystorePassphrase, rpc: cfg.rpcUrl });
      const { action, path } = await ag.sign({ buyBase: a.side === 'buy', amountIn: parseAmount(a.amountIn), minAmountOut: parseAmount(a.minAmountOut) },
        { nonce: a.nonce, expiry: a.expiry, ttl: a.ttlSecs, out: a.outDir });
      return { signedAction: action, writtenTo: path };
    }));
  }

  return server;
}
