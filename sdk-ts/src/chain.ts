/**
 * Chain access with viem: read-only views (registry, fees, digest) and *unsigned* transaction builders
 * (register / fund / deposit / alert) that any wallet can sign, plus an optional local sender.
 * Mirrors `sdk/src/chain.rs` + the chain half of `sdk/src/agent.rs`.
 */
import {
  createPublicClient, createWalletClient, decodeEventLog, defineChain, encodeFunctionData, http, parseAbi,
  type Account, type Address, type Chain, type PublicClient, type TransactionReceipt,
} from 'viem';
import { type Hex, hex0x, unhexN } from './bytes.js';
import { MAX_U96 } from './action.js';

export const registryAbi = parseAbi([
  'function selfRegister(bytes32 pkHash, uint128 capBaseIn, uint128 capQuoteIn) payable returns (uint32 id)',
  'function registrationFee() view returns (uint96)',
  'function minStake() view returns (uint96)',
  'function openRegistration() view returns (bool)',
  'function defaultCapBaseIn() view returns (uint128)',
  'function defaultCapQuoteIn() view returns (uint128)',
  'function admin() view returns (address)',
  'function treasury() view returns (address)',
  'function agentCount() view returns (uint32)',
  'function isAuthorized(uint32 id, bytes32 pkHash) view returns (bool)',
  'function isAgentKey(uint32 id, bytes32 pkHash) view returns (bool)',
  'function keyCount(uint32 id) view returns (uint32)',
  'function agents(uint32 id) view returns (address operator, bool active, bool killed, uint96 stake, uint128 capBaseIn, uint128 capQuoteIn)',
  'event AgentRegistered(uint32 indexed agentId, address operator, bytes32 pkHash, uint96 stake)',
  'error NotAdmin()', 'error NotAuthorised()', 'error UnknownAgent(uint32 agentId)', 'error AgentKilled(uint32 agentId)',
  'error UnknownKey(uint32 agentId, bytes32 pkHash)', 'error StakeTooLow(uint256 sent, uint256 min)', 'error RegistrationClosed()',
  'error CapsTooHigh(uint128 capBaseIn, uint128 capQuoteIn, uint128 maxBaseIn, uint128 maxQuoteIn)', 'error ZeroValue()',
]);

export const settlementAbi = parseAbi([
  'function registry() view returns (address)',
  'function base() view returns (address)',
  'function quote() view returns (address)',
  'function pool() view returns (address)',
  'function verifier() view returns (address)',
  'function batchProgramVKey() view returns (bytes32)',
  'function agentState(uint32 id) view returns (uint96 base, uint96 quote, uint64 lastNonce)',
  'function deposit(uint32 agentId, uint96 baseAmt, uint96 quoteAmt)',
  'function feeToken(uint8 idx) view returns (address)',
  'function feeConfig(uint8 idx) view returns (uint72 feePerAction, uint72 maxFeePerBatch, bool enabled, uint104 accrued)',
  'function feeAccount(uint32 id) view returns (uint96 balance, uint96 threshold, uint8 token, bool low)',
  'function autoTopUp(uint32 id) view returns (address from, uint96 amount)',
  'function pendingFeeWithdrawal(uint32 id) view returns (uint96 amount, uint64 readyAt, address to)',
  'function feeQuote(uint32 id, uint256 actions) view returns (uint256)',
  'function remainingActions(uint32 id) view returns (uint256)',
  'function selectFeeToken(uint32 id, uint8 idx)',
  'function depositFeeNative(uint32 id) payable',
  'function depositFeeToken(uint32 id, uint256 amount)',
  'function setFeeAlert(uint32 id, uint96 threshold)',
  'function setAutoTopUp(uint32 id, uint96 amount)',
  'function batchDigest(uint64 batchId, bytes batch) view returns (bytes32)',
  'event LowFeeBalance(uint32 indexed agentId, uint256 balance, uint256 threshold)',
  'error NotOperator()', 'error UnknownAgent(uint32 agentId)', 'error FeeTokenNotEnabled(uint8 token)',
  'error WrongFeeToken(uint32 agentId, uint8 token)', 'error FeeAccountNotEmpty(uint32 agentId)',
  'error InsufficientFeeBalance(uint32 agentId, uint256 balance, uint256 fee)', 'error BadFeeToken(uint8 token)',
  'error InsufficientBalance(uint32 agentId)', 'error AmountTooLarge()',
]);

export const erc20Abi = parseAbi([
  'function approve(address spender, uint256 amount) returns (bool)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function balanceOf(address who) view returns (uint256)',
  'function symbol() view returns (string)',
]);

/** Live Monad Solonet stack (local devnet, chain 20143) used by this repo's results. */
export const SOLONET = {
  chainId: 20143,
  rpcUrl: 'http://localhost:8080',
  settlement: '0x0e1AD57BFb7E25656dE899571BE624559d871D10' as Address,
  registry: '0x28ef4A35d2618A7EdDB46D7c71634B8eDA7c0ABF' as Address,
} as const;

export interface NetworkConfig {
  chainId: number;
  rpcUrl: string;
  settlement: Address | string;
  /** default: settlement.registry() */
  registry?: Address | string;
  name?: string;
}

/** An unsigned transaction any wallet (or `eth_sendTransaction`) can sign. `value` is a decimal wei string. */
export interface UnsignedTx {
  chainId: number;
  to: Address;
  data: Hex;
  value: string;
  /** human description of what this tx does */
  description: string;
}

export function chainFor(n: NetworkConfig): Chain {
  return defineChain({
    id: n.chainId, name: n.name ?? (n.chainId === 20143 ? 'Monad Solonet' : n.chainId === 143 ? 'Monad' : `chain ${n.chainId}`),
    nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 },
    rpcUrls: { default: { http: [n.rpcUrl] } },
  });
}

const U256_MAX = (1n << 256n) - 1n;
const asAddr = (a: string) => hex0x(unhexN(a, 20, 'address')) as Address;
const asB32 = (h: string | Uint8Array) => (typeof h === 'string' ? hex0x(unhexN(h, 32, 'bytes32')) : hex0x(h)) as Hex;
const u96 = (v: bigint, what: string) => { if (v < 0n || v > MAX_U96) throw new Error(`${what} must fit uint96`); return v; };

export interface RegistryInfo {
  registry: Address; settlement: Address; chainId: number;
  openRegistration: boolean; registrationFee: string; minStake: string;
  maxCapBaseIn: string; maxCapQuoteIn: string; agentCount: number; admin: Address; treasury: Address;
  base: Address; quote: Address; batchProgramVKey: Hex;
  feePerActionNative: string; maxFeePerBatchNative: string;
}

export interface AgentStatus {
  agentId: number; registered: boolean; operator: Address; active: boolean; killed: boolean;
  /** only when a pkHash was given */
  pkHash?: Hex; authorized?: boolean;
  keyCount: number; stake: string; capBaseIn: string; capQuoteIn: string;
  lastNonce: number; nextNonce: number; feeBalance: string; remainingActions: string;
  tradingBase: string; tradingQuote: string;
}

export interface FeeBalance {
  agentId: number; feeTokenIndex: number; feeToken: string; feeBalance: string; alertThreshold: string; low: boolean;
  feePerAction: string; maxFeePerBatch: string;
  /** lower bound; "unlimited" when the fee is zero */
  remainingActions: string; autoTopUpAmount: string; autoTopUpFrom: Address; pendingWithdrawal: string;
  tradingBase: string; tradingQuote: string; lastNonce: number;
}

/** Read/compose client for one deployment. No keys. */
export class PqClient {
  readonly net: NetworkConfig;
  readonly chain: Chain;
  readonly public: PublicClient;
  readonly settlement: Address;
  #registry?: Address;

  constructor(net: NetworkConfig, publicClient?: PublicClient) {
    this.net = net;
    this.chain = chainFor(net);
    this.public = publicClient ?? (createPublicClient({ chain: this.chain, transport: http(net.rpcUrl, { timeout: 30_000 }) }) as PublicClient);
    this.settlement = asAddr(String(net.settlement));
    if (net.registry) this.#registry = asAddr(String(net.registry));
  }

  /** Fails unless the RPC's chainId matches the configured one. */
  async checkChain(): Promise<void> {
    const id = await this.public.getChainId();
    if (id !== this.net.chainId) throw new Error(`rpc chainId ${id} != configured chainId ${this.net.chainId}`);
  }

  async registry(): Promise<Address> {
    if (!this.#registry) this.#registry = await this.s('registry');
    return this.#registry as Address;
  }

  private s(fn: any, args?: readonly unknown[]): Promise<any> {
    return this.public.readContract({ address: this.settlement, abi: settlementAbi, functionName: fn, args: args as any });
  }
  private async r(fn: any, args?: readonly unknown[]): Promise<any> {
    return this.public.readContract({ address: await this.registry(), abi: registryAbi, functionName: fn, args: args as any });
  }

  async registryInfo(): Promise<RegistryInfo> {
    const reg = await this.registry();
    const [open, fee, stake, cb, cq, count, admin, treasury, base, quote, vkey, fc] = await Promise.all([
      this.r('openRegistration'), this.r('registrationFee'), this.r('minStake'), this.r('defaultCapBaseIn'), this.r('defaultCapQuoteIn'),
      this.r('agentCount'), this.r('admin'), this.r('treasury'), this.s('base'), this.s('quote'), this.s('batchProgramVKey'), this.s('feeConfig', [0]),
    ]);
    return {
      registry: reg, settlement: this.settlement, chainId: this.net.chainId, openRegistration: open,
      registrationFee: fee.toString(), minStake: stake.toString(), maxCapBaseIn: cb.toString(), maxCapQuoteIn: cq.toString(),
      agentCount: Number(count), admin, treasury, base, quote, batchProgramVKey: vkey,
      feePerActionNative: fc[0].toString(), maxFeePerBatchNative: fc[1].toString(),
    };
  }

  async isAuthorized(agentId: number, pkHash: Hex | string | Uint8Array): Promise<boolean> {
    return this.r('isAuthorized', [agentId, asB32(pkHash)]);
  }

  async agentStatus(agentId: number, pkHash?: Hex | string | Uint8Array): Promise<AgentStatus> {
    const [a, kc, st, fa, rem] = await Promise.all([
      this.r('agents', [agentId]), this.r('keyCount', [agentId]), this.s('agentState', [agentId]),
      this.s('feeAccount', [agentId]), this.s('remainingActions', [agentId]),
    ]);
    const out: AgentStatus = {
      agentId, registered: a[0] !== '0x0000000000000000000000000000000000000000', operator: a[0], active: a[1], killed: a[2],
      keyCount: Number(kc), stake: a[3].toString(), capBaseIn: a[4].toString(), capQuoteIn: a[5].toString(),
      lastNonce: Number(st[2]), nextNonce: Number(st[2]) + 1, feeBalance: fa[0].toString(),
      remainingActions: rem === U256_MAX ? 'unlimited' : rem.toString(), tradingBase: st[0].toString(), tradingQuote: st[1].toString(),
    };
    if (pkHash !== undefined) { out.pkHash = asB32(pkHash); out.authorized = await this.isAuthorized(agentId, pkHash); }
    return out;
  }

  async feeQuote(agentId: number, actions: number | bigint): Promise<bigint> {
    return this.s('feeQuote', [agentId, BigInt(actions)]);
  }

  async feeBalance(agentId: number): Promise<FeeBalance> {
    const [fa, rem, at, pw, st] = await Promise.all([
      this.s('feeAccount', [agentId]), this.s('remainingActions', [agentId]), this.s('autoTopUp', [agentId]),
      this.s('pendingFeeWithdrawal', [agentId]), this.s('agentState', [agentId]),
    ]);
    const fc = await this.s('feeConfig', [fa[2]]);
    const tok = fa[2] === 0 ? 'native MON' : await this.s('feeToken', [fa[2]]);
    return {
      agentId, feeTokenIndex: fa[2], feeToken: tok, feeBalance: fa[0].toString(), alertThreshold: fa[1].toString(), low: fa[3],
      feePerAction: fc[0].toString(), maxFeePerBatch: fc[1].toString(),
      remainingActions: rem === U256_MAX ? 'unlimited' : rem.toString(),
      autoTopUpAmount: at[1].toString(), autoTopUpFrom: at[0],
      pendingWithdrawal: pw[0] === 0n ? 'none' : `${pw[0]} ready at ${pw[1]}`,
      tradingBase: st[0].toString(), tradingQuote: st[1].toString(), lastNonce: Number(st[2]),
    };
  }

  /** settlement.batchDigest(batchId, batch) — the contract's own digest of a packed batch. */
  async batchDigest(batchId: number | bigint, batch: Hex | string): Promise<Hex> {
    return this.s('batchDigest', [BigInt(batchId), hex0x(Buffer.from(batch.replace(/^0x/, ''), 'hex'))]);
  }

  async now(): Promise<bigint> {
    return (await this.public.getBlock({ blockTag: 'latest' })).timestamp;
  }

  // ------------------------------------------------------------ unsigned transaction builders

  /**
   * selfRegister(pkHash, caps) with msg.value = registrationFee + minStake + extraBond.
   * cap 0 = the registry maximum. Fails early if open registration is disabled or caps exceed the maximum.
   */
  async buildRegisterTx(pkHash: Hex | string | Uint8Array, o: { capBaseIn?: bigint; capQuoteIn?: bigint; extraBond?: bigint } = {}): Promise<UnsignedTx> {
    const reg = await this.registry();
    const [open, fee, stake, mb, mq] = await Promise.all([
      this.r('openRegistration'), this.r('registrationFee'), this.r('minStake'), this.r('defaultCapBaseIn'), this.r('defaultCapQuoteIn'),
    ]);
    if (!open) throw new Error(`registry ${reg} has open registration disabled (ask the admin)`);
    const cb = o.capBaseIn ?? 0n; const cq = o.capQuoteIn ?? 0n;
    if (cb > mb || cq > mq) throw new Error(`caps above the registry maximum (base ${mb}, quote ${mq}) would revert CapsTooHigh`);
    const value = fee + stake + (o.extraBond ?? 0n);
    return {
      chainId: this.net.chainId, to: reg, value: value.toString(),
      data: encodeFunctionData({ abi: registryAbi, functionName: 'selfRegister', args: [asB32(pkHash), cb, cq] }),
      description: `selfRegister pkHash ${asB32(pkHash)} caps base ${cb || mb} quote ${cq || mq}; pays registrationFee ${fee} + bond ${stake + (o.extraBond ?? 0n)} wei`,
    };
  }

  /**
   * Prepaid fee deposit in the agent's fee token: native MON -> depositFeeNative{value};
   * ERC20 -> [approve (when `operator` is given and its allowance is short, or always when unknown)], depositFeeToken.
   */
  async buildFundTxs(agentId: number, amount: bigint, operator?: Address | string): Promise<UnsignedTx[]> {
    if (amount <= 0n) throw new Error('amount must be > 0');
    const fa = await this.s('feeAccount', [agentId]);
    const c = this.net.chainId;
    if (fa[2] === 0) {
      return [{ chainId: c, to: this.settlement, value: amount.toString(),
        data: encodeFunctionData({ abi: settlementAbi, functionName: 'depositFeeNative', args: [agentId] }),
        description: `depositFeeNative(agent ${agentId}) ${amount} wei MON` }];
    }
    const token: Address = await this.s('feeToken', [fa[2]]);
    const out: UnsignedTx[] = [];
    const have = operator ? await this.public.readContract({ address: token, abi: erc20Abi, functionName: 'allowance', args: [asAddr(String(operator)), this.settlement] }) : 0n;
    if (have < amount) out.push({ chainId: c, to: token, value: '0', description: `approve settlement to pull ${amount} fee token`,
      data: encodeFunctionData({ abi: erc20Abi, functionName: 'approve', args: [this.settlement, amount] }) });
    out.push({ chainId: c, to: this.settlement, value: '0', description: `depositFeeToken(agent ${agentId}, ${amount})`,
      data: encodeFunctionData({ abi: settlementAbi, functionName: 'depositFeeToken', args: [agentId, amount] }) });
    return out;
  }

  /** Trading balances (base/quote ERC20) the agent's orders spend: approvals as needed, then deposit. */
  async buildDepositTxs(agentId: number, baseAmt: bigint, quoteAmt: bigint, operator?: Address | string): Promise<UnsignedTx[]> {
    u96(baseAmt, 'base'); u96(quoteAmt, 'quote');
    if (baseAmt === 0n && quoteAmt === 0n) throw new Error('nothing to deposit');
    const [base, quote] = await Promise.all([this.s('base'), this.s('quote')]);
    const c = this.net.chainId; const out: UnsignedTx[] = [];
    for (const [amt, tok, name] of [[baseAmt, base, 'base'], [quoteAmt, quote, 'quote']] as const) {
      if (amt === 0n) continue;
      const have = operator ? await this.public.readContract({ address: tok, abi: erc20Abi, functionName: 'allowance', args: [asAddr(String(operator)), this.settlement] }) : 0n;
      if (have < amt) out.push({ chainId: c, to: tok, value: '0', description: `approve settlement to pull ${amt} ${name}`,
        data: encodeFunctionData({ abi: erc20Abi, functionName: 'approve', args: [this.settlement, amt] }) });
    }
    out.push({ chainId: c, to: this.settlement, value: '0', description: `deposit(agent ${agentId}, base ${baseAmt}, quote ${quoteAmt})`,
      data: encodeFunctionData({ abi: settlementAbi, functionName: 'deposit', args: [agentId, baseAmt, quoteAmt] }) });
    return out;
  }

  /** LowFeeBalance alert threshold (+ optional ERC20 auto top-up amount). Operator-only on chain. */
  buildSetAlertTxs(agentId: number, threshold: bigint, autoTopUp?: bigint): UnsignedTx[] {
    const c = this.net.chainId;
    const out: UnsignedTx[] = [{ chainId: c, to: this.settlement, value: '0', description: `setFeeAlert(agent ${agentId}, ${threshold})`,
      data: encodeFunctionData({ abi: settlementAbi, functionName: 'setFeeAlert', args: [agentId, u96(threshold, 'threshold')] }) }];
    if (autoTopUp !== undefined) out.push({ chainId: c, to: this.settlement, value: '0', description: `setAutoTopUp(agent ${agentId}, ${autoTopUp})`,
      data: encodeFunctionData({ abi: settlementAbi, functionName: 'setAutoTopUp', args: [agentId, u96(autoTopUp, 'autoTopUp')] }) });
    return out;
  }

  // ------------------------------------------------------------ local sending (operator key stays in-process)

  /**
   * Sign and send prepared txs in order with a local viem Account, waiting for each receipt and failing
   * on revert. Gas limit = eth_estimateGas (Monad charges the limit, not gas used).
   */
  async sendTxs(account: Account, txs: UnsignedTx[]): Promise<TransactionReceipt[]> {
    await this.checkChain();
    const wallet = createWalletClient({ account, chain: this.chain, transport: http(this.net.rpcUrl, { timeout: 30_000 }) });
    const out: TransactionReceipt[] = [];
    for (const tx of txs) {
      if (tx.chainId !== this.net.chainId) throw new Error(`tx for chain ${tx.chainId}, client on ${this.net.chainId}`);
      const gas = await this.public.estimateGas({ account, to: tx.to, data: tx.data, value: BigInt(tx.value) });
      const hash = await wallet.sendTransaction({ to: tx.to, data: tx.data, value: BigInt(tx.value), gas, chain: this.chain, account });
      const rc = await this.public.waitForTransactionReceipt({ hash, timeout: 120_000, pollingInterval: 300 });
      if (rc.status !== 'success') throw new Error(`transaction ${hash} reverted (${tx.description})`);
      out.push(rc);
    }
    return out;
  }
}

/** Agent id from the AgentRegistered log of a selfRegister receipt. */
export function registeredId(rc: TransactionReceipt, registry: Address): number | undefined {
  for (const l of rc.logs) {
    if (l.address.toLowerCase() !== registry.toLowerCase()) continue;
    try {
      const ev = decodeEventLog({ abi: registryAbi, data: l.data, topics: l.topics });
      if (ev.eventName === 'AgentRegistered') return Number(ev.args.agentId);
    } catch { /* other event */ }
  }
  return undefined;
}
