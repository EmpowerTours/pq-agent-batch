// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import { AgentRegistry } from "./AgentRegistry.sol";

/// @title  AgentFees: prepaid per-agent fee balances for the batch settlement
/// @notice Each agent has ONE fee account (one storage slot) denominated in one fee token:
///         native MON (token index 0) or an admin-listed ERC20 (index 1..3). Anyone may deposit
///         for an agent; only the agent's operator (its owner in the registry) can withdraw, set a
///         low-balance alert threshold, switch token (when empty), or configure auto top-up.
///
///         Settlement charges `min(actions * feePerAction, maxFeePerBatch)` per agent group, in the
///         agent's fee token. Fees are summed in memory and written once per agent and once per
///         token per batch; they accrue here and `sweepFees` sends them to `registry.treasury()`.
///
///         If an agent's fee balance cannot cover its group, the WHOLE batch reverts with
///         `InsufficientFeeBalance(agentId, balance, fee)`: nothing is settled for free, and the
///         service must re-batch without that agent. Services check `feeQuote` / `feeAccount`
///         (minus any pending withdrawal) BEFORE proving.
///
///         Alerts: when a settlement (or a withdrawal) takes the balance below the owner's
///         threshold, `LowFeeBalance` is emitted ONCE; it re-arms only after the balance is back
///         at or above the threshold (deposit, top-up, or threshold change).
///
///         Auto top-up (ERC20 only): the owner sets an amount and approves this contract; anyone
///         (a keeper) can then call `topUp(agentId)` while that agent is below threshold. It pulls
///         exactly the configured amount from the address that configured it, into that agent's
///         balance only. Settlement itself never pulls funds, so a revoked allowance cannot break
///         a batch.
abstract contract AgentFees is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    uint8   public constant MAX_FEE_TOKENS = 4;      // index 0 = native MON
    uint64  public constant MAX_WITHDRAW_DELAY = 7 days;

    struct FeeConfig {          // per fee token, ONE slot: config + the treasury's accrued fees, so a
        uint72  feePerAction;   //   batch reads it once (cold) and writes it once (warm)
        uint72  maxFeePerBatch; // cap per agent per batch; 0 = uncapped
        bool    enabled;        // accepts new deposits / selection
        uint104 accrued;        // charged and not yet swept to the treasury
    }

    struct FeeAccount {       // per agent, ONE slot: read once and written at most once per batch
        uint96 balance;
        uint96 threshold;     // owner's low-balance alert level (0 = no alerts)
        uint8  token;         // fee token index
        bool   low;           // LowFeeBalance already emitted for the current crossing
    }

    struct AutoTopUp {
        address from;         // the operator that configured it; the only address ever pulled from
        uint96  amount;       // pulled per topUp() call; 0 = disabled
    }

    struct PendingWithdrawal {
        uint96  amount;
        uint64  readyAt;
        address to;
    }

    AgentRegistry public immutable registry;

    mapping(uint8 => address) public feeToken;              // index -> ERC20 (index 0 = native, address(0))
    mapping(uint8 => FeeConfig) public feeConfig;
    mapping(uint32 => FeeAccount) public feeAccount;
    mapping(uint32 => AutoTopUp) public autoTopUp;
    mapping(uint32 => PendingWithdrawal) public pendingFeeWithdrawal;
    uint64 public feeWithdrawDelay;

    event FeeTokenListed(uint8 indexed token, address erc20);
    event FeeConfigSet(uint8 indexed token, uint72 feePerAction, uint72 maxFeePerBatch, bool enabled);
    event FeeWithdrawDelaySet(uint64 delay);
    event FeeTokenSelected(uint32 indexed agentId, uint8 token);
    event FeeDeposited(uint32 indexed agentId, uint8 token, uint256 amount, address from);
    event FeeWithdrawalRequested(uint32 indexed agentId, uint256 amount, address to, uint64 readyAt);
    event FeeWithdrawalCancelled(uint32 indexed agentId);
    event FeeWithdrawn(uint32 indexed agentId, uint256 amount, address to);
    event FeeAlertSet(uint32 indexed agentId, uint96 threshold);
    event AutoTopUpSet(uint32 indexed agentId, address from, uint96 amount);
    event ToppedUp(uint32 indexed agentId, uint256 amount, address keeper);
    event LowFeeBalance(uint32 indexed agentId, uint256 balance, uint256 threshold);
    event FeesCharged(uint64 indexed batchId, uint8 indexed token, uint256 amount);
    event FeesSwept(uint8 indexed token, uint256 amount, address treasury);

    error NotAdmin();
    error NotOperator();
    error UnknownAgent(uint32 agentId);
    error BadFeeToken(uint8 token);
    error FeeTokenNotEnabled(uint8 token);
    error WrongFeeToken(uint32 agentId, uint8 token);
    error FeeAccountNotEmpty(uint32 agentId);
    error InsufficientFeeBalance(uint32 agentId, uint256 balance, uint256 fee);
    error WithdrawalNotReady(uint64 readyAt);
    error NoPendingWithdrawal();
    error DelayTooLong();
    error TopUpDisabled(uint32 agentId);
    error NotBelowThreshold(uint32 agentId, uint256 balance, uint256 threshold);
    error NativeTransferFailed();

    constructor(AgentRegistry _registry) {
        registry = _registry;
    }

    // ------------------------------------------------------------ access helpers

    modifier onlyAdmin() {
        if (msg.sender != registry.admin()) revert NotAdmin();
        _;
    }

    function _operator(uint32 id) internal view returns (address operator, bool active) {
        (operator, active,,,,) = registry.agents(id);
    }

    modifier onlyOperator(uint32 id) {
        (address op,) = _operator(id);
        if (msg.sender != op) revert NotOperator();
        _;
    }

    // ------------------------------------------------------------ admin

    /// @notice List an ERC20 as fee token `idx` (1..3). Write-once, so balances can never change denomination.
    function listFeeToken(uint8 idx, address erc20) external onlyAdmin {
        if (idx == 0 || idx >= MAX_FEE_TOKENS || erc20 == address(0) || feeToken[idx] != address(0)) {
            revert BadFeeToken(idx);
        }
        feeToken[idx] = erc20;
        emit FeeTokenListed(idx, erc20);
    }

    function setFeeConfig(uint8 idx, uint72 feePerAction, uint72 maxFeePerBatch, bool enabled) external onlyAdmin {
        if (idx >= MAX_FEE_TOKENS || (idx != 0 && feeToken[idx] == address(0))) revert BadFeeToken(idx);
        FeeConfig storage c = feeConfig[idx];
        (c.feePerAction, c.maxFeePerBatch, c.enabled) = (feePerAction, maxFeePerBatch, enabled);
        emit FeeConfigSet(idx, feePerAction, maxFeePerBatch, enabled);
    }

    function setFeeWithdrawDelay(uint64 delay) external onlyAdmin {
        if (delay > MAX_WITHDRAW_DELAY) revert DelayTooLong();
        feeWithdrawDelay = delay;
        emit FeeWithdrawDelaySet(delay);
    }

    /// @notice Permissionless: send accrued fees of one token to the registry's treasury.
    function sweepFees(uint8 idx) external nonReentrant {
        uint256 amt = feeConfig[idx].accrued;
        address treasury = registry.treasury();
        feeConfig[idx].accrued = 0;
        emit FeesSwept(idx, amt, treasury);
        _send(idx, treasury, amt);
    }

    // ------------------------------------------------------------ owner / depositor

    function selectFeeToken(uint32 id, uint8 idx) external onlyOperator(id) {
        FeeAccount storage a = feeAccount[id];
        if (a.balance != 0 || pendingFeeWithdrawal[id].amount != 0) revert FeeAccountNotEmpty(id);
        if (idx >= MAX_FEE_TOKENS) revert BadFeeToken(idx);
        if (!feeConfig[idx].enabled) revert FeeTokenNotEnabled(idx);
        a.token = idx;
        emit FeeTokenSelected(id, idx);
    }

    /// @notice Deposit native MON into an agent's fee balance (agent's fee token must be index 0).
    function depositFeeNative(uint32 id) external payable nonReentrant {
        _credit(id, 0, msg.value);
    }

    /// @notice Deposit the agent's ERC20 fee token (pulled from msg.sender).
    function depositFeeToken(uint32 id, uint256 amount) external nonReentrant {
        uint8 t = feeAccount[id].token;
        if (t == 0) revert WrongFeeToken(id, t);
        IERC20(feeToken[t]).safeTransferFrom(msg.sender, address(this), amount);
        _credit(id, t, amount);
    }

    /// @notice Start a withdrawal; executable after `feeWithdrawDelay`. Until then the balance still
    ///         pays for batches, so a batch proved against it cannot be griefed by a sudden withdrawal.
    function requestFeeWithdrawal(uint32 id, uint96 amount, address to) external onlyOperator(id) {
        uint64 readyAt = uint64(block.timestamp) + feeWithdrawDelay;
        pendingFeeWithdrawal[id] = PendingWithdrawal(amount, readyAt, to);
        emit FeeWithdrawalRequested(id, amount, to, readyAt);
    }

    function cancelFeeWithdrawal(uint32 id) external onlyOperator(id) {
        delete pendingFeeWithdrawal[id];
        emit FeeWithdrawalCancelled(id);
    }

    /// @notice Pays out min(requested, current balance) to the address named in the request.
    function executeFeeWithdrawal(uint32 id) external nonReentrant onlyOperator(id) {
        PendingWithdrawal memory w = pendingFeeWithdrawal[id];
        if (w.amount == 0) revert NoPendingWithdrawal();
        if (block.timestamp < w.readyAt) revert WithdrawalNotReady(w.readyAt);
        delete pendingFeeWithdrawal[id];
        FeeAccount memory a = feeAccount[id];
        uint96 amt = w.amount < a.balance ? w.amount : a.balance;
        a.balance -= amt;
        _storeAccount(id, a);
        emit FeeWithdrawn(id, amt, w.to);
        _send(a.token, w.to, amt);
    }

    /// @notice Low-balance alert level. Setting it above the current balance alerts immediately.
    function setFeeAlert(uint32 id, uint96 threshold) external onlyOperator(id) {
        FeeAccount memory a = feeAccount[id];
        a.threshold = threshold;
        if (a.balance >= threshold) a.low = false;
        _storeAccount(id, a);
        emit FeeAlertSet(id, threshold);
    }

    /// @notice Pre-authorise keepers to pull `amount` of the agent's ERC20 fee token from msg.sender
    ///         whenever the agent is below threshold. Also needs an ERC20 approval to this contract,
    ///         which bounds the total that can ever be pulled. amount = 0 disables.
    function setAutoTopUp(uint32 id, uint96 amount) external onlyOperator(id) {
        autoTopUp[id] = AutoTopUp(msg.sender, amount);
        emit AutoTopUpSet(id, msg.sender, amount);
    }

    /// @notice Permissionless keeper hook. Only while the agent is below its threshold; pulls exactly the
    ///         configured amount from the configured owner address into THIS agent's fee balance.
    function topUp(uint32 id) external nonReentrant {
        AutoTopUp memory cfg = autoTopUp[id];
        if (cfg.amount == 0) revert TopUpDisabled(id);
        FeeAccount memory a = feeAccount[id];
        if (a.token == 0) revert WrongFeeToken(id, 0);
        if (a.balance >= a.threshold) revert NotBelowThreshold(id, a.balance, a.threshold);
        IERC20(feeToken[a.token]).safeTransferFrom(cfg.from, address(this), cfg.amount);
        a.balance += cfg.amount;                       // checked
        if (a.balance >= a.threshold) a.low = false;
        feeAccount[id] = a;
        emit ToppedUp(id, cfg.amount, msg.sender);
    }

    // ------------------------------------------------------------ views

    /// @notice Fees charged in token `idx` and not yet swept to the treasury.
    function accruedFees(uint8 idx) external view returns (uint256) {
        return feeConfig[idx].accrued;
    }

    /// @notice Fee settlement would charge agent `id` for `actions` orders in one batch.
    function feeQuote(uint32 id, uint256 actions) public view returns (uint256 fee) {
        FeeConfig memory c = feeConfig[feeAccount[id].token];
        fee = actions * c.feePerAction;
        if (c.maxFeePerBatch != 0 && fee > c.maxFeePerBatch) fee = c.maxFeePerBatch;
    }

    /// @notice Lower bound on how many more actions the current balance pays for (per-batch caps
    ///         can only make actions cheaper). type(uint256).max when the fee is zero.
    function remainingActions(uint32 id) external view returns (uint256) {
        FeeAccount memory a = feeAccount[id];
        uint256 f = feeConfig[a.token].feePerAction;
        return f == 0 ? type(uint256).max : a.balance / f;
    }

    // ------------------------------------------------------------ internals

    function _credit(uint32 id, uint8 t, uint256 amount) private {
        (, bool active) = _operator(id);
        if (!active) revert UnknownAgent(id);
        FeeAccount memory a = feeAccount[id];
        if (a.token != t) revert WrongFeeToken(id, t);
        if (!feeConfig[t].enabled) revert FeeTokenNotEnabled(t);
        a.balance += SafeCastU96.u96(amount);          // checked add
        if (a.balance >= a.threshold) a.low = false;   // re-arm the alert
        feeAccount[id] = a;
        emit FeeDeposited(id, t, amount, msg.sender);
    }

    /// Stores an account after a debit/threshold change; emits LowFeeBalance on a downward crossing.
    function _storeAccount(uint32 id, FeeAccount memory a) internal {
        if (a.balance < a.threshold && !a.low) {
            a.low = true;
            emit LowFeeBalance(id, a.balance, a.threshold);
        }
        feeAccount[id] = a;
    }

    function _send(uint8 t, address to, uint256 amt) private {
        if (amt == 0) return;
        if (t == 0) {
            (bool ok,) = payable(to).call{ value: amt }("");
            if (!ok) revert NativeTransferFailed();
        } else {
            IERC20(feeToken[t]).safeTransfer(to, amt);
        }
    }

    // ------------------------------------------------------------ settlement hot path

    /// Per-batch fee context, kept in memory: each token's config is read at most once per batch.
    struct FeeCtx {
        uint256 loaded;               // bitmask of token configs loaded
        uint256[MAX_FEE_TOKENS] perAction;
        uint256[MAX_FEE_TOKENS] cap;
        uint256[MAX_FEE_TOKENS] total;
    }

    /// Charge one agent group IN MEMORY (one SLOAD of the account). Reverts the batch if short.
    /// Returns the post-charge account packed in one word (same layout as storage) with bit 255
    /// set when a fee was taken, so the batch keeps no per-group struct allocations.
    function _chargeFee(FeeCtx memory f, uint32 id, uint256 actions) internal view returns (uint256 w) {
        FeeAccount memory a = feeAccount[id];
        uint8 t = a.token;
        if (f.loaded & (1 << t) == 0) {
            FeeConfig memory c = feeConfig[t];
            f.perAction[t] = c.feePerAction;
            f.cap[t] = c.maxFeePerBatch;
            f.loaded |= 1 << t;
        }
        uint256 fee = actions * f.perAction[t];        // actions < 2^16, perAction < 2^72: no overflow
        if (f.cap[t] != 0 && fee > f.cap[t]) fee = f.cap[t];
        uint256 bal = a.balance;
        if (fee > bal) revert InsufficientFeeBalance(id, bal, fee);
        if (fee != 0) {
            unchecked { bal -= fee; }
            f.total[t] += fee;
            w = 1 << 255;
        }
        w |= bal | (uint256(a.threshold) << 96) | (uint256(t) << 192) | (a.low ? 1 << 200 : 0);
    }

    /// Write a charged account (skipped when nothing changed, e.g. zero fee and no new alert) and
    /// emit LowFeeBalance on a downward threshold crossing.
    function _commitFee(uint32 id, uint256 w) internal {
        uint96 bal = uint96(w);
        uint96 thr = uint96(w >> 96);
        bool low = (w >> 200) & 1 == 1;
        if (bal < thr && !low) {
            emit LowFeeBalance(id, bal, thr);
            feeAccount[id] = FeeAccount(bal, thr, uint8(w >> 192), true);
        } else if (w >> 255 != 0) {
            feeAccount[id] = FeeAccount(bal, thr, uint8(w >> 192), low);
        }
    }

    function _accrueFees(FeeCtx memory f, uint64 batchId) internal {
        for (uint8 t; t < MAX_FEE_TOKENS; ++t) {
            uint256 amt = f.total[t];
            if (amt != 0) {
                FeeConfig storage c = feeConfig[t];      // warm: loaded by _chargeFee this batch
                c.accrued = SafeCastU96.u104(uint256(c.accrued) + amt);
                emit FeesCharged(batchId, t, amt);
            }
        }
    }
}

library SafeCastU96 {
    error AmountTooLarge();

    function u96(uint256 x) internal pure returns (uint96) {
        if (x > type(uint96).max) revert AmountTooLarge();
        return uint96(x);
    }

    function u104(uint256 x) internal pure returns (uint104) {
        if (x > type(uint104).max) revert AmountTooLarge();
        return uint104(x);
    }
}
