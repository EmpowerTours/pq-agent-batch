// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { ISP1Verifier } from "./interfaces/ISP1Verifier.sol";
import { AgentRegistry } from "./AgentRegistry.sol";
import { AgentFees } from "./AgentFees.sol";
import { MiniAMM } from "./dex/MiniAMM.sol";

/// @title  BatchSettlementV2: one SP1 Groth16 proof settles a batch of ML-DSA-65 signed agent orders
/// @notice Packed batch encoding (v2):
///
///   batch := group+                          (no trailing bytes)
///   group := agentId u32 | count u16 | firstNonce u64 | expiry u32 | pkHash b32 | modelHash b32   (82 B)
///            order[count]
///   order := flags u8 | amountIn u96 | minAmountOut u96                                            (25 B)
///            flags bit0 = buyBase; all other bits must be zero
///
///   order j of a group has nonce firstNonce + j. Groups have strictly increasing agentId.
///
/// What each agent signs with ML-DSA-65 (checked only inside the SP1 guest):
///   ORDER_TAG_V2 | chainid u64 | settlement u160 | agentId u32 | nonce u64 | expiry u32 | modelHash | order(25 B)
/// (expiry and modelHash are per group: one agent's orders in a batch share them.)
/// The guest also checks sha256(pk) == group.pkHash. The public output is
///   abi.encode(keccak256(abi.encode(BATCH_TAG_V2, chainid, this, batchId, keccak256(batch))))
/// so the contract hashes the batch bytes ONCE and never rebuilds per-order messages.
///
/// Fees (AgentFees, contract-side only; the proved batch format and digest are unchanged):
/// each agent group is charged min(count * feePerAction, maxFeePerBatch) from the agent's
/// prepaid fee balance.
///
/// Group skipping (audit M-01): a group whose AGENT STATE makes it unsettleable at settle time
/// (expired, unknown/retired agent, killed, revoked key, nonce not above lastNonce, over caps,
/// short trading or fee balance) is skipped with `GroupSkipped(batchId, agentId, reason)`: no trade,
/// no fee, no nonce change. The other groups settle. Framing errors, a bad proof and slippage still
/// revert the whole batch. If NO group can settle (e.g. a replayed batch) the call reverts with the
/// first group's error. Without this, any one agent in a batch could grief the whole proved batch by
/// withdrawing, killing itself or revoking its key after proving.
contract BatchSettlementV2 is AgentFees {
    using SafeERC20 for IERC20;

    uint256 internal constant HEADER = 82;
    uint256 internal constant ORDER = 25;
    uint256 internal constant M96 = (1 << 96) - 1;

    /// One storage slot per agent: read once and written once per batch.
    struct AgentState {
        uint96 base;
        uint96 quote;
        uint64 lastNonce;
    }

    bytes32 public constant ORDER_TAG_V2 = keccak256("EmpowerTours.AgentOrder.v2");
    bytes32 public constant BATCH_TAG_V2 = keccak256("EmpowerTours.AgentBatch.v2");

    ISP1Verifier  public immutable verifier;
    bytes32       public immutable batchProgramVKey;
    MiniAMM       public immutable pool;
    IERC20        public immutable base;
    IERC20        public immutable quote;

    mapping(uint32 => AgentState) public agentState;

    event Deposited(uint32 indexed agentId, uint96 base, uint96 quote);
    event Withdrawn(uint32 indexed agentId, uint96 base, uint96 quote, address to);
    /// `orders` counts SETTLED orders (skipped groups excluded).
    event BatchSettled(uint64 indexed batchId, bytes32 digest, uint256 orders, uint256 baseIn,
        uint256 quoteIn, uint256 ammIn, uint256 ammOut);
    /// `reason` is the full abi-encoded custom error the group would have reverted with.
    event GroupSkipped(uint64 indexed batchId, uint32 indexed agentId, bytes reason);

    error EmptyBatch();
    error Malformed(uint256 offset);
    error Expired(uint256 index);
    error OrdersNotGrouped(uint256 index);
    error NonceNotIncreasing(uint32 agentId, uint64 firstNonce, uint64 last);
    error CapExceeded(uint32 agentId);
    error InsufficientBalance(uint32 agentId);
    error SlippageExceeded(uint256 index, uint256 out, uint256 minOut);
    error EmptyPool();
    error ZeroAmount(uint256 index);
    error AgentKilled(uint32 agentId);              // same selectors as AgentRegistry's errors
    error UnknownKey(uint32 agentId, bytes32 pkHash);
    error BadConfig();

    constructor(ISP1Verifier _verifier, bytes32 _vkey, AgentRegistry _registry, MiniAMM _pool) AgentFees(_registry) {
        // audit L-05: a codeless verifier/registry/pool or a zero vkey would brick (or, for a verifier
        // stub, unprotect) an immutable deployment.
        if (_vkey == bytes32(0) || address(_verifier).code.length == 0 || address(_registry).code.length == 0
            || address(_pool).code.length == 0) revert BadConfig();
        verifier = _verifier;
        batchProgramVKey = _vkey;
        pool = _pool;
        base = _pool.token0();
        quote = _pool.token1();
    }

    function batchDigest(uint64 batchId, bytes calldata batch) public view returns (bytes32) {
        return keccak256(abi.encode(BATCH_TAG_V2, block.chainid, address(this), batchId, keccak256(batch)));
    }

    // ------------------------------------------------------------ agent funds

    function deposit(uint32 agentId, uint96 baseAmt, uint96 quoteAmt) external nonReentrant {
        // audit L-03: no deposits for unregistered (future) ids, whose funds would belong to whoever
        // registers that id next.
        (, bool active) = _operator(agentId);
        if (!active) revert UnknownAgent(agentId);
        if (baseAmt > 0) _pullExact(base, msg.sender, baseAmt);    // rejects fee-on-transfer tokens (L-02)
        if (quoteAmt > 0) _pullExact(quote, msg.sender, quoteAmt);
        AgentState storage s = agentState[agentId];
        s.base += baseAmt;   // checked: reverts on uint96 overflow
        s.quote += quoteAmt;
        emit Deposited(agentId, baseAmt, quoteAmt);
    }

    function withdraw(uint32 agentId, uint96 baseAmt, uint96 quoteAmt, address to) external nonReentrant {
        // slither-disable-next-line unused-return
        (address operator,,,,,) = registry.agents(agentId);
        if (msg.sender != operator) revert NotOperator();
        if (to == address(0)) revert ZeroAddress();
        AgentState storage s = agentState[agentId];
        if (s.base < baseAmt || s.quote < quoteAmt) revert InsufficientBalance(agentId);
        s.base -= baseAmt;
        s.quote -= quoteAmt;
        if (baseAmt > 0) base.safeTransfer(to, baseAmt);
        if (quoteAmt > 0) quote.safeTransfer(to, quoteAmt);
        emit Withdrawn(agentId, baseAmt, quoteAmt, to);
    }

    // ------------------------------------------------------------ packed decoding

    function _header(uint256 p)
        private
        pure
        returns (uint32 id, uint256 count, uint64 firstNonce, uint256 expiry, bytes32 pkHash)
    {
        uint256 w;
        assembly {
            w := calldataload(p)
            pkHash := calldataload(add(p, 18))
        }
        id = uint32(w >> 224);
        count = (w >> 208) & 0xffff;
        firstNonce = uint64(w >> 144);
        expiry = (w >> 112) & 0xffffffff;
    }

    /// Pass-1 cursor, kept in memory to stay clear of stack-too-deep.
    struct Cursor {
        uint256 p;          // absolute calldata offset
        uint256 start;
        uint256 end;
        uint256 n;          // orders seen (all groups; used for error indexes)
        uint32  prevId;
        uint256 gBase;      // current group's base / quote in (added to totals only if it settles)
        uint256 gQuote;
        uint256 totalBaseIn;   // settled groups only
        uint256 totalQuoteIn;
        uint256 settled;       // settled orders
        bytes   firstErr;      // first skipped group's error
    }

    /// Pass 1 for group `g`: debit + fee, or mark skipped.
    function _pass1Group(Cursor memory c, AgentState[] memory st, uint32[] memory ids, uint256[] memory feeWord,
        FeeCtx memory fctx, uint256 g, uint64 batchId) private
    {
        AgentState memory s = st[g];                       // zero-initialised
        (uint32 gid, uint256 count, bytes memory err) = _debitGroup(c, s);
        ids[g] = gid;
        if (err.length == 0) (feeWord[g], err) = _chargeFee(fctx, gid, count);
        if (err.length == 0) {
            c.totalBaseIn += c.gBase;
            c.totalQuoteIn += c.gQuote;
            c.settled += count;
        } else {
            s.lastNonce = 0;                               // marks the group as skipped
            emit GroupSkipped(batchId, gid, err);
            if (c.firstErr.length == 0) c.firstErr = err;
        }
    }

    /// @dev Pass 1 for one agent group. Framing errors revert. Agent-state problems are returned as `err`
    ///      (abi-encoded custom error) so the caller skips the group. On success `st` holds the post-debit
    ///      state (lastNonce >= 1, which pass 2 uses as the "settles" marker).
    function _debitGroup(Cursor memory c, AgentState memory st)
        private
        view
        returns (uint32 id, uint256 count, bytes memory err)
    {
        uint256 p = c.p;
        if (p + HEADER > c.end) revert Malformed(p - c.start);
        uint64 firstNonce;
        uint256 expiry;
        bytes32 pkHash;
        (id, count, firstNonce, expiry, pkHash) = _header(p);
        if (count == 0) revert Malformed(p - c.start);
        if (uint256(firstNonce) + count - 1 > type(uint64).max) revert Malformed(p - c.start); // nonce overflow
        if (id <= c.prevId) revert OrdersNotGrouped(c.n);
        p += HEADER;
        if (p + count * ORDER > c.end) revert Malformed(p - c.start);

        uint256 nBefore = c.n;
        uint256 agentBaseIn;
        uint256 agentQuoteIn;
        unchecked { // amounts < 2^96, count < 2^16: sums cannot overflow
            uint256 qEnd = p + count * ORDER;
            for (uint256 q = p; q < qEnd; q += ORDER) {
                uint256 w;
                assembly { w := calldataload(q) }
                uint256 flags = w >> 248;
                uint256 amountIn = (w >> 152) & M96;
                if (flags > 1) revert Malformed(q - c.start);
                if (amountIn == 0) revert ZeroAmount(c.n + (q - p) / ORDER);
                if (flags == 1) agentQuoteIn += amountIn;
                else agentBaseIn += amountIn;
            }
            c.p = qEnd;
            c.n += count;
            c.prevId = id;
        }
        c.gBase = agentBaseIn;
        c.gQuote = agentQuoteIn;

        if (expiry < block.timestamp) return (id, count, abi.encodeWithSelector(Expired.selector, nBefore));
        (uint8 status, uint128 capB, uint128 capQ) = registry.agentStatus(id, pkHash);
        if (status != 0) {
            if (status == 1) err = abi.encodeWithSelector(UnknownAgent.selector, id);
            else if (status == 2) err = abi.encodeWithSelector(AgentKilled.selector, id);
            else err = abi.encodeWithSelector(UnknownKey.selector, id, pkHash);
            return (id, count, err);
        }
        AgentState memory cur = agentState[id];           // one SLOAD
        if (firstNonce <= cur.lastNonce) {
            return (id, count, abi.encodeWithSelector(NonceNotIncreasing.selector, id, firstNonce, cur.lastNonce));
        }
        if (agentBaseIn > capB || agentQuoteIn > capQ) return (id, count, abi.encodeWithSelector(CapExceeded.selector, id));
        if (cur.base < agentBaseIn || cur.quote < agentQuoteIn) {
            return (id, count, abi.encodeWithSelector(InsufficientBalance.selector, id));
        }
        st.base = cur.base - uint96(agentBaseIn);          // < cur.base, so the cast is exact
        st.quote = cur.quote - uint96(agentQuoteIn);
        st.lastNonce = firstNonce + uint64(count) - 1;     // >= 1 since firstNonce > lastNonce >= 0
    }

    // ------------------------------------------------------------ settlement

    // slither-disable-start reentrancy-no-eth
    // audit S-05: the only external calls after pass 1 go to the immutable pool and immutable tokens, and the
    // whole function (and every other state-changing entrypoint) holds the transient nonReentrant lock.
    function settle(uint64 batchId, bytes calldata batch, bytes calldata proof) external nonReentrant {
        if (batch.length == 0) revert EmptyBatch();
        // No batch nullifier: a group settles only if it starts above its agent's lastNonce, and settling
        // advances it. A replayed batch therefore has every group skipped and reverts (first group's
        // NonceNotIncreasing); a partially replayed one can only settle groups that never settled.
        uint256 start;
        assembly { start := batch.offset }
        uint256 end = start + batch.length;

        // per-group post-debit state, kept in memory until the single write in pass 2
        AgentState[] memory st = new AgentState[](batch.length / (HEADER + ORDER));
        uint32[] memory ids = new uint32[](st.length);
        uint256[] memory feeWord = new uint256[](st.length);   // packed post-charge fee account per group
        FeeCtx memory fctx;

        // ---- pass 1
        Cursor memory c = Cursor(start, start, end, 0, 0, 0, 0, 0, 0, 0, "");
        uint256 groups;
        while (c.p < end) {
            if (groups == st.length) revert Malformed(c.p - start); // unreachable for well-formed input
            _pass1Group(c, st, ids, feeWord, fctx, groups, batchId);
            unchecked { ++groups; }
        }
        if (c.settled == 0) {
            bytes memory firstErr = c.firstErr;
            assembly { revert(add(firstErr, 32), mload(firstErr)) }
        }
        uint256 totalBaseIn = c.totalBaseIn;
        uint256 totalQuoteIn = c.totalQuoteIn;

        // ---- one proof for the whole batch (every group, settled or skipped, is bound by the digest)
        bytes32 digest = batchDigest(batchId, batch);
        verifier.verifyProof(batchProgramVKey, abi.encode(digest), proof);

        // ---- clear: net at mid, residual to the AMM (quote computed inline, same formula as MiniAMM)
        (uint256 r0, uint256 r1) = pool.getReserves();
        if (r0 == 0 || r1 == 0) revert EmptyPool();
        bool excessBase = totalBaseIn >= totalQuoteIn * r0 / r1;
        uint256 pot;    // excessBase: quote paid to sellers pro rata; else base paid to buyers pro rata
        uint256 ammIn;
        uint256 ammOut;
        if (excessBase) {
            ammIn = totalBaseIn - totalQuoteIn * r0 / r1;
            ammOut = ammIn == 0 ? 0 : _amountOut(ammIn, r0, r1);
            if (ammOut > 0) {   // audit L-06: a dust residual with zero output stays here instead of reverting
                base.safeTransfer(address(pool), ammIn);
                pool.swap(0, ammOut, address(this));
            }
            pot = totalQuoteIn + ammOut;
        } else {
            ammIn = totalQuoteIn - totalBaseIn * r1 / r0;
            ammOut = _amountOut(ammIn, r1, r0);
            if (ammOut > 0) {
                quote.safeTransfer(address(pool), ammIn);
                pool.swap(ammOut, 0, address(this));
            }
            pot = totalBaseIn + ammOut;
        }

        // ---- pass 2: per-order payout + slippage check, ONE SSTORE per settled agent
        // payout = amountIn * num / den, with (num, den) fixed per side for the whole batch
        (uint256 buyNum, uint256 buyDen, uint256 sellNum, uint256 sellDen) =
            excessBase ? (r0, r1, pot, totalBaseIn) : (pot, totalQuoteIn, r1, r0);
        {
            uint256 p = start;
            uint256 i;
            for (uint256 g; g < groups; ++g) {
                uint256 qEnd;
                uint256 baseOut;
                uint256 quoteOut;
                unchecked { // amountIn < 2^96, num < 2^120: products < 2^216
                    qEnd = p + HEADER + ((_word(p) >> 208) & 0xffff) * ORDER;
                    if (st[g].lastNonce == 0) {          // skipped group: no payout, no state change
                        i += (qEnd - p - HEADER) / ORDER;
                        p = qEnd;
                        continue;
                    }
                    for (uint256 q = p + HEADER; q < qEnd; q += ORDER) {
                        uint256 w;
                        assembly { w := calldataload(q) }
                        uint256 amountIn = (w >> 152) & M96;
                        uint256 out;
                        if (w >> 248 != 0) {
                            out = amountIn * buyNum / buyDen;
                            baseOut += out;
                        } else {
                            out = amountIn * sellNum / sellDen;
                            quoteOut += out;
                        }
                        uint256 minOut = (w >> 56) & M96;
                        if (out < minOut) revert SlippageExceeded(i + (q - p - HEADER) / ORDER, out, minOut);
                    }
                    i += (qEnd - p - HEADER) / ORDER;
                }
                p = qEnd;
                AgentState memory s = st[g];
                s.base += SafeCast.toUint96(baseOut);   // checked cast + checked add
                s.quote += SafeCast.toUint96(quoteOut);
                agentState[ids[g]] = s;
                _commitFee(ids[g], feeWord[g]);
            }
        }
        _accrueFees(fctx, batchId);

        emit BatchSettled(batchId, digest, c.settled, totalBaseIn, totalQuoteIn, ammIn, ammOut);
    }
    // slither-disable-end reentrancy-no-eth

    function _word(uint256 p) private pure returns (uint256 w) {
        assembly { w := calldataload(p) }
    }

    function _amountOut(uint256 amountIn, uint256 rIn, uint256 rOut) private pure returns (uint256) {
        uint256 inFee = amountIn * 997;
        return inFee * rOut / (rIn * 1000 + inFee);
    }
}
