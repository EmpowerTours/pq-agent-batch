// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import { ISP1Verifier } from "./interfaces/ISP1Verifier.sol";
import { AgentRegistry } from "./AgentRegistry.sol";
import { MiniAMM } from "./dex/MiniAMM.sol";

/// @title  BatchSettlementV2 (packed batches), stage S6
/// @notice Same semantics as BatchSettlement, with a packed batch encoding:
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
contract BatchSettlementV2 is ReentrancyGuardTransient {
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
    AgentRegistry public immutable registry;
    MiniAMM       public immutable pool;
    IERC20        public immutable base;
    IERC20        public immutable quote;

    mapping(uint32 => AgentState) public agentState;

    event Deposited(uint32 indexed agentId, uint96 base, uint96 quote);
    event Withdrawn(uint32 indexed agentId, uint96 base, uint96 quote, address to);
    event BatchSettled(uint64 indexed batchId, bytes32 digest, uint256 orders, uint256 baseIn,
        uint256 quoteIn, uint256 ammIn, uint256 ammOut);

    error EmptyBatch();
    error Malformed(uint256 offset);
    error Expired(uint256 index);
    error OrdersNotGrouped(uint256 index);
    error NonceNotIncreasing(uint32 agentId, uint64 firstNonce, uint64 last);
    error CapExceeded(uint32 agentId);
    error InsufficientBalance(uint32 agentId);
    error SlippageExceeded(uint256 index, uint256 out, uint256 minOut);
    error NotOperator();
    error EmptyPool();
    error ZeroAmount(uint256 index);

    constructor(ISP1Verifier _verifier, bytes32 _vkey, AgentRegistry _registry, MiniAMM _pool) {
        verifier = _verifier;
        batchProgramVKey = _vkey;
        registry = _registry;
        pool = _pool;
        base = _pool.token0();
        quote = _pool.token1();
    }

    function batchDigest(uint64 batchId, bytes calldata batch) public view returns (bytes32) {
        return keccak256(abi.encode(BATCH_TAG_V2, block.chainid, address(this), batchId, keccak256(batch)));
    }

    // ------------------------------------------------------------ agent funds

    function deposit(uint32 agentId, uint96 baseAmt, uint96 quoteAmt) external nonReentrant {
        if (baseAmt > 0) base.safeTransferFrom(msg.sender, address(this), baseAmt);
        if (quoteAmt > 0) quote.safeTransferFrom(msg.sender, address(this), quoteAmt);
        AgentState storage s = agentState[agentId];
        s.base += baseAmt;   // checked: reverts on uint96 overflow
        s.quote += quoteAmt;
        emit Deposited(agentId, baseAmt, quoteAmt);
    }

    function withdraw(uint32 agentId, uint96 baseAmt, uint96 quoteAmt, address to) external nonReentrant {
        (address operator,,,,,) = registry.agents(agentId);
        if (msg.sender != operator) revert NotOperator();
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
        uint256 n;          // orders seen
        uint32  prevId;
        uint256 totalBaseIn;
        uint256 totalQuoteIn;
    }

    /// @dev Pass 1 for one agent group: framing, registry, nonces, expiry, caps, debit IN MEMORY.
    function _debitGroup(Cursor memory c, AgentState memory st) private view returns (uint32 id) {
        uint256 p = c.p;
        if (p + HEADER > c.end) revert Malformed(p - c.start);
        (uint32 gid, uint256 count, uint64 firstNonce, uint256 expiry, bytes32 pkHash) = _header(p);
        id = gid;
        if (count == 0) revert Malformed(p - c.start);
        if (expiry < block.timestamp) revert Expired(c.n);
        if (uint256(firstNonce) + count - 1 > type(uint64).max) revert Malformed(p - c.start); // nonce overflow
        if (id <= c.prevId) revert OrdersNotGrouped(c.n);
        p += HEADER;
        if (p + count * ORDER > c.end) revert Malformed(p - c.start);

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
            c.totalBaseIn += agentBaseIn;
            c.totalQuoteIn += agentQuoteIn;
        }

        (uint128 capB, uint128 capQ) = registry.checkAgent(id, pkHash);
        AgentState memory cur = agentState[id];           // one SLOAD
        if (firstNonce <= cur.lastNonce) revert NonceNotIncreasing(id, firstNonce, cur.lastNonce);
        if (agentBaseIn > capB || agentQuoteIn > capQ) revert CapExceeded(id);
        if (cur.base < agentBaseIn || cur.quote < agentQuoteIn) revert InsufficientBalance(id);
        st.base = cur.base - uint96(agentBaseIn);          // < cur.base, so the cast is exact
        st.quote = cur.quote - uint96(agentQuoteIn);
        st.lastNonce = firstNonce + uint64(count) - 1;
    }

    // ------------------------------------------------------------ settlement

    function settle(uint64 batchId, bytes calldata batch, bytes calldata proof) external nonReentrant {
        if (batch.length == 0) revert EmptyBatch();
        // No batch nullifier: every group must start above its agent's lastNonce and
        // advances it, and a batch has >= 1 group, so a replayed batch (or any batch
        // re-using an order) always reverts NonceNotIncreasing.
        uint256 start;
        assembly { start := batch.offset }
        uint256 end = start + batch.length;

        // per-group post-debit state, kept in memory until the single write in pass 2
        AgentState[] memory st = new AgentState[](batch.length / (HEADER + ORDER));
        uint32[] memory ids = new uint32[](st.length);

        // ---- pass 1
        Cursor memory c = Cursor(start, start, end, 0, 0, 0, 0);
        uint256 groups;
        while (c.p < end) {
            if (groups == st.length) revert Malformed(c.p - start); // unreachable for well-formed input
            st[groups] = AgentState(0, 0, 0);
            ids[groups] = _debitGroup(c, st[groups]);
            unchecked { ++groups; }
        }
        uint256 totalBaseIn = c.totalBaseIn;
        uint256 totalQuoteIn = c.totalQuoteIn;
        uint256 n = c.n;

        // ---- one proof for the whole batch
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
            if (ammIn > 0) {
                ammOut = _amountOut(ammIn, r0, r1);
                base.safeTransfer(address(pool), ammIn);
                pool.swap(0, ammOut, address(this));
            }
            pot = totalQuoteIn + ammOut;
        } else {
            ammIn = totalQuoteIn - totalBaseIn * r1 / r0;
            ammOut = _amountOut(ammIn, r1, r0);
            quote.safeTransfer(address(pool), ammIn);
            pool.swap(ammOut, 0, address(this));
            pot = totalBaseIn + ammOut;
        }

        // ---- pass 2: per-order payout + slippage check, ONE SSTORE per agent
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
            }
        }

        emit BatchSettled(batchId, digest, n, totalBaseIn, totalQuoteIn, ammIn, ammOut);
    }

    function _word(uint256 p) private pure returns (uint256 w) {
        assembly { w := calldataload(p) }
    }

    function _amountOut(uint256 amountIn, uint256 rIn, uint256 rOut) private pure returns (uint256) {
        uint256 inFee = amountIn * 997;
        return inFee * rOut / (rIn * 1000 + inFee);
    }
}
