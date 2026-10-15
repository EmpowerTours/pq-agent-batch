// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { ISP1Verifier } from "./interfaces/ISP1Verifier.sol";
import { AgentRegistry } from "./AgentRegistry.sol";
import { MiniAMM } from "./dex/MiniAMM.sol";

/// @title  BatchSettlement — one market, one aggregated PQ proof per batch
/// @notice Settles a batch of agent orders for ONE market (one MiniAMM pair:
///         base = token0, quote = token1) in a single transaction:
///           1. recompute every order hash from calldata and fold them into the
///              batch digest the SP1 guest committed;
///           2. verify ONE Groth16 proof that every order carries a valid
///              ML-DSA-65 signature by the key named in the order;
///           3. enforce the registry (key authorised, agent not killed,
///              per-batch caps) and per-agent nonce ordering;
///           4. net buys against sells at the pool mid-price, and send only the
///              residual imbalance to the AMM;
///           5. pay every order pro rata out of internal agent balances.
/// @dev    Exec binding: the bytes each agent signs are exactly
///         `abi.encode(ORDER_TAG, chainid, address(this), order)`, so the
///         executed parameters cannot differ from the signed ones without
///         changing the order hash, the batch digest, and therefore the proof.
///         There is no per-order storage. Replay protection is one nullifier
///         per batch plus one strictly increasing nonce per agent.
///         Sharding: deploy one BatchSettlement per market; the market is bound
///         into every order through `address(this)`.
contract BatchSettlement is ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct Order {
        uint32  agentId;
        bool    buyBase;       // true: spend quote, receive base. false: spend base, receive quote
        uint64  nonce;         // strictly increasing per agent, across batches
        uint64  expiry;        // unix seconds
        uint128 amountIn;
        uint128 minAmountOut;
        bytes32 pkHash;        // SHA-256 of the signing ML-DSA-65 public key
        bytes32 modelHash;     // commitment to the model / run that produced the order
    }

    struct AgentState {
        uint128 base;
        uint128 quote;
        uint64  lastNonce;
    }

    bytes32 public constant ORDER_TAG = keccak256("EmpowerTours.AgentOrder.v1");
    bytes32 public constant BATCH_TAG = keccak256("EmpowerTours.AgentBatch.v1");

    ISP1Verifier  public immutable verifier;
    bytes32       public immutable batchProgramVKey;
    AgentRegistry public immutable registry;
    MiniAMM       public immutable pool;
    IERC20        public immutable base;
    IERC20        public immutable quote;

    mapping(uint64 => bool) public batchUsed;
    mapping(uint32 => AgentState) public agentState;

    event Deposited(uint32 indexed agentId, uint128 base, uint128 quote);
    event Withdrawn(uint32 indexed agentId, uint128 base, uint128 quote, address to);
    event BatchSettled(
        uint64 indexed batchId,
        bytes32 digest,
        uint256 orders,
        uint256 baseIn,
        uint256 quoteIn,
        uint256 ammIn,
        uint256 ammOut
    );

    error EmptyBatch();
    error BatchReplayed(uint64 batchId);
    error Expired(uint256 index);
    error OrdersNotGrouped(uint256 index);
    error NonceNotIncreasing(uint256 index, uint64 nonce, uint64 last);
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

    // ------------------------------------------------------------ hashing (mirrored by the guest)

    function orderHash(Order calldata o) public view returns (bytes32) {
        return keccak256(abi.encode(ORDER_TAG, block.chainid, address(this), o));
    }

    function batchDigest(uint64 batchId, bytes32[] memory hashes) public view returns (bytes32) {
        return keccak256(
            abi.encode(BATCH_TAG, block.chainid, address(this), batchId, keccak256(abi.encodePacked(hashes)))
        );
    }

    // ------------------------------------------------------------ agent funds

    function deposit(uint32 agentId, uint128 baseAmt, uint128 quoteAmt) external nonReentrant {
        if (baseAmt > 0) base.safeTransferFrom(msg.sender, address(this), baseAmt);
        if (quoteAmt > 0) quote.safeTransferFrom(msg.sender, address(this), quoteAmt);
        AgentState storage s = agentState[agentId];
        s.base += baseAmt;
        s.quote += quoteAmt;
        emit Deposited(agentId, baseAmt, quoteAmt);
    }

    function withdraw(uint32 agentId, uint128 baseAmt, uint128 quoteAmt, address to) external nonReentrant {
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

    // ------------------------------------------------------------ settlement

    /// @param batchId unique id chosen by the batcher (nullified on use)
    /// @param orders  grouped by agentId (non-decreasing), nonces strictly increasing per agent
    /// @param proof   SP1 Groth16 proof over publicValues = abi.encode(batchDigest)
    function settle(uint64 batchId, Order[] calldata orders, bytes calldata proof) external nonReentrant {
        uint256 n = orders.length;
        if (n == 0) revert EmptyBatch();
        if (batchUsed[batchId]) revert BatchReplayed(batchId);
        batchUsed[batchId] = true;

        // ---- pass 1: hash, validate, debit, total
        bytes32[] memory hashes = new bytes32[](n);
        uint256 totalBaseIn;
        uint256 totalQuoteIn;
        {
            uint256 i;
            while (i < n) {
                uint32 id = orders[i].agentId;
                (uint128 capB, uint128 capQ) = registry.tradingLimits(id); // reverts if unknown/killed
                AgentState storage s = agentState[id];
                uint64 last = s.lastNonce;
                bytes32 lastPk;
                uint256 agentBaseIn;
                uint256 agentQuoteIn;
                // consume this agent's contiguous group
                for (; i < n && orders[i].agentId == id; ++i) {
                    Order calldata o = orders[i];
                    if (o.expiry < block.timestamp) revert Expired(i);
                    if (o.amountIn == 0) revert ZeroAmount(i);
                    if (o.nonce <= last) revert NonceNotIncreasing(i, o.nonce, last);
                    last = o.nonce;
                    if (o.pkHash != lastPk) {
                        registry.requireKey(id, o.pkHash);
                        lastPk = o.pkHash;
                    }
                    if (o.buyBase) agentQuoteIn += o.amountIn;
                    else agentBaseIn += o.amountIn;
                    hashes[i] = orderHash(o);
                }
                if (i < n && orders[i].agentId < id) revert OrdersNotGrouped(i);
                if (agentBaseIn > capB || agentQuoteIn > capQ) revert CapExceeded(id);
                if (s.base < agentBaseIn || s.quote < agentQuoteIn) revert InsufficientBalance(id);
                s.base -= uint128(agentBaseIn);
                s.quote -= uint128(agentQuoteIn);
                s.lastNonce = last;
                totalBaseIn += agentBaseIn;
                totalQuoteIn += agentQuoteIn;
            }
        }

        // ---- one proof for the whole batch
        bytes32 digest = batchDigest(batchId, hashes);
        verifier.verifyProof(batchProgramVKey, abi.encode(digest), proof);

        // ---- clear: net at mid, residual to the AMM
        (uint112 r0, uint112 r1) = pool.getReserves();
        if (r0 == 0 || r1 == 0) revert EmptyPool();
        bool excessBase = totalBaseIn >= totalQuoteIn * r0 / r1; // more base sold than buyers' quote buys at mid
        uint256 quoteToSellers;   // excessBase: all quote distributed pro rata to sellers
        uint256 baseToBuyers;     // !excessBase: all base distributed pro rata to buyers
        uint256 ammIn;
        uint256 ammOut;
        if (excessBase) {
            // excess base -> sell on AMM for quote; buyers are filled at mid
            ammIn = totalBaseIn - totalQuoteIn * r0 / r1;
            if (ammIn > 0) {
                ammOut = pool.quoteToken1Out(ammIn);
                base.safeTransfer(address(pool), ammIn);
                pool.swap(0, ammOut, address(this));
            }
            quoteToSellers = totalQuoteIn + ammOut;
        } else {
            // excess quote -> buy base on AMM; sellers are filled at mid
            uint256 matchedQuote = totalBaseIn * r1 / r0;
            ammIn = totalQuoteIn - matchedQuote;
            ammOut = pool.quoteToken0Out(ammIn);
            quote.safeTransfer(address(pool), ammIn);
            pool.swap(ammOut, 0, address(this));
            baseToBuyers = totalBaseIn + ammOut;
        }

        // ---- pass 2: pay out pro rata, check limits, credit once per agent
        {
            uint256 i;
            while (i < n) {
                uint32 id = orders[i].agentId;
                uint256 baseOut;
                uint256 quoteOut;
                for (; i < n && orders[i].agentId == id; ++i) {
                    Order calldata o = orders[i];
                    uint256 out;
                    if (o.buyBase) {
                        out = excessBase
                            ? uint256(o.amountIn) * r0 / r1
                            : uint256(o.amountIn) * baseToBuyers / totalQuoteIn;
                        baseOut += out;
                    } else {
                        out = excessBase
                            ? uint256(o.amountIn) * quoteToSellers / totalBaseIn
                            : uint256(o.amountIn) * r1 / r0;
                        quoteOut += out;
                    }
                    if (out < o.minAmountOut) revert SlippageExceeded(i, out, o.minAmountOut);
                }
                AgentState storage s = agentState[id];
                s.base += uint128(baseOut);
                s.quote += uint128(quoteOut);
            }
        }

        emit BatchSettled(batchId, digest, n, totalBaseIn, totalQuoteIn, ammIn, ammOut);
    }
}
