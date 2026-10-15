// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test } from "forge-std/Test.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { BatchSettlement } from "../src/BatchSettlement.sol";
import { MiniAMM } from "../src/dex/MiniAMM.sol";
import { MockToken } from "../src/dex/MockToken.sol";
import { HashBoundMockVerifier } from "./helpers/HashBoundMockVerifier.sol";

contract BatchSettlementTest is Test {
    bytes32 constant VKEY = keccak256("batch-guest-vkey");
    bytes32 constant PK_A = keccak256("agent-A-mldsa-pk");
    bytes32 constant PK_B = keccak256("agent-B-mldsa-pk");
    bytes32 constant MODEL = keccak256("ridge-v1+xy-qaoa");

    address admin = address(0xA11CE);
    address guardian = address(0x6A2D);
    address opA = makeAddr("operatorA");
    address opB = makeAddr("operatorB");

    MockToken baseTok;
    MockToken quoteTok;
    MiniAMM pool;
    AgentRegistry reg;
    HashBoundMockVerifier ver;
    BatchSettlement bs;
    uint32 idA;
    uint32 idB;

    function setUp() public {
        vm.warp(1_800_000_000);
        MockToken t0 = new MockToken("Base", "BASE", 18);
        MockToken t1 = new MockToken("Quote", "QUOTE", 18);
        pool = new MiniAMM(address(t0), address(t1));
        baseTok = MockToken(address(pool.token0()));
        quoteTok = MockToken(address(pool.token1()));
        // seed pool at 2 quote per base
        _mint(baseTok, address(this), 50_000e18);
        _mint(quoteTok, address(this), 100_000e18);
        baseTok.approve(address(pool), type(uint256).max);
        quoteTok.approve(address(pool), type(uint256).max);
        _addLiq(50_000e18, 100_000e18);

        reg = new AgentRegistry(admin, guardian, 1 ether);
        ver = new HashBoundMockVerifier();
        bs = new BatchSettlement(ver, VKEY, reg, pool);

        vm.deal(admin, 10 ether);
        vm.startPrank(admin);
        idA = reg.registerAgent{ value: 1 ether }(opA, PK_A, 1_000e18, 2_000e18);
        idB = reg.registerAgent{ value: 1 ether }(opB, PK_B, 1_000e18, 2_000e18);
        vm.stopPrank();

        _fund(idA, 1_000e18, 2_000e18);
        _fund(idB, 1_000e18, 2_000e18);
    }

    // ------------------------------------------------------------ helpers

    function _mint(MockToken t, address to, uint256 amt) internal {
        vm.startPrank(to);
        while (amt > 0) {
            uint256 a = amt > 100_000e18 ? 100_000e18 : amt;
            t.faucet(a);
            amt -= a;
        }
        vm.stopPrank();
    }

    function _addLiq(uint256 a0, uint256 a1) internal {
        (bool ok,) = address(pool).call(abi.encodeWithSignature("addLiquidity(uint256,uint256,address)", a0, a1, address(this)));
        require(ok, "addLiquidity");
    }

    function _fund(uint32 id, uint128 b, uint128 q) internal {
        _mint(baseTok, address(this), b);
        _mint(quoteTok, address(this), q);
        baseTok.approve(address(bs), type(uint256).max);
        quoteTok.approve(address(bs), type(uint256).max);
        bs.deposit(id, b, q);
    }

    function _order(uint32 id, bytes32 pk, bool buy, uint64 nonce, uint128 amt)
        internal
        view
        returns (BatchSettlement.Order memory)
    {
        return BatchSettlement.Order(id, buy, nonce, uint64(block.timestamp + 60), amt, 0, pk, MODEL);
    }

    function _proof(uint64 batchId, BatchSettlement.Order[] memory orders) internal view returns (bytes memory) {
        bytes32[] memory h = new bytes32[](orders.length);
        for (uint256 i; i < orders.length; ++i) h[i] = bs.orderHash(orders[i]);
        return ver.proofFor(VKEY, abi.encode(bs.batchDigest(batchId, h)));
    }

    function _twoAgentBatch() internal view returns (BatchSettlement.Order[] memory o) {
        o = new BatchSettlement.Order[](3);
        o[0] = _order(idA, PK_A, false, 1, 100e18);  // A sells 100 base
        o[1] = _order(idA, PK_A, false, 2, 50e18);   // A sells 50 base
        o[2] = _order(idB, PK_B, true, 1, 200e18);   // B buys with 200 quote
    }

    // ------------------------------------------------------------ happy path

    function test_HappyPath_TwoAgents() public {
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        (uint128 aB0, uint128 aQ0,) = bs.agentState(idA);
        (uint128 bB0, uint128 bQ0,) = bs.agentState(idB);
        uint256 poolBase0 = baseTok.balanceOf(address(pool));

        bs.settle(1, o, _proof(1, o));

        (uint128 aB1, uint128 aQ1, uint64 aN) = bs.agentState(idA);
        (uint128 bB1, uint128 bQ1, uint64 bN) = bs.agentState(idB);
        assertEq(aB0 - aB1, 150e18, "A sold 150 base");
        assertEq(bQ0 - bQ1, 200e18, "B spent 200 quote");
        assertEq(bB1 - bB0, 100e18, "B filled at mid (2 quote/base)");
        // 150 base sold, 100 crossed internally, 50 residual to AMM
        assertEq(baseTok.balanceOf(address(pool)) - poolBase0, 50e18, "only residual hits the AMM");
        assertGt(aQ1 - aQ0, 290e18, "A got 200 internal + AMM proceeds");
        assertLt(aQ1 - aQ0, 300e18, "AMM leg pays below mid");
        assertEq(aN, 2);
        assertEq(bN, 1);
        assertTrue(bs.batchUsed(1));
        _assertSolvent();
    }

    function test_ExcessQuoteGoesToAmm() public {
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](2);
        o[0] = _order(idA, PK_A, false, 1, 10e18);   // sells 10 base (=20 quote at mid)
        o[1] = _order(idB, PK_B, true, 1, 100e18);   // buys with 100 quote
        uint256 poolQuote0 = quoteTok.balanceOf(address(pool));
        bs.settle(7, o, _proof(7, o));
        assertEq(quoteTok.balanceOf(address(pool)) - poolQuote0, 80e18, "80 quote residual to AMM");
        (, uint128 aQ,) = bs.agentState(idA);
        assertEq(aQ, 2_000e18 + 20e18, "seller filled at mid");
        _assertSolvent();
    }

    // ------------------------------------------------------------ rejections

    function test_TamperedOrderRejected() public {
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        bytes memory proof = _proof(1, o);
        o[2].minAmountOut = 0;
        o[2].amountIn = 199e18; // change what B "signed"
        vm.expectRevert(HashBoundMockVerifier.InvalidMockProof.selector);
        bs.settle(1, o, proof);
    }

    function test_ModelHashIsBound() public {
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        bytes memory proof = _proof(1, o);
        o[0].modelHash = keccak256("some-other-model");
        vm.expectRevert(HashBoundMockVerifier.InvalidMockProof.selector);
        bs.settle(1, o, proof);
    }

    function test_UnregisteredAgentRejected() public {
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](1);
        o[0] = _order(99, PK_A, false, 1, 1e18);
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.UnknownAgent.selector, uint32(99)));
        bs.settle(1, o, proof);
    }

    function test_UnregisteredKeyRejected() public {
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](1);
        o[0] = _order(idA, PK_B, false, 1, 1e18); // B's key on A's order
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.UnknownKey.selector, idA, PK_B));
        bs.settle(1, o, proof);
    }

    function test_RevokedKeyRejected() public {
        bytes32 pk2 = keccak256("agent-A-key-2");
        vm.startPrank(opA);
        reg.addKey(idA, pk2);
        reg.revokeKey(idA, PK_A);
        vm.stopPrank();
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](1);
        o[0] = _order(idA, PK_A, false, 1, 1e18);
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.UnknownKey.selector, idA, PK_A));
        bs.settle(1, o, proof);
    }

    function test_ReplayedBatchRejected() public {
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        bytes memory proof = _proof(1, o);
        bs.settle(1, o, proof);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlement.BatchReplayed.selector, uint64(1)));
        bs.settle(1, o, proof);
    }

    function test_ReplayedOrdersUnderNewBatchIdRejected() public {
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        bs.settle(1, o, _proof(1, o));
        bytes memory proof2 = _proof(2, o); // a fresh valid proof over the SAME orders
        vm.expectRevert(abi.encodeWithSelector(BatchSettlement.NonceNotIncreasing.selector, 0, uint64(1), uint64(2)));
        bs.settle(2, o, proof2);
    }

    function test_CapExceededRejected() public {
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](2);
        o[0] = _order(idA, PK_A, false, 1, 600e18);
        o[1] = _order(idA, PK_A, false, 2, 600e18); // 1,200 > cap 1,000
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlement.CapExceeded.selector, idA));
        bs.settle(1, o, proof);
    }

    function test_KilledAgentRejected_ByGuardian() public {
        vm.prank(guardian);
        reg.kill(idB);
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.AgentKilled.selector, idB));
        bs.settle(1, o, proof);
        // guardian cannot revive; admin can
        vm.prank(guardian);
        vm.expectRevert(AgentRegistry.NotAdmin.selector);
        reg.revive(idB);
        vm.prank(admin);
        reg.revive(idB);
        bs.settle(1, o, proof);
    }

    function test_OperatorCanKillItself() public {
        vm.prank(opA);
        reg.kill(idA);
        (,, bool killed,,,) = reg.agents(idA);
        assertTrue(killed);
    }

    function test_StrangerCannotKill() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(AgentRegistry.NotAuthorised.selector);
        reg.kill(idA);
    }

    function test_SlippageRejected() public {
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        o[2].minAmountOut = 101e18; // mid fill is exactly 100
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlement.SlippageExceeded.selector, 2, 100e18, 101e18));
        bs.settle(1, o, proof);
    }

    function test_ExpiredRejected() public {
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        bytes memory proof = _proof(1, o);
        vm.warp(block.timestamp + 61);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlement.Expired.selector, 0));
        bs.settle(1, o, proof);
    }

    function test_UngroupedRejected() public {
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](3);
        o[0] = _order(idB, PK_B, true, 1, 10e18);
        o[1] = _order(idA, PK_A, false, 1, 10e18);
        o[2] = _order(idA, PK_A, false, 2, 10e18);
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlement.OrdersNotGrouped.selector, 1));
        bs.settle(1, o, proof);
    }

    function test_InsufficientBalanceRejected() public {
        vm.prank(admin);
        reg.setCaps(idA, 10_000e18, 10_000e18);
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](1);
        o[0] = _order(idA, PK_A, false, 1, 1_001e18); // balance is 1,000
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlement.InsufficientBalance.selector, idA));
        bs.settle(1, o, proof);
    }

    function test_WithdrawOnlyOperator() public {
        vm.expectRevert(BatchSettlement.NotOperator.selector);
        bs.withdraw(idA, 1e18, 0, address(this));
        vm.prank(opA);
        bs.withdraw(idA, 1e18, 0, opA);
        assertEq(baseTok.balanceOf(opA), 1e18);
    }

    function test_RetireRefundsStake() public {
        vm.prank(admin);
        reg.retire(idA);
        assertEq(opA.balance, 1 ether);
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](1);
        o[0] = _order(idA, PK_A, false, 1, 1e18);
        bytes memory proof = _proof(1, o);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.UnknownAgent.selector, idA));
        bs.settle(1, o, proof);
    }

    // ------------------------------------------------------------ fuzz

    /// Any single-field mutation after proving must be rejected.
    function testFuzz_AnyFieldTamperRejected(uint8 which, uint8 field, uint64 delta) public {
        vm.assume(delta != 0);
        BatchSettlement.Order[] memory o = _twoAgentBatch();
        bytes memory proof = _proof(1, o);
        uint256 i = which % o.length;
        uint256 f = field % 4;
        if (f == 0) o[i].amountIn = o[i].amountIn - uint128(delta % 1e18 + 1);
        else if (f == 1) o[i].modelHash = keccak256(abi.encode(o[i].modelHash, delta));
        else if (f == 2) o[i].expiry = o[i].expiry + (delta % 1e6) + 1;
        else o[i].buyBase = !o[i].buyBase;
        vm.expectRevert();
        bs.settle(1, o, proof);
    }

    /// Settlement never pays out more than it holds, for any mix of two agents' orders.
    function testFuzz_SolventForAnyAmounts(uint128 a, uint128 b, bool aBuys, bool bBuys) public {
        a = uint128(bound(a, 1e9, 1_000e18));
        b = uint128(bound(b, 1e9, 1_000e18));
        BatchSettlement.Order[] memory o = new BatchSettlement.Order[](2);
        o[0] = _order(idA, PK_A, aBuys, 1, a);
        o[1] = _order(idB, PK_B, bBuys, 1, b);
        bs.settle(3, o, _proof(3, o));
        _assertSolvent();
    }

    function _assertSolvent() internal view {
        (uint128 aB, uint128 aQ,) = bs.agentState(idA);
        (uint128 bB, uint128 bQ,) = bs.agentState(idB);
        assertLe(uint256(aB) + bB, baseTok.balanceOf(address(bs)), "base solvent");
        assertLe(uint256(aQ) + bQ, quoteTok.balanceOf(address(bs)), "quote solvent");
    }
}
