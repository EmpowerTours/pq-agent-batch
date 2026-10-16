// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Vm } from "forge-std/Test.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";
import { AgentFees } from "../src/AgentFees.sol";
import { MockToken } from "../src/dex/MockToken.sol";
import { V2Fixture } from "./helpers/V2Fixture.sol";
import { ReentrantToken, ReentrantOperator } from "./helpers/FeeTestTokens.sol";

/// Prepaid fee balances, treasury accounting, registration fee + bond, low-balance alerts, top-up.
contract AgentFeesTest is V2Fixture {
    address treasury = makeAddr("treasury-multisig");
    address keeper = makeAddr("keeper");
    MockToken usdc;
    uint64 nonceA = 1;

    bytes32 constant LOW_SIG = keccak256("LowFeeBalance(uint32,uint256,uint256)");

    function setUp() public override {
        super.setUp();
        usdc = new MockToken("Mock USDC", "mUSDC", 6);
        vm.startPrank(admin);
        reg.setTreasury(treasury);
        bs.listFeeToken(1, address(usdc));
        bs.setFeeConfig(0, 1e15, 0, true);       // 0.001 MON per action, uncapped
        bs.setFeeConfig(1, 10_000, 0, true);     // 0.01 mUSDC per action
        vm.stopPrank();
        vm.deal(opA, 100 ether);
        vm.deal(opB, 100 ether);
    }

    // ------------------------------------------------------------ helpers

    function _fundNative(uint32 id, uint256 amt) internal {
        vm.deal(address(this), address(this).balance + amt);
        bs.depositFeeNative{ value: amt }(id);
    }

    function _useUsdc(uint32 id, address op, uint256 amt) internal {
        vm.prank(op);
        bs.selectFeeToken(id, 1);
        if (amt > 0) {
            vm.startPrank(op);
            usdc.faucet(amt);
            usdc.approve(address(bs), amt);
            bs.depositFeeToken(id, amt);
            vm.stopPrank();
        }
    }

    function _bal(uint32 id) internal view returns (uint96 b) { (b,,,) = bs.feeAccount(id); }
    function _low(uint32 id) internal view returns (bool l) { (,,, l) = bs.feeAccount(id); }

    /// A-only batch of `count` small sells, next nonces.
    function _settleA(uint16 count) internal {
        bytes memory blob = _hdr(idA, count, nonceA, exp, PK_A);
        for (uint256 i; i < count; ++i) blob = bytes.concat(blob, _ord(false, 1e18, 0));
        nonceA += count;
        bs.settle(uint64(nonceA), blob, _proof(uint64(nonceA), blob));
    }

    function _countLow(Vm.Log[] memory logs) internal view returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(bs) && logs[i].topics[0] == LOW_SIG) ++n;
        }
    }

    // ------------------------------------------------------------ deduction

    function test_FeeDeduction_Native_TwoAgents() public {
        _fundNative(idA, 1 ether);
        _fundNative(idB, 1 ether);
        bytes memory blob = _twoAgentBatch();               // A: 2 orders, B: 1 order
        vm.expectEmit(true, true, false, true, address(bs));
        emit AgentFees.FeesCharged(1, 0, 3e15);
        bs.settle(1, blob, _proof(1, blob));
        assertEq(_bal(idA), 1 ether - 2e15, "A charged 2 actions");
        assertEq(_bal(idB), 1 ether - 1e15, "B charged 1 action");
        assertEq(bs.accruedFees(0), 3e15, "accrued for treasury");
        assertEq(address(bs).balance, uint256(_bal(idA)) + _bal(idB) + bs.accruedFees(0), "native solvent");
    }

    function test_FeeCapPerBatch() public {
        vm.prank(admin);
        bs.setFeeConfig(0, 1e15, 15e14, true);              // cap 0.0015 MON per agent per batch
        _fundNative(idA, 1 ether);
        _fundNative(idB, 1 ether);
        assertEq(bs.feeQuote(idA, 2), 15e14);
        assertEq(bs.feeQuote(idA, 1), 1e15);
        bytes memory blob = _twoAgentBatch();
        bs.settle(1, blob, _proof(1, blob));
        assertEq(_bal(idA), 1 ether - 15e14, "A capped");
        assertEq(_bal(idB), 1 ether - 1e15, "B under cap");
    }

    function test_FeeDeduction_ERC20_And_ZeroFeeNative() public {
        vm.prank(admin);
        bs.setFeeConfig(0, 0, 0, true);                     // native free: B pays nothing, no write
        _useUsdc(idA, opA, 1e6);
        bytes memory blob = _twoAgentBatch();
        bs.settle(1, blob, _proof(1, blob));
        assertEq(_bal(idA), 1e6 - 20_000);
        assertEq(_bal(idB), 0);
        assertEq(bs.accruedFees(1), 20_000);
        assertEq(bs.accruedFees(0), 0);
        assertEq(usdc.balanceOf(address(bs)), uint256(_bal(idA)) + bs.accruedFees(1));
    }

    // ------------------------------------------------------------ insufficient balance

    function test_InsufficientFeeBalance_RejectsWholeBatch() public {
        _fundNative(idA, 1 ether);
        _fundNative(idB, 5e14);                             // needs 1e15
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.InsufficientFeeBalance.selector, idB, 5e14, 1e15));
        bs.settle(1, blob, proof);
        // nothing moved: no free settlement, no partial fee, nonces untouched
        assertEq(_bal(idA), 1 ether);
        (,, uint64 nA) = _state(idA);
        assertEq(nA, 0);
        // the service re-batches without B
        bytes memory onlyA = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, 1e18, 0));
        bs.settle(2, onlyA, _proof(2, onlyA));
        assertEq(_bal(idA), 1 ether - 1e15);
    }

    function test_UnfundedAgentRejectedWhenFeesOn() public {
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.InsufficientFeeBalance.selector, idA, 0, 2e15));
        bs.settle(1, blob, proof);
    }

    // ------------------------------------------------------------ treasury

    function test_TreasuryAccountingAndSweep() public {
        _fundNative(idA, 1 ether);
        _settleA(3);
        _settleA(4);
        assertEq(bs.accruedFees(0), 7e15);
        vm.prank(keeper);                                   // permissionless
        bs.sweepFees(0);
        assertEq(treasury.balance, 7e15);
        assertEq(bs.accruedFees(0), 0);
        assertEq(address(bs).balance, _bal(idA));
        bs.sweepFees(0);                                    // nothing left: no-op
        assertEq(treasury.balance, 7e15);
    }

    function test_FeeAdminOnly() public {
        vm.expectRevert(AgentFees.NotAdmin.selector);
        bs.setFeeConfig(0, 1, 0, true);
        vm.expectRevert(AgentFees.NotAdmin.selector);
        bs.listFeeToken(2, address(usdc));
        vm.expectRevert(AgentRegistry.NotAdmin.selector);
        reg.setTreasury(address(this));
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.BadFeeToken.selector, uint8(1)));
        bs.listFeeToken(1, address(0xBEEF));                // write-once
        vm.expectRevert(abi.encodeWithSelector(AgentFees.BadFeeToken.selector, uint8(2)));
        bs.setFeeConfig(2, 1, 0, true);                     // unlisted
        vm.expectRevert(AgentFees.DelayTooLong.selector);
        bs.setFeeWithdrawDelay(8 days);
        vm.stopPrank();
    }

    // ------------------------------------------------------------ registration fee + bond

    function test_RegistrationFeeAndRefundableBond() public {
        vm.prank(admin);
        reg.setRegistrationFee(0.5 ether);
        vm.deal(admin, 10 ether);
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.StakeTooLow.selector, 1 ether, 1.5 ether));
        reg.registerAgent{ value: 1 ether }(opA, keccak256("k3"), 1, 1);
        uint32 id = reg.registerAgent{ value: 2 ether }(opA, keccak256("k3"), 1, 1);
        vm.stopPrank();
        (,,, uint96 stake,,) = reg.agents(id);
        assertEq(stake, 1.5 ether, "bond = value - fee");
        assertEq(reg.accruedRegistrationFees(), 0.5 ether);
        reg.sweepRegistrationFees();
        assertEq(treasury.balance, 0.5 ether);
        assertEq(reg.accruedRegistrationFees(), 0);
        uint256 before = opA.balance;
        vm.prank(admin);
        reg.retire(id);
        assertEq(opA.balance - before, 1.5 ether, "bond refunded, fee not");
    }

    function test_SelfRegistration() public {
        address dev = makeAddr("agent-dev");
        vm.deal(dev, 5 ether);
        vm.prank(dev);
        vm.expectRevert(AgentRegistry.RegistrationClosed.selector);
        reg.selfRegister{ value: 2 ether }(keccak256("dev-key"));
        vm.startPrank(admin);
        reg.setRegistrationFee(0.25 ether);
        reg.setOpenRegistration(true, 10e18, 20e18);
        vm.stopPrank();
        vm.prank(dev);
        uint32 id = reg.selfRegister{ value: 1.25 ether }(keccak256("dev-key"));
        (address op, bool active,, uint96 stake, uint128 cB, uint128 cQ) = reg.agents(id);
        assertEq(op, dev);
        assertTrue(active);
        assertEq(stake, 1 ether);
        assertEq(cB, 10e18);
        assertEq(cQ, 20e18);
        assertTrue(reg.isAuthorized(id, keccak256("dev-key")));
        assertFalse(reg.isAuthorized(id, keccak256("other")));
        vm.prank(dev);
        reg.kill(id);
        assertFalse(reg.isAuthorized(id, keccak256("dev-key")));
    }

    // ------------------------------------------------------------ low-balance alerts

    function test_LowBalanceEmittedOncePerCrossing() public {
        _fundNative(idA, 5e15);
        vm.prank(opA);
        bs.setFeeAlert(idA, 25e14);

        vm.recordLogs();
        _settleA(2);                                        // 5 -> 3 (>= 2.5): no alert
        assertEq(_countLow(vm.getRecordedLogs()), 0);

        vm.expectEmit(true, false, false, true, address(bs));
        emit AgentFees.LowFeeBalance(idA, 2e15, 25e14);
        _settleA(1);                                        // 3 -> 2: crossing, alert
        assertTrue(_low(idA));

        vm.recordLogs();
        _settleA(1);                                        // 2 -> 1: still low, no repeat
        assertEq(_countLow(vm.getRecordedLogs()), 0);

        _fundNative(idA, 5e15);                             // refill to 6: re-armed
        assertFalse(_low(idA));
        vm.recordLogs();
        _settleA(2);                                        // 6 -> 4: above, nothing
        assertEq(_countLow(vm.getRecordedLogs()), 0);
        vm.recordLogs();
        _settleA(2);                                        // 4 -> 2: new crossing, alert again
        assertEq(_countLow(vm.getRecordedLogs()), 1);
    }

    function test_PartialRefillBelowThresholdDoesNotRearm() public {
        _fundNative(idA, 3e15);
        vm.prank(opA);
        bs.setFeeAlert(idA, 25e14);
        _settleA(1);                                        // 3 -> 2: alert
        _fundNative(idA, 1e14);                             // 2.1: still below, stays "low"
        assertTrue(_low(idA));
        vm.recordLogs();
        _settleA(1);
        assertEq(_countLow(vm.getRecordedLogs()), 0);
    }

    function test_SetAlertAboveBalanceAlertsImmediately() public {
        _fundNative(idA, 1e15);
        vm.expectEmit(true, false, false, true, address(bs));
        emit AgentFees.LowFeeBalance(idA, 1e15, 2e15);
        vm.prank(opA);
        bs.setFeeAlert(idA, 2e15);
        vm.expectRevert(AgentFees.NotOperator.selector);
        bs.setFeeAlert(idA, 0);
    }

    function test_RemainingActionsView() public {
        _fundNative(idA, 7.5e15);
        assertEq(bs.remainingActions(idA), 7);
        vm.prank(admin);
        bs.setFeeConfig(0, 0, 0, true);
        assertEq(bs.remainingActions(idA), type(uint256).max);
    }

    // ------------------------------------------------------------ withdrawals

    function test_WithdrawalDelayAndMinBalance() public {
        vm.prank(admin);
        bs.setFeeWithdrawDelay(1 days);
        _fundNative(idA, 5e15);
        vm.expectRevert(AgentFees.NotOperator.selector);
        bs.requestFeeWithdrawal(idA, 5e15, address(this));
        vm.prank(opA);
        bs.requestFeeWithdrawal(idA, 5e15, opA);
        vm.prank(opA);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.WithdrawalNotReady.selector, uint64(block.timestamp + 1 days)));
        bs.executeFeeWithdrawal(idA);
        _settleA(2);                                        // pending balance still pays for a proved batch
        vm.warp(block.timestamp + 1 days);
        exp = uint32(block.timestamp + 60);
        uint256 before = opA.balance;
        vm.prank(opA);
        bs.executeFeeWithdrawal(idA);
        assertEq(opA.balance - before, 3e15, "pays min(requested, balance)");
        assertEq(_bal(idA), 0);
        vm.prank(opA);
        vm.expectRevert(AgentFees.NoPendingWithdrawal.selector);
        bs.executeFeeWithdrawal(idA);
    }

    function test_SelectTokenRequiresEmptyAccount() public {
        _fundNative(idA, 1e15);
        vm.prank(opA);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.FeeAccountNotEmpty.selector, idA));
        bs.selectFeeToken(idA, 1);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.WrongFeeToken.selector, idA, uint8(0)));
        bs.depositFeeToken(idA, 1);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.UnknownAgent.selector, uint32(99)));
        bs.depositFeeNative{ value: 1 }(99);
    }

    // ------------------------------------------------------------ top-up

    function _topUpSetup(uint96 threshold, uint96 amount, uint256 allowance) internal {
        _useUsdc(idA, opA, 0);
        vm.startPrank(opA);
        bs.setFeeAlert(idA, threshold);
        bs.setAutoTopUp(idA, amount);
        usdc.faucet(100_000e6);
        usdc.approve(address(bs), allowance);
        vm.stopPrank();
    }

    function test_TopUp_PullsConfiguredAmountOnlyWhenLow() public {
        _topUpSetup(100e6, 30e6, 1_000e6);
        uint256 opBefore = usdc.balanceOf(opA);
        vm.startPrank(keeper);
        bs.topUp(idA);
        bs.topUp(idA);
        bs.topUp(idA);
        assertEq(_bal(idA), 90e6);
        assertTrue(_low(idA));
        bs.topUp(idA);                                      // 120 >= 100: re-armed
        assertEq(_bal(idA), 120e6);
        assertFalse(_low(idA));
        vm.expectRevert(abi.encodeWithSelector(AgentFees.NotBelowThreshold.selector, idA, 120e6, 100e6));
        bs.topUp(idA);
        vm.stopPrank();
        assertEq(opBefore - usdc.balanceOf(opA), 120e6, "pulled exactly 4 x amount from owner");
        assertEq(usdc.balanceOf(keeper), 0);
    }

    function test_TopUp_CannotExceedAllowance() public {
        _topUpSetup(100e6, 30e6, 50e6);
        vm.startPrank(keeper);
        bs.topUp(idA);                                      // 30 of 50
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, address(bs), 20e6, 30e6));
        bs.topUp(idA);
        vm.stopPrank();
        assertEq(_bal(idA), 30e6);
    }

    function test_TopUp_CannotPullForOtherAgents() public {
        _topUpSetup(100e6, 30e6, 1_000e6);                  // opA approved the contract
        // opB's agent: B's top-up can only pull from opB, never from opA's allowance
        _useUsdc(idB, opB, 0);
        vm.startPrank(opB);
        bs.setFeeAlert(idB, 100e6);
        bs.setAutoTopUp(idB, 30e6);
        vm.stopPrank();
        uint256 aBefore = usdc.balanceOf(opA);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, address(bs), 0, 30e6));
        bs.topUp(idB);
        assertEq(usdc.balanceOf(opA), aBefore);
        // a stranger cannot (re)configure A's top-up
        vm.prank(keeper);
        vm.expectRevert(AgentFees.NotOperator.selector);
        bs.setAutoTopUp(idA, 1_000e6);
        // and a top-up credits only the named agent
        bs.topUp(idA);
        assertEq(_bal(idA), 30e6);
        assertEq(_bal(idB), 0);
    }

    function test_TopUp_DisabledAndNativeRejected() public {
        vm.expectRevert(abi.encodeWithSelector(AgentFees.TopUpDisabled.selector, idA));
        bs.topUp(idA);
        vm.startPrank(opA);
        bs.setFeeAlert(idA, 1e15);
        bs.setAutoTopUp(idA, 1e15);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(AgentFees.WrongFeeToken.selector, idA, uint8(0)));
        bs.topUp(idA);                                      // native cannot be pulled
    }

    function test_TopUp_AfterSettlementCrossing() public {
        _topUpSetup(50_000, 100_000, 1_000e6);
        vm.startPrank(opA);
        usdc.approve(address(bs), type(uint256).max);
        bs.depositFeeToken(idA, 60_000);                    // 6 actions worth
        vm.stopPrank();
        vm.recordLogs();
        _settleA(2);                                        // 60k -> 40k < 50k
        assertEq(_countLow(vm.getRecordedLogs()), 1);
        vm.prank(keeper);
        bs.topUp(idA);                                      // what the watcher does on the alert
        assertEq(_bal(idA), 140_000);
        assertFalse(_low(idA));
    }

    // ------------------------------------------------------------ reentrancy

    function test_Reentrancy_TopUpTokenCannotReenter() public {
        ReentrantToken evil = new ReentrantToken();
        vm.startPrank(admin);
        bs.listFeeToken(2, address(evil));
        bs.setFeeConfig(2, 1, 0, true);
        vm.stopPrank();
        vm.startPrank(opA);
        bs.selectFeeToken(idA, 2);
        bs.setFeeAlert(idA, 100);
        bs.setAutoTopUp(idA, 50);
        evil.approve(address(bs), type(uint256).max);
        vm.stopPrank();
        evil.mint(opA, 1_000);
        evil.arm(address(bs), abi.encodeCall(AgentFees.topUp, (idA)));
        bs.topUp(idA);
        assertTrue(evil.reentered());
        assertEq(bytes4(evil.lastRevert()), ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        assertEq(_bal(idA), 50, "only the outer top-up landed");
        assertEq(evil.balanceOf(address(bs)), 50);
    }

    function test_Reentrancy_SettleFromTokenHookBlocked() public {
        ReentrantToken evil = new ReentrantToken();
        vm.startPrank(admin);
        bs.listFeeToken(2, address(evil));
        bs.setFeeConfig(2, 1, 0, true);
        vm.stopPrank();
        vm.prank(opA);
        bs.selectFeeToken(idA, 2);
        evil.mint(address(this), 1_000);
        evil.approve(address(bs), 1_000);
        bytes memory blob = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, 1e18, 0));
        evil.arm(address(bs), abi.encodeCall(BatchSettlementV2.settle, (1, blob, _proof(1, blob))));
        bs.depositFeeToken(idA, 1_000);
        assertEq(bytes4(evil.lastRevert()), ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        (,, uint64 n) = _state(idA);
        assertEq(n, 0, "settle did not run inside the deposit");
    }

    function test_Reentrancy_NativeWithdrawalBlocked() public {
        ReentrantOperator op = new ReentrantOperator();
        vm.prank(admin);
        uint32 id = reg.registerAgent{ value: 1 ether }(address(op), keccak256("op-key"), 1, 1);
        _fundNative(id, 4e15);
        op.exec(address(bs), abi.encodeCall(AgentFees.requestFeeWithdrawal, (id, 1e15, address(op))));
        op.arm(address(bs), abi.encodeCall(AgentFees.executeFeeWithdrawal, (id)));
        op.exec(address(bs), abi.encodeCall(AgentFees.executeFeeWithdrawal, (id)));
        assertTrue(op.reentered());
        assertEq(bytes4(op.lastRevert()), ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        assertEq(_bal(id), 3e15);
        assertEq(address(op).balance, 1e15);
    }

    // ------------------------------------------------------------ fuzz

    /// Fee math matches min(n * fee, cap) per agent, a short balance always reverts, and native
    /// MON held == sum of fee balances + accrued fees.
    function testFuzz_FeeMathAndSolvency(uint72 fee, uint72 cap, uint8 nA, uint8 nB, uint96 depA, uint96 depB) public {
        fee = uint72(bound(fee, 0, 1e18));
        cap = uint72(bound(cap, 0, 50e18));
        nA = uint8(bound(nA, 1, 30));
        nB = uint8(bound(nB, 1, 30));
        depA = uint96(bound(depA, 0, 40e18));
        depB = uint96(bound(depB, 0, 40e18));
        vm.prank(admin);
        bs.setFeeConfig(0, fee, cap, true);
        if (depA > 0) _fundNative(idA, depA);
        if (depB > 0) _fundNative(idB, depB);

        bytes memory blob = _hdr(idA, nA, 1, exp, PK_A);
        for (uint256 i; i < nA; ++i) blob = bytes.concat(blob, _ord(i % 2 == 0, 1e18, 0));
        blob = bytes.concat(blob, _hdr(idB, nB, 1, exp, PK_B));
        for (uint256 i; i < nB; ++i) blob = bytes.concat(blob, _ord(i % 2 == 1, 1e18, 0));

        uint256 fA = uint256(nA) * fee;
        if (cap != 0 && fA > cap) fA = cap;
        uint256 fB = uint256(nB) * fee;
        if (cap != 0 && fB > cap) fB = cap;
        assertEq(bs.feeQuote(idA, nA), fA);

        bytes memory proof = _proof(1, blob);
        if (fA > depA) {
            vm.expectRevert(abi.encodeWithSelector(AgentFees.InsufficientFeeBalance.selector, idA, uint256(depA), fA));
            bs.settle(1, blob, proof);
        } else if (fB > depB) {
            vm.expectRevert(abi.encodeWithSelector(AgentFees.InsufficientFeeBalance.selector, idB, uint256(depB), fB));
            bs.settle(1, blob, proof);
        } else {
            bs.settle(1, blob, proof);
            assertEq(_bal(idA), depA - fA);
            assertEq(_bal(idB), depB - fB);
            assertEq(bs.accruedFees(0), fA + fB);
        }
        assertEq(address(bs).balance, uint256(_bal(idA)) + _bal(idB) + bs.accruedFees(0), "native solvent");
        _assertSolvent();
    }

    /// Any sequence of deposits / batches / sweeps keeps the books balanced.
    function testFuzz_SequenceSolvency(uint256 seed) public {
        uint256 swept;
        for (uint256 k; k < 8; ++k) {
            uint256 r = uint256(keccak256(abi.encode(seed, k)));
            uint256 op = r % 3;
            if (op == 0) _fundNative(idA, bound(r >> 8, 1, 5e15));
            else if (op == 1) {
                uint16 c = uint16(bound(r >> 8, 1, 6));
                if (bs.feeQuote(idA, c) <= _bal(idA)) _settleA(c);
            } else {
                swept += bs.accruedFees(0);
                bs.sweepFees(0);
            }
            assertEq(address(bs).balance, uint256(_bal(idA)) + bs.accruedFees(0));
            assertEq(treasury.balance, swept);
        }
    }

    receive() external payable {}
}
