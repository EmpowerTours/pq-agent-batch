// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// One regression test per audit fix (see audits/REPORT.md). Each test fails on the pre-audit code (e5aa627).

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { AgentRegistry } from "../../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../../src/BatchSettlementV2.sol";
import { AgentFees } from "../../src/AgentFees.sol";
import { MiniAMM } from "../../src/dex/MiniAMM.sol";
import { MockToken } from "../../src/dex/MockToken.sol";
import { ISP1Verifier } from "../../src/interfaces/ISP1Verifier.sol";
import { V2Fixture } from "../helpers/V2Fixture.sol";

/// 1% burned on every transfer (fee-on-transfer token).
contract FeeOnTransferToken is ERC20 {
    constructor() ERC20("FoT", "FOT") { _mint(msg.sender, 1e30); }
    function _update(address from, address to, uint256 v) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 burn = v / 100;
            super._update(from, address(0), burn);
            v -= burn;
        }
        super._update(from, to, v);
    }
}

contract AuditFixesTest is V2Fixture {
    // ------------------------------------------------------------ M-01 batch griefing

    /// Agent A withdraws its whole trading balance AFTER the batch was proved. Before: the whole proved batch
    /// reverted (InsufficientBalance), wasting the proof for B. After: A is skipped, B settles.
    function test_M01_WithdrawAfterProvingOnlySkipsGriefer() public {
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        vm.prank(opA);
        bs.withdraw(idA, 1_000e18, 2_000e18, opA);
        vm.expectEmit(address(bs));
        emit BatchSettlementV2.GroupSkipped(1, idA, abi.encodeWithSelector(BatchSettlementV2.InsufficientBalance.selector, idA));
        bs.settle(1, blob, proof);
        (,, uint64 nB) = _state(idB);
        assertEq(nB, 1, "honest agent settled");
        (,, uint64 nA) = _state(idA);
        assertEq(nA, 0);
        _assertSolvent();
    }

    function test_M01_SelfKillAfterProvingOnlySkipsGriefer() public {
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        vm.prank(opA);
        reg.kill(idA);
        bs.settle(1, blob, proof);
        (,, uint64 nB) = _state(idB);
        assertEq(nB, 1);
    }

    function test_M01_RevokedKeyAfterProvingOnlySkipsGriefer() public {
        vm.prank(opA);
        reg.addKey(idA, keccak256("second key"));
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        vm.prank(opA);
        reg.revokeKey(idA, PK_A);
        vm.expectEmit(address(bs));
        emit BatchSettlementV2.GroupSkipped(1, idA, abi.encodeWithSelector(AgentRegistry.UnknownKey.selector, idA, PK_A));
        bs.settle(1, blob, proof);
        (,, uint64 nB) = _state(idB);
        assertEq(nB, 1);
    }

    /// A skipped group can still be settled later from the SAME proof (its signed orders are still valid
    /// until expiry), but a group that settled can never settle again.
    function test_M01_SkippedGroupSettlesOnResubmitOnlyOnce() public {
        vm.prank(guardian);
        reg.kill(idA);
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        bs.settle(1, blob, proof);              // B settles, A skipped
        vm.prank(admin);
        reg.revive(idA);
        bs.settle(1, blob, proof);              // A settles now, B skipped (replay)
        (,, uint64 nA) = _state(idA);
        (uint96 bB, uint96 bQ, uint64 nB) = _state(idB);
        assertEq(nA, 2); assertEq(nB, 1);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.NonceNotIncreasing.selector, idA, uint64(1), uint64(2)));
        bs.settle(1, blob, proof);              // nothing left: reverts
        (uint96 bB2, uint96 bQ2,) = _state(idB);
        assertEq(bB2, bB); assertEq(bQ2, bQ);
        _assertSolvent();
    }

    function test_M01_ExpiredGroupSkippedOthersSettle() public {
        bytes memory blob = bytes.concat(
            _hdr(idA, 1, 1, uint32(block.timestamp + 10), PK_A), _ord(false, 1e18, 0),
            _hdr(idB, 1, 1, uint32(block.timestamp + 1000), PK_B), _ord(true, 2e18, 0));
        bytes memory proof = _proof(1, blob);
        vm.warp(block.timestamp + 100);
        vm.expectEmit(address(bs));
        emit BatchSettlementV2.GroupSkipped(1, idA, abi.encodeWithSelector(BatchSettlementV2.Expired.selector, uint256(0)));
        bs.settle(1, blob, proof);
        (,, uint64 nB) = _state(idB);
        assertEq(nB, 1);
    }

    /// Framing, proof and slippage errors still revert the WHOLE batch (no partial settlement of a bad proof).
    function test_M01_BadProofStillRevertsEvenWithSkips() public {
        vm.prank(guardian);
        reg.kill(idA);
        bytes memory blob = _twoAgentBatch();
        bytes memory wrong = _proof(2, blob);
        vm.expectRevert();
        bs.settle(1, blob, wrong);
    }

    // ------------------------------------------------------------ L-02 fee-on-transfer

    function test_L02_FeeOnTransferFeeTokenRejected() public {
        FeeOnTransferToken fot = new FeeOnTransferToken();
        vm.startPrank(admin);
        bs.listFeeToken(1, address(fot));
        bs.setFeeConfig(1, 1, 0, true);
        vm.stopPrank();
        vm.prank(opA);
        bs.selectFeeToken(idA, 1);
        fot.approve(address(bs), 1e18);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.UnsupportedToken.selector, 1e18, 0.99e18));
        bs.depositFeeToken(idA, 1e18);
    }

    function test_L02_FeeOnTransferTradingTokenRejected() public {
        FeeOnTransferToken fot = new FeeOnTransferToken();
        MockToken m = new MockToken("M", "M", 18);
        MiniAMM p2 = new MiniAMM(address(fot), address(m));
        BatchSettlementV2 bs2 = new BatchSettlementV2(ver, VKEY, reg, p2);
        fot.approve(address(bs2), type(uint256).max);
        bool fotIsBase = address(p2.token0()) == address(fot);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.UnsupportedToken.selector, 100e18, 99e18));
        if (fotIsBase) bs2.deposit(idA, 100e18, 0);
        else bs2.deposit(idA, 0, 100e18);
    }

    // ------------------------------------------------------------ L-03 deposits to unregistered ids

    function test_L03_DepositToUnregisteredIdRejected() public {
        _mint(baseTok, address(this), 1e18);
        vm.expectRevert(abi.encodeWithSelector(AgentFees.UnknownAgent.selector, uint32(3)));
        bs.deposit(3, 1e18, 0);   // id 3 would belong to whoever registers next
    }

    // ------------------------------------------------------------ L-04 admin handover

    function test_L04_TwoStepAdminTransfer() public {
        address safe = makeAddr("safe-multisig");
        vm.prank(opA);
        vm.expectRevert(AgentRegistry.NotAdmin.selector);
        reg.transferAdmin(safe);
        vm.prank(admin);
        reg.transferAdmin(safe);
        assertEq(reg.admin(), admin, "not yet");
        vm.prank(opA);
        vm.expectRevert(AgentRegistry.NotPendingAdmin.selector);
        reg.acceptAdmin();
        vm.prank(safe);
        reg.acceptAdmin();
        assertEq(reg.admin(), safe);
        assertEq(reg.pendingAdmin(), address(0));
        // fee admin follows the registry admin
        vm.prank(admin);
        vm.expectRevert(AgentFees.NotAdmin.selector);
        bs.setFeeConfig(0, 1, 0, true);
        vm.prank(safe);
        bs.setFeeConfig(0, 1, 0, true);
    }

    // ------------------------------------------------------------ L-05 constructor validation

    function test_L05_ConstructorRejectsBadWiring() public {
        vm.expectRevert(BatchSettlementV2.BadConfig.selector);
        new BatchSettlementV2(ISP1Verifier(address(0xdead)), VKEY, reg, pool);      // codeless verifier
        vm.expectRevert(BatchSettlementV2.BadConfig.selector);
        new BatchSettlementV2(ver, bytes32(0), reg, pool);                          // unpinned vkey
        vm.expectRevert(BatchSettlementV2.BadConfig.selector);
        new BatchSettlementV2(ver, VKEY, AgentRegistry(address(0xbeef)), pool);     // codeless registry
    }

    // ------------------------------------------------------------ L-06 dust residual

    /// 2 wei of quote: residual to the AMM quotes 0 out. Before: MiniAMM.swap(0,0) reverted the batch.
    function test_L06_DustResidualDoesNotRevert() public {
        bytes memory blob = bytes.concat(_hdr(idB, 1, 1, exp, PK_B), _ord(true, 2, 0));
        bs.settle(1, blob, _proof(1, blob));
        (,, uint64 nB) = _state(idB);
        assertEq(nB, 1);
        _assertSolvent();
    }

    // ------------------------------------------------------------ L-07 zero-address payouts

    function test_L07_ZeroAddressPayoutsRejected() public {
        vm.prank(opA);
        vm.expectRevert(AgentFees.ZeroAddress.selector);
        bs.withdraw(idA, 1, 0, address(0));
        vm.prank(opA);
        vm.expectRevert(AgentFees.ZeroAddress.selector);
        bs.requestFeeWithdrawal(idA, 1, address(0));
        vm.prank(admin);
        vm.expectRevert(AgentRegistry.ZeroValue.selector);
        reg.slash(idA, 1, payable(address(0)));
    }

    // ------------------------------------------------------------ domain separation (no fix needed)

    /// The same batch bytes under another settlement address or chain produce a different digest.
    function test_DomainSeparation_DigestBindsChainAndContract() public {
        bytes memory blob = _twoAgentBatch();
        bytes32 d = bs.batchDigest(1, blob);
        BatchSettlementV2 other = new BatchSettlementV2(ver, VKEY, reg, pool);
        assertTrue(other.batchDigest(1, blob) != d, "contract bound");
        vm.chainId(143);
        assertTrue(bs.batchDigest(1, blob) != d, "chain bound");
    }

    // ------------------------------------------------------------ property fuzzing

    /// Per-batch caps: a single-agent batch settles iff its base-in and quote-in sums are within caps.
    function testFuzz_CapsEnforcedPerBatch(uint128 capB, uint128 capQ, uint96 s1, uint96 s2, uint96 b1) public {
        capB = uint128(bound(capB, 0, 600e18));
        capQ = uint128(bound(capQ, 0, 1_200e18));
        s1 = uint96(bound(s1, 1, 400e18)); s2 = uint96(bound(s2, 1, 400e18)); b1 = uint96(bound(b1, 1, 1_000e18));
        vm.prank(admin);
        reg.setCaps(idA, capB, capQ);
        bytes memory blob = bytes.concat(_hdr(idA, 3, 1, exp, PK_A), _ord(false, s1, 0), _ord(false, s2, 0), _ord(true, b1, 0));
        bytes memory proof = _proof(1, blob);
        if (uint256(s1) + s2 > capB || b1 > capQ) {
            vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.CapExceeded.selector, idA));
            bs.settle(1, blob, proof);
        } else {
            bs.settle(1, blob, proof);
            (,, uint64 n) = _state(idA);
            assertEq(n, 3);
        }
        _assertSolvent();
    }

    /// Any mix of tiny and large amounts on both sides settles (no AMM zero-output brick) and stays solvent.
    function testFuzz_ResidualNeverBricks(uint96 sellAmt, uint96 buyAmt) public {
        sellAmt = uint96(bound(sellAmt, 1, 1_000e18));
        buyAmt = uint96(bound(buyAmt, 1, 2_000e18));
        bytes memory blob = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, sellAmt, 0),
            _hdr(idB, 1, 1, exp, PK_B), _ord(true, buyAmt, 0));
        bs.settle(1, blob, _proof(1, blob));
        (,, uint64 nA) = _state(idA);
        (,, uint64 nB) = _state(idB);
        assertEq(nA, 1); assertEq(nB, 1);
        _assertSolvent();
    }
}
