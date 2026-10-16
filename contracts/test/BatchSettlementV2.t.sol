// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test, Vm } from "forge-std/Test.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";
import { AgentFees } from "../src/AgentFees.sol";
import { MiniAMM } from "../src/dex/MiniAMM.sol";
import { MockToken } from "../src/dex/MockToken.sol";
import { HashBoundMockVerifier } from "./helpers/HashBoundMockVerifier.sol";
import { V2Fixture } from "./helpers/V2Fixture.sol";

contract BatchSettlementV2Test is V2Fixture {
    // ------------------------------------------------------------ happy path + parity

    function test_HappyPath_TwoAgents() public {
        bytes memory blob = _twoAgentBatch();
        (uint96 aB0, uint96 aQ0,) = _state(idA);
        (uint96 bB0, uint96 bQ0,) = _state(idB);
        uint256 poolBase0 = baseTok.balanceOf(address(pool));
        bs.settle(1, blob, _proof(1, blob));
        (uint96 aB1, uint96 aQ1, uint64 aN) = _state(idA);
        (uint96 bB1, uint96 bQ1, uint64 bN) = _state(idB);
        assertEq(aB0 - aB1, 150e18, "A sold 150 base");
        assertEq(bQ0 - bQ1, 200e18, "B spent 200 quote");
        assertEq(bB1 - bB0, 100e18, "B filled at mid");
        assertEq(baseTok.balanceOf(address(pool)) - poolBase0, 50e18, "only residual hits the AMM");
        assertGt(aQ1 - aQ0, 290e18);
        assertLt(aQ1 - aQ0, 300e18);
        assertEq(aN, 2);
        assertEq(bN, 1);
        _assertSolvent();
    }

    function test_ExcessQuoteGoesToAmm() public {
        bytes memory blob = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, 10e18, 0),
            _hdr(idB, 1, 1, exp, PK_B), _ord(true, 100e18, 0));
        uint256 poolQuote0 = quoteTok.balanceOf(address(pool));
        bs.settle(7, blob, _proof(7, blob));
        assertEq(quoteTok.balanceOf(address(pool)) - poolQuote0, 80e18, "80 quote residual to AMM");
        (, uint96 aQ,) = _state(idA);
        assertEq(aQ, 2_000e18 + 20e18, "seller filled at mid");
        _assertSolvent();
    }

    /// The Rust guest (zk-batch, v2) produced this batch + digest for settlement BS_ADDR on chain 20143.
    function test_GuestParityFixture() public {
        string memory fx = vm.readFile("test/fixtures/guest_v2_batch10.json");
        bytes memory blob = vm.parseJsonBytes(fx, ".batch");
        bytes32 digest = vm.parseJsonBytes32(fx, ".digest");
        uint64 batchId = uint64(vm.parseJsonUint(fx, ".batch_id"));
        assertEq(bs.batchDigest(batchId, blob), digest, "contract digest == guest digest");
        vm.recordLogs();
        bs.settle(batchId, blob, ver.proofFor(VKEY, abi.encode(digest)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory last = logs[logs.length - 1];
        (bytes32 d, uint256 n, uint256 baseIn, uint256 quoteIn,,) =
            abi.decode(last.data, (bytes32, uint256, uint256, uint256, uint256, uint256));
        assertEq(d, digest);
        assertEq(n, vm.parseJsonUint(fx, ".n"), "same order count as guest");
        assertEq(baseIn, vm.parseUint(vm.parseJsonString(fx, ".base_in")), "same base total as guest");
        assertEq(quoteIn, vm.parseUint(vm.parseJsonString(fx, ".quote_in")), "same quote total as guest");
        (,, uint64 aN) = _state(idA);
        (,, uint64 bN) = _state(idB);
        assertEq(aN, 5);  // host: group A nonces 1..5
        assertEq(bN, 10); // host: group B nonces 6..10 (firstNonce = from + 1)
    }

    // ------------------------------------------------------------ binding

    function test_TamperedAmountRejected() public {
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        blob[blob.length - 13] = 0x01; // low byte of B's amountIn
        vm.expectRevert(HashBoundMockVerifier.InvalidMockProof.selector);
        bs.settle(1, blob, proof);
    }

    function test_ModelHashIsBound() public {
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        blob[60] = bytes1(uint8(blob[60]) ^ 1); // inside A's modelHash (offset 50..81)
        vm.expectRevert(HashBoundMockVerifier.InvalidMockProof.selector);
        bs.settle(1, blob, proof);
    }

    function test_ExpiryIsBound() public {
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        blob[17] = bytes1(uint8(blob[17]) ^ 1); // A's expiry (offset 14..17)
        vm.expectRevert(HashBoundMockVerifier.InvalidMockProof.selector);
        bs.settle(1, blob, proof);
    }

    function test_BatchIdIsBound() public {
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(HashBoundMockVerifier.InvalidMockProof.selector);
        bs.settle(2, blob, proof);
    }

    // ------------------------------------------------------------ registry

    function test_UnregisteredAgentRejected() public {
        bytes memory blob = bytes.concat(_hdr(99, 1, 1, exp, PK_A), _ord(false, 1e18, 0));
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.UnknownAgent.selector, uint32(99)));
        bs.settle(1, blob, proof);
    }

    function test_UnregisteredKeyRejected() public {
        bytes memory blob = bytes.concat(_hdr(idA, 1, 1, exp, PK_B), _ord(false, 1e18, 0));
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.UnknownKey.selector, idA, PK_B));
        bs.settle(1, blob, proof);
    }

    function test_RevokedKeyRejected() public {
        vm.startPrank(opA);
        reg.addKey(idA, keccak256("agent-A-key-2"));
        reg.revokeKey(idA, PK_A);
        vm.stopPrank();
        bytes memory blob = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, 1e18, 0));
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.UnknownKey.selector, idA, PK_A));
        bs.settle(1, blob, proof);
    }

    /// audit M-01: a killed agent's group is skipped (event), the other agent still settles; a batch in
    /// which every group is unsettleable reverts with the first group's error.
    function test_KilledAgentRejected_ByGuardian() public {
        vm.prank(guardian);
        reg.kill(idB);
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        (uint96 bB0, uint96 bQ0,) = _state(idB);
        vm.expectEmit(address(bs));
        emit BatchSettlementV2.GroupSkipped(1, idB, abi.encodeWithSelector(AgentRegistry.AgentKilled.selector, idB));
        bs.settle(1, blob, proof);
        (uint96 bB1, uint96 bQ1, uint64 bN) = _state(idB);
        assertEq(bN, 0, "killed agent's nonce untouched");
        assertEq(bB1, bB0); assertEq(bQ1, bQ0);
        (,, uint64 aN) = _state(idA);
        assertEq(aN, 2, "live agent settled");
        _assertSolvent();

        bytes memory onlyB = bytes.concat(_hdr(idB, 1, 1, exp, PK_B), _ord(true, 1e18, 0));
        bytes memory proofB = _proof(2, onlyB);
        vm.expectRevert(abi.encodeWithSelector(AgentRegistry.AgentKilled.selector, idB));
        bs.settle(2, onlyB, proofB);
        vm.prank(guardian);
        vm.expectRevert(AgentRegistry.NotAdmin.selector);
        reg.revive(idB);
        vm.prank(admin);
        reg.revive(idB);
        bs.settle(2, onlyB, proofB);
        (,, bN) = _state(idB);
        assertEq(bN, 1);
    }

    function test_CapExceededRejected() public {
        vm.prank(admin);
        reg.setCaps(idA, 120e18, 2_000e18);
        bytes memory blob = _twoAgentBatch(); // A sells 150 > 120
        bytes memory proof = _proof(1, blob);
        vm.expectEmit(address(bs));
        emit BatchSettlementV2.GroupSkipped(1, idA, abi.encodeWithSelector(BatchSettlementV2.CapExceeded.selector, idA));
        bs.settle(1, blob, proof);
        (uint96 aB, , uint64 aN) = _state(idA);
        assertEq(aN, 0); assertEq(aB, 1_000e18, "over-cap agent not debited");
        bytes memory onlyA = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, 121e18, 0));
        bytes memory proofA = _proof(2, onlyA);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.CapExceeded.selector, idA));
        bs.settle(2, onlyA, proofA);
    }

    // ------------------------------------------------------------ replay / nonces

    function test_ReplayedBatchRejected() public {
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        bs.settle(1, blob, proof);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.NonceNotIncreasing.selector, idA, uint64(1), uint64(2)));
        bs.settle(1, blob, proof);
    }

    function test_ReplayedOrdersUnderNewBatchIdRejected() public {
        bytes memory blob = _twoAgentBatch();
        bs.settle(1, blob, _proof(1, blob));
        bytes memory proof2 = _proof(2, blob); // even with a valid proof for the new id
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.NonceNotIncreasing.selector, idA, uint64(1), uint64(2)));
        bs.settle(2, blob, proof2);
    }

    function test_ReplaySingleAgentGroupRejected() public {
        bytes memory blob = _twoAgentBatch();
        bs.settle(1, blob, _proof(1, blob));
        // B's group re-submitted alone (fresh A group in front, so only B replays)
        bytes memory b2 = bytes.concat(_hdr(idA, 1, 3, exp, PK_A), _ord(false, 1e18, 0),
            _hdr(idB, 1, 1, exp, PK_B), _ord(true, 200e18, 0));
        bytes memory proof = _proof(2, b2);
        (uint96 bB0, uint96 bQ0,) = _state(idB);
        vm.expectEmit(address(bs));
        emit BatchSettlementV2.GroupSkipped(2, idB,
            abi.encodeWithSelector(BatchSettlementV2.NonceNotIncreasing.selector, idB, uint64(1), uint64(1)));
        bs.settle(2, b2, proof);
        (uint96 bB1, uint96 bQ1, uint64 bN) = _state(idB);
        assertEq(bN, 1); assertEq(bB1, bB0); assertEq(bQ1, bQ0);   // replayed group did not execute again
        (,, uint64 aN) = _state(idA);
        assertEq(aN, 3);
    }

    function test_NonceGapAllowedAndAdvances() public {
        bytes memory blob = bytes.concat(_hdr(idA, 3, 100, exp, PK_A), _ord(false, 1e18, 0),
            _ord(true, 2e18, 0), _ord(false, 1e18, 0));
        bs.settle(1, blob, _proof(1, blob));
        (,, uint64 n) = _state(idA);
        assertEq(n, 102);
    }

    function test_NonceOverflowRejected() public {
        bytes memory blob = bytes.concat(_hdr(idA, 2, type(uint64).max, exp, PK_A), _ord(false, 1e18, 0), _ord(false, 1e18, 0));
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.Malformed.selector, uint256(0)));
        bs.settle(1, blob, proof);
    }

    function test_DuplicateOrDescendingAgentGroupsRejected() public {
        bytes memory dup = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, 1e18, 0),
            _hdr(idA, 1, 2, exp, PK_A), _ord(false, 1e18, 0));
        bytes memory proof = _proof(1, dup);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.OrdersNotGrouped.selector, uint256(1)));
        bs.settle(1, dup, proof);
        bytes memory desc = bytes.concat(_hdr(idB, 1, 1, exp, PK_B), _ord(false, 1e18, 0),
            _hdr(idA, 1, 1, exp, PK_A), _ord(false, 1e18, 0));
        proof = _proof(1, desc);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.OrdersNotGrouped.selector, uint256(1)));
        bs.settle(1, desc, proof);
    }

    // ------------------------------------------------------------ order checks

    function test_SlippageRejected() public {
        bytes memory blob = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, 100e18, 0),
            _hdr(idB, 1, 1, exp, PK_B), _ord(true, 200e18, 101e18)); // wants > mid
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.SlippageExceeded.selector, uint256(1), 100e18, 101e18));
        bs.settle(1, blob, proof);
    }

    function test_ExpiredRejected() public {
        bytes memory blob = bytes.concat(_hdr(idA, 1, 1, uint32(block.timestamp - 1), PK_A), _ord(false, 1e18, 0));
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.Expired.selector, uint256(0)));
        bs.settle(1, blob, proof);
    }

    function test_ZeroAmountRejected() public {
        bytes memory blob = bytes.concat(_hdr(idA, 2, 1, exp, PK_A), _ord(false, 1e18, 0), _ord(true, 0, 0));
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.ZeroAmount.selector, uint256(1)));
        bs.settle(1, blob, proof);
    }

    function test_InsufficientBalanceRejected() public {
        vm.prank(admin);
        reg.setCaps(idA, 5_000e18, 5_000e18);
        bytes memory blob = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), _ord(false, 1_001e18, 0));
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.InsufficientBalance.selector, idA));
        bs.settle(1, blob, proof);
    }

    function test_WithdrawOnlyOperator() public {
        vm.expectRevert(AgentFees.NotOperator.selector);
        bs.withdraw(idA, 1e18, 0, address(this));
        vm.prank(opA);
        bs.withdraw(idA, 1e18, 0, opA);
        assertEq(baseTok.balanceOf(opA), 1e18);
    }

    function test_DepositOverflowReverts() public {
        _mint(baseTok, address(this), 0);
        vm.expectRevert(); // uint96 balance overflow (checked add)
        bs.deposit(idA, type(uint96).max, 0);
    }

    // ------------------------------------------------------------ malformed encodings

    function _expectMalformed(bytes memory blob, uint256 offset) internal {
        bytes memory proof = _proof(1, blob);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.Malformed.selector, offset));
        bs.settle(1, blob, proof);
    }

    function test_EmptyBatchRejected() public {
        vm.expectRevert(BatchSettlementV2.EmptyBatch.selector);
        bs.settle(1, "", "");
    }

    function test_MalformedEncodingsRejected() public {
        bytes memory ok = bytes.concat(_hdr(idA, 2, 1, exp, PK_A), _ord(false, 1e18, 0), _ord(true, 2e18, 0));
        bytes memory truncHdr = new bytes(81);
        for (uint256 i; i < 81; ++i) truncHdr[i] = ok[i];
        _expectMalformed(truncHdr, 0);                                         // truncated header
        bytes memory truncOrd = new bytes(ok.length - 1);
        for (uint256 i; i < truncOrd.length; ++i) truncOrd[i] = ok[i];
        _expectMalformed(truncOrd, 82);                                        // truncated order
        _expectMalformed(bytes.concat(ok, hex"00"), ok.length);                // trailing byte
        _expectMalformed(bytes.concat(ok, new bytes(81)), ok.length);          // trailing partial header
        _expectMalformed(_hdr(idA, 0, 1, exp, PK_A), 0);                       // zero count
        bytes memory badFlags = bytes.concat(_hdr(idA, 1, 1, exp, PK_A), hex"02", new bytes(24));
        _expectMalformed(badFlags, 82);                                        // flags > 1
        bytes memory countTooBig = bytes.concat(_hdr(idA, 3, 1, exp, PK_A), _ord(false, 1e18, 0), _ord(true, 2e18, 0));
        _expectMalformed(countTooBig, 82);                                     // count beyond data
    }

    // ------------------------------------------------------------ fuzz

    /// Any single-byte change to a valid batch is rejected (decode error, registry, or proof).
    function testFuzz_AnyByteFlipRejected(uint256 pos, uint8 mask) public {
        mask = uint8(bound(mask, 1, 255));
        bytes memory blob = _twoAgentBatch();
        bytes memory proof = _proof(1, blob);
        pos = bound(pos, 0, blob.length - 1);
        blob[pos] = bytes1(uint8(blob[pos]) ^ mask);
        vm.expectRevert();
        bs.settle(1, blob, proof);
    }

    /// Arbitrary bytes, even with a "valid" proof for their digest, never settle and never
    /// hit a Panic (overflow / out-of-bounds) in the custom decoder.
    function testFuzz_RandomBlobNeverPanics(bytes calldata blob) public {
        vm.assume(blob.length > 0);
        bytes memory proof = _proof(1, blob);
        (bool ok, bytes memory ret) = address(bs).call(abi.encodeCall(BatchSettlementV2.settle, (1, blob, proof)));
        assertFalse(ok, "random bytes settled");
        assertTrue(ret.length >= 4, "revert without reason");
        bytes4 sel = bytes4(ret);
        assertTrue(sel != bytes4(0x4e487b71), "panic in decoder");
    }

    /// Random well-formed two-agent batches stay solvent and advance nonces.
    function testFuzz_WellFormedBatchesSolvent(uint256 seed, uint8 nA, uint8 nB) public {
        nA = uint8(bound(nA, 1, 20));
        nB = uint8(bound(nB, 1, 20));
        bytes memory blob = _hdr(idA, nA, 1, exp, PK_A);
        for (uint256 i; i < nA; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            blob = bytes.concat(blob, _ord(r & 1 == 1, uint96(bound(r >> 8, 1e15, 40e18)), 0));
        }
        blob = bytes.concat(blob, _hdr(idB, nB, 1, exp, PK_B));
        for (uint256 i; i < nB; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i + 100)));
            blob = bytes.concat(blob, _ord(r & 1 == 1, uint96(bound(r >> 8, 1e15, 40e18)), 0));
        }
        bs.settle(1, blob, _proof(1, blob));
        _assertSolvent();
        (,, uint64 a) = _state(idA);
        (,, uint64 b) = _state(idB);
        assertEq(a, nA);
        assertEq(b, nB);
    }
}
