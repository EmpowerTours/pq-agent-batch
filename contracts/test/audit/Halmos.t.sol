// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// Halmos symbolic checks (audit). Run: halmos --match-contract HalmosAudit --solver-timeout-assertion 0
// `check_*` functions are ignored by `forge test`. The SVM cheatcode interface is declared inline so CI needs no
// extra dependency.

import { Test } from "forge-std/Test.sol";
import { AgentRegistry } from "../../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../../src/BatchSettlementV2.sol";
import { MiniAMM } from "../../src/dex/MiniAMM.sol";
import { MockToken } from "../../src/dex/MockToken.sol";
import { ISP1Verifier } from "../../src/interfaces/ISP1Verifier.sol";

interface SVM {
    function createCalldata(string memory contractName) external pure returns (bytes memory);
    function createAddress(string memory name) external pure returns (address);
    function createBytes32(string memory name) external pure returns (bytes32);
    function createUint(uint256 bits, string memory name) external pure returns (uint256);
}

/// Proof soundness is out of scope here (it is the SNARK's job, tested with real proofs elsewhere):
/// this verifier accepts everything so the solver explores the settlement logic itself.
contract AcceptAllVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure { }
}

contract HalmosAudit is Test {
    SVM constant svm = SVM(address(uint160(uint256(keccak256("svm cheat code")))));
    address constant ADMIN = address(0xA11CE);
    address constant GUARDIAN = address(0x6A2D);
    address constant OP = address(0x0BEEF);
    bytes32 constant PK = bytes32(uint256(0x1234));

    AgentRegistry reg;
    BatchSettlementV2 bs;
    MockToken b;
    MockToken q;
    MiniAMM pool;
    uint32 id;

    function setUp() public {
        vm.warp(1_800_000_000);
        MockToken t0 = new MockToken("B", "B", 18);
        MockToken t1 = new MockToken("Q", "Q", 18);
        pool = new MiniAMM(address(t0), address(t1));
        b = MockToken(address(pool.token0()));
        q = MockToken(address(pool.token1()));
        b.faucet(100_000e18); q.faucet(100_000e18);
        b.approve(address(pool), type(uint256).max); q.approve(address(pool), type(uint256).max);
        pool.addLiquidity(50_000e18, 100_000e18, address(this));
        reg = new AgentRegistry(ADMIN, GUARDIAN, 1 ether);
        bs = new BatchSettlementV2(new AcceptAllVerifier(), keccak256("vk"), reg, pool);
        vm.deal(ADMIN, 10 ether);
        vm.prank(ADMIN);
        id = reg.registerAgent{ value: 1 ether }(OP, PK, 1_000e18, 2_000e18);
        b.faucet(10_000e18); q.faucet(20_000e18);
        b.approve(address(bs), type(uint256).max); q.approve(address(bs), type(uint256).max);
        bs.deposit(id, 10_000e18, 20_000e18);
    }

    /// Bonds can only leave the registry through an admin call (slash / retire / fee sweep to treasury):
    /// ANY function with ANY calldata from a non-admin caller leaves the registry's MON balance untouched,
    /// except the permissionless sweep, which can only pay the treasury exactly the accrued fees.
    function check_bondsOnlyLeaveViaAdmin(address caller) public {
        vm.assume(caller != ADMIN);
        bytes memory data = svm.createCalldata("AgentRegistry");
        uint256 before = address(reg).balance;
        uint256 accrued = reg.accruedRegistrationFees();
        vm.prank(caller);
        (bool ok,) = address(reg).call(data);
        if (ok) assert(address(reg).balance >= before - accrued);
    }

    /// Only the operator can move an agent's trading balance out.
    function check_onlyOperatorWithdraws(address caller, uint96 amt, address to) public {
        vm.assume(caller != OP);
        vm.prank(caller);
        (bool ok,) = address(bs).call(abi.encodeCall(bs.withdraw, (id, amt, 0, to)));
        assert(!ok);
    }

    /// agentStatus (used by settlement) agrees with isAuthorized (used by apps) for any key, after any
    /// admin/guardian/operator kill or key change.
    function check_agentStatusMatchesIsAuthorized(bytes32 pk, bool kill, bool addRevoke, bytes32 extra, uint32 qid) public {
        if (kill) { vm.prank(GUARDIAN); reg.kill(id); }
        if (addRevoke) {
            vm.assume(extra != bytes32(0) && extra != PK);
            vm.startPrank(OP); reg.addKey(id, extra); reg.revokeKey(id, PK); vm.stopPrank();
        }
        (uint8 st,,) = reg.agentStatus(qid, pk);
        assert((st == 0) == reg.isAuthorized(qid, pk));
    }

    /// Fee quote never exceeds the per-batch cap and is linear below it.
    function check_feeQuoteBounded(uint72 fee, uint72 cap, uint16 actions) public {
        vm.prank(ADMIN);
        bs.setFeeConfig(0, fee, cap, true);
        uint256 f = bs.feeQuote(id, actions);
        if (cap != 0) assert(f <= cap);
        assert(f <= uint256(actions) * fee);
        if (cap == 0 || uint256(actions) * fee <= cap) assert(f == uint256(actions) * fee);
    }

    /// One-order batch with symbolic nonce, side and amounts: if settle succeeds, the nonce strictly increased to
    /// exactly firstNonce, the amount was within the cap and the balance, and the same batch can never settle again.
    function check_singleOrderSettle(uint64 firstNonce, bool buy, uint64 amountIn, uint64 minOut, uint64 prevNonce) public {
        // pre-state: an arbitrary earlier nonce (settle a concrete batch first when prevNonce != 0)
        if (prevNonce != 0) {
            bytes memory pre = abi.encodePacked(id, uint16(1), prevNonce, uint32(block.timestamp + 60), PK, bytes32(0),
                uint8(0), uint96(1e18), uint96(0));
            bs.settle(1, pre, "");
        }
        (uint96 b0, uint96 q0, uint64 n0) = bs.agentState(id);
        bytes memory blob = abi.encodePacked(id, uint16(1), firstNonce, uint32(block.timestamp + 60), PK, bytes32(0),
            uint8(buy ? 1 : 0), uint96(amountIn), uint96(minOut));
        (bool ok,) = address(bs).call(abi.encodeCall(bs.settle, (2, blob, "")));
        if (ok) {
            (uint96 b1, uint96 q1, uint64 n1) = bs.agentState(id);
            assert(firstNonce > n0 && n1 == firstNonce);
            if (buy) assert(amountIn <= 2_000e18 && amountIn <= q0 && q1 == q0 - amountIn);
            else assert(amountIn <= 1_000e18 && amountIn <= b0 && b1 == b0 - amountIn);
            (bool again,) = address(bs).call(abi.encodeCall(bs.settle, (2, blob, "")));
            assert(!again);
        } else {
            (,, uint64 n1) = bs.agentState(id);
            assert(n1 == n0);
        }
    }
}
