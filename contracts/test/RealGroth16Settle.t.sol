// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";
import { RealProofFixture, ISP1VerifierInfo } from "./helpers/RealProofFixture.sol";

/// @notice Replays the two REAL SP1 Groth16 batch proofs (N=10, N=100) from results/solonet/ against
///         the REAL SP1 v6.1.0 Groth16 verifier bytecode (byte-identical to Succinct's Monad mainnet
///         deployment, see bytecode/README.md). No mock or stand-in verifier is involved, and no RPC:
///         the proofs are bound to chain 20143 + the Solonet settlement address, so the test sets the
///         chain id and deploys BatchSettlementV2 at that address.
contract RealGroth16SettleTest is RealProofFixture {
    function test_VerifierIsSp1V610Groth16() public view {
        assertEq(ISP1VerifierInfo(address(ver)).VERSION(), "v6.1.0");
        assertEq(ISP1VerifierInfo(address(ver)).VERIFIER_HASH(), 0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696);
    }

    function test_RealProofs_N10_then_N100() public {
        _settle(_b1());
        assertEq(_lastNonce(1), 5);
        assertEq(_lastNonce(2), 10);
        _settle(_b2());
        assertEq(_lastNonce(1), 55);
        assertEq(_lastNonce(2), 105);
    }

    function test_RealProof_ReplayRejected() public {
        Fx memory f = _b1();
        bs.settle(f.batchId, f.batch, f.proof);
        vm.expectRevert(abi.encodeWithSelector(BatchSettlementV2.NonceNotIncreasing.selector, uint32(1), uint64(1), uint64(5)));
        bs.settle(f.batchId, f.batch, f.proof);
    }

    function test_RealProof_TamperedOrderRejected() public {
        Fx memory f = _b1();
        f.batch[f.batch.length - 13] = bytes1(uint8(f.batch[f.batch.length - 13]) ^ 1); // last order's amountIn
        vm.expectRevert(PROOF_INVALID);
        bs.settle(f.batchId, f.batch, f.proof);
    }

    function test_RealProof_WrongBatchIdRejected() public {
        Fx memory f = _b1();
        vm.expectRevert(PROOF_INVALID);
        bs.settle(f.batchId + 1, f.batch, f.proof);
    }

    function test_RealProof_TamperedProofRejected() public {
        Fx memory f = _b2();
        f.proof[100] = bytes1(uint8(f.proof[100]) ^ 1);
        vm.expectRevert();
        bs.settle(f.batchId, f.batch, f.proof);
    }

    function test_RealProof_WrongChainRejected() public {
        Fx memory f = _b1();
        vm.chainId(143);
        vm.expectRevert(PROOF_INVALID);
        bs.settle(f.batchId, f.batch, f.proof);
    }
}
