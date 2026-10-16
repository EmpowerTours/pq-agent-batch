// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { RealProofFixture } from "./helpers/RealProofFixture.sol";

/// The committed REAL proofs still verify with fees switched on (fees are contract-side only:
/// the proved batch bytes and digest are unchanged), and the gas cost of the fee path at N=100.
/// Gas here is forge/EVM-priced (Ethereum storage costs), NOT Monad-priced; see README for the
/// Monad (Solonet) measurement.
contract RealGroth16FeesTest is RealProofFixture {
    function _settleGas(Fx memory f) internal returns (uint256 g) {
        g = gasleft();
        bs.settle(f.batchId, f.batch, f.proof);
        g -= gasleft();
    }

    function test_RealProofs_WithNativeFees_N100Gas() public {
        bs.setFeeConfig(0, 1e15, 0, true);                    // 0.001 MON per action
        bs.depositFeeNative{ value: 1 ether }(1);
        bs.depositFeeNative{ value: 1 ether }(2);
        bs.setFeeAlert(1, 0.95 ether);                        // will cross on batch 2
        bs.setFeeAlert(2, 0.5 ether);
        _settleGas(_b1());                                    // 5 + 5 actions
        uint256 g = _settleGas(_b2());                        // 50 + 50 actions
        emit log_named_uint("real N=100 settle, fees ON (forge gas, excl. intrinsic/calldata)", g);
        (uint96 b1,,,) = bs.feeAccount(1);
        (uint96 b2,,,) = bs.feeAccount(2);
        assertEq(b1, 1 ether - 55e15);
        assertEq(b2, 1 ether - 55e15);
        assertEq(bs.accruedFees(0), 110e15);
        (,,, bool low1) = bs.feeAccount(1);
        assertTrue(low1, "agent 1 crossed its alert threshold");
    }

    function test_RealProofs_FeesOff_N100Gas() public {
        _settleGas(_b1());
        uint256 g = _settleGas(_b2());
        emit log_named_uint("real N=100 settle, fees OFF (forge gas, excl. intrinsic/calldata)", g);
    }

    receive() external payable {}
}
