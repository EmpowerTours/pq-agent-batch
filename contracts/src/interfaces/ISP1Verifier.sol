// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal SP1 verifier interface (verifyProof only).
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
