// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// NOT FOR DEPLOYMENT. Test/measurement helper; lives under test/ on purpose.

import { ISP1Verifier } from "../../src/interfaces/ISP1Verifier.sol";

/// @notice TEST ONLY. Models a sound SNARK without proving: a "proof" is valid
///         iff it equals keccak256(abi.encode(vkey, publicValues)). So a proof
///         made for one batch digest fails for any other digest, which is the
///         property the settlement contract relies on.
contract HashBoundMockVerifier is ISP1Verifier {
    error InvalidMockProof();

    function proofFor(bytes32 vkey, bytes memory publicValues) public pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(vkey, publicValues)));
    }

    function verifyProof(bytes32 vkey, bytes calldata publicValues, bytes calldata proofBytes)
        external
        pure
    {
        if (keccak256(proofBytes) != keccak256(proofFor(vkey, publicValues))) revert InvalidMockProof();
    }
}
