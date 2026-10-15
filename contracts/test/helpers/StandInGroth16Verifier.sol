// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// NOT FOR DEPLOYMENT. Test/measurement helper; lives under test/ on purpose.

import { ISP1Verifier } from "../../src/interfaces/ISP1Verifier.sol";

/// @notice GAS-MEASUREMENT STAND-IN. NOT SOUND. Do not deploy anywhere real.
///         There is no real aggregated batch proof yet, so this wrapper ignores
///         the batch's vkey/publicValues and runs the REAL SP1 Groth16 verifier
///         on the REAL single-order proof from quantum-portfolio
///         (fixtures/groth16-mldsa-route.json). The pairing work is identical
///         in size to what a real batch proof costs (Groth16 verification is
///         constant-size; SP1 public values are hashed to one field element),
///         so the gas reflects Monad pricing. The wrapper itself adds one cold
///         CALL plus a 64-byte re-encode.
contract StandInGroth16Verifier is ISP1Verifier {
    ISP1Verifier public immutable real;
    bytes32 public immutable realVKey;
    bytes32 public immutable realOrderHash;
    bytes32 public immutable realPkHash;

    constructor(ISP1Verifier _real, bytes32 _vkey, bytes32 _orderHash, bytes32 _pkHash) {
        real = _real;
        realVKey = _vkey;
        realOrderHash = _orderHash;
        realPkHash = _pkHash;
    }

    function verifyProof(bytes32, bytes calldata, bytes calldata proofBytes) external view {
        real.verifyProof(realVKey, abi.encodePacked(realOrderHash, realPkHash), proofBytes);
    }
}
