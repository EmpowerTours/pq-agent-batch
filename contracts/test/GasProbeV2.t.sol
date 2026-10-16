// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import { V2Fixture } from "./helpers/V2Fixture.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";

/// Local (EVM-priced) marginal-gas probe used while tuning; Solonet is the real oracle.
contract GasProbeV2 is V2Fixture {
    function _blob(uint256 n) internal view returns (bytes memory blob) {
        uint256 half = (n + 1) / 2;
        blob = _hdr(idA, uint16(half), 1, exp, PK_A);
        for (uint256 i; i < half; ++i) blob = bytes.concat(blob, _ord(i % 2 == 0, uint96(1e18 + i * 1e15), 1));
        blob = bytes.concat(blob, _hdr(idB, uint16(n - half), 1, exp, PK_B));
        for (uint256 i = half; i < n; ++i) blob = bytes.concat(blob, _ord(i % 2 == 0, uint96(1e18 + i * 1e15), 1));
    }

    function _gas(uint256 n) internal returns (uint256 g) {
        bytes memory blob = _blob(n);
        bytes memory proof = _proof(1, blob);
        g = gasleft();
        bs.settle(1, blob, proof);
        g -= gasleft();
    }

    function test_probe_marginal() public {
        uint256 snap = vm.snapshotState();
        uint256 g10 = _gas(10);
        vm.revertToState(snap);
        uint256 g100 = _gas(100);
        emit log_named_uint("settle N=10 (local EVM, mock verifier)", g10);
        emit log_named_uint("settle N=100", g100);
        emit log_named_uint("marginal per order", (g100 - g10) / 90);
    }
}
