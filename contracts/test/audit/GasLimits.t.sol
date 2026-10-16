// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// Audit: worst-case settle gas vs Monad's 30M per-tx cap (local EVM pricing, mock verifier; see REPORT.md for the
// Monad adjustment). Worst case = every order from a different agent (one cold registry call + 2 cold slots each).

import { V2Fixture } from "../helpers/V2Fixture.sol";

contract GasLimitsTest is V2Fixture {
    function _manyAgents(uint256 k) internal returns (bytes memory blob) {
        vm.deal(admin, 1000 ether);
        for (uint256 i; i < k; ++i) {
            bytes32 pk = keccak256(abi.encode("pk", i));
            vm.prank(admin);
            uint32 id = reg.registerAgent{ value: 1 ether }(address(uint160(0x5000 + i)), pk, 1_000e18, 2_000e18);
            _fund(id, 10e18, 20e18);
            blob = bytes.concat(blob, _hdr(id, 1, 1, exp, pk), _ord(i % 2 == 0, 1e18, 0));
        }
    }

    function test_gas_worstCaseGroups() public {
        bytes memory blob = _manyAgents(200);
        bytes memory proof = _proof(1, blob);
        uint256 g = gasleft();
        bs.settle(1, blob, proof);
        g -= gasleft();
        emit log_named_uint("settle, 200 single-order agent groups (local EVM, mock verifier)", g);
        emit log_named_uint("per group", g / 200);
        assertLt(g, 30_000_000);
    }
}
