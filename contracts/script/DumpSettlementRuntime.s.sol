// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { MiniAMM } from "../src/dex/MiniAMM.sol";
import { ISP1Verifier } from "../src/interfaces/ISP1Verifier.sol";

/// Simulation only (never broadcast): prints the runtime bytecode of the CURRENT BatchSettlementV2
/// source built with the immutables of an existing deployment, for eth_estimateGas code overrides
/// (script/measure_fee_gas.py). env: VERIFIER, BATCH_VKEY, REGISTRY, POOL. Run with --fork-url.
contract DumpSettlementRuntime is Script {
    function run() external {
        BatchSettlementV2 bs = new BatchSettlementV2(
            ISP1Verifier(vm.envAddress("VERIFIER")),
            vm.envBytes32("BATCH_VKEY"),
            AgentRegistry(vm.envAddress("REGISTRY")),
            MiniAMM(vm.envAddress("POOL"))
        );
        console.logBytes(address(bs).code);
    }
}
