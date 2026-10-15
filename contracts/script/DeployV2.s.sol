// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";
import { MiniAMM } from "../src/dex/MiniAMM.sol";
import { MockToken } from "../src/dex/MockToken.sol";
import { ISP1Verifier } from "../src/interfaces/ISP1Verifier.sol";

/// Deploys a fresh AgentRegistry + BatchSettlementV2 on the EXISTING Solonet pool,
/// reusing the existing StandInGroth16Verifier (GAS STAND-IN, NOT SOUND).
contract DeployV2 is Script {
    function run() external {
        MiniAMM pool = MiniAMM(vm.envAddress("POOL"));
        ISP1Verifier ver = ISP1Verifier(vm.envAddress("STANDIN_VERIFIER"));
        bytes32 pkA = vm.envBytes32("PK_A");
        bytes32 pkB = vm.envBytes32("PK_B");
        MockToken b = MockToken(address(pool.token0()));
        MockToken q = MockToken(address(pool.token1()));

        vm.startBroadcast();
        address me = msg.sender;
        AgentRegistry reg = new AgentRegistry(me, me, 1 ether);
        BatchSettlementV2 bs = new BatchSettlementV2(ver, vm.envBytes32("BATCH_VKEY"), reg, pool);
        uint32 idA = reg.registerAgent{ value: 1 ether }(me, pkA, 1_000_000e18, 2_000_000e18);
        uint32 idB = reg.registerAgent{ value: 1 ether }(me, pkB, 1_000_000e18, 2_000_000e18);
        for (uint256 k; k < 4; ++k) { b.faucet(100_000e18); q.faucet(100_000e18); q.faucet(100_000e18); }
        b.approve(address(bs), type(uint256).max);
        q.approve(address(bs), type(uint256).max);
        bs.deposit(idA, 200_000e18, 400_000e18);
        bs.deposit(idB, 200_000e18, 400_000e18);
        vm.stopBroadcast();
        console.log("REGISTRY", address(reg));
        console.log("SETTLEMENT", address(bs));
    }
}
