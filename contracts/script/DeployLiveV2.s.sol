// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";
import { MiniAMM } from "../src/dex/MiniAMM.sol";
import { MockToken } from "../src/dex/MockToken.sol";
import { ISP1Verifier } from "../src/interfaces/ISP1Verifier.sol";

/// Live (devnet) stack for REAL proofs: fresh AgentRegistry + BatchSettlementV2 wired to a real
/// SP1 Groth16 verifier and the guest vkey produced by the prove workflow. Registers the two
/// TEST agents (ids 1, 2) and deposits working balances. No stand-in anywhere.
///   env: POOL, VERIFIER, BATCH_VKEY, PK_A, PK_B
contract DeployLiveV2 is Script {
    function run() external {
        MiniAMM pool = MiniAMM(vm.envAddress("POOL"));
        ISP1Verifier ver = ISP1Verifier(vm.envAddress("VERIFIER"));
        MockToken b = MockToken(address(pool.token0()));
        MockToken q = MockToken(address(pool.token1()));

        vm.startBroadcast();
        address me = msg.sender;
        AgentRegistry reg = new AgentRegistry(me, me, 1 ether);
        BatchSettlementV2 bs = new BatchSettlementV2(ver, vm.envBytes32("BATCH_VKEY"), reg, pool);
        uint32 idA = reg.registerAgent{ value: 1 ether }(me, vm.envBytes32("PK_A"), 1_000_000e18, 2_000_000e18);
        uint32 idB = reg.registerAgent{ value: 1 ether }(me, vm.envBytes32("PK_B"), 1_000_000e18, 2_000_000e18);
        require(idA == 1 && idB == 2, "agent ids must be 1 and 2 (bound in the proved batch)");
        for (uint256 k; k < 4; ++k) {
            b.faucet(100_000e18);
            q.faucet(100_000e18);
            q.faucet(100_000e18);
        }
        b.approve(address(bs), type(uint256).max);
        q.approve(address(bs), type(uint256).max);
        bs.deposit(idA, 200_000e18, 400_000e18);
        bs.deposit(idB, 200_000e18, 400_000e18);
        vm.stopBroadcast();
        console.log("REGISTRY", address(reg));
        console.log("SETTLEMENT", address(bs));
    }
}
