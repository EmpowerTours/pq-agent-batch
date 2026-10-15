// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { BatchSettlement } from "../src/BatchSettlement.sol";
import { MiniAMM } from "../src/dex/MiniAMM.sol";
import { MockToken } from "../src/dex/MockToken.sol";
import { ISP1Verifier } from "../src/interfaces/ISP1Verifier.sol";
import { StandInGroth16Verifier } from "../test/helpers/StandInGroth16Verifier.sol";

/// Deploys the milestone on a LOCAL Solonet. Verifier = StandInGroth16Verifier
/// (GAS STAND-IN, NOT SOUND) wrapping the real SP1 Groth16 verifier bytecode
/// already deployed at REAL_VERIFIER, fed the repo's real route proof.
contract DeploySolonet is Script {
    function run() external {
        address realVerifier = vm.envAddress("REAL_VERIFIER");
        bytes32 batchVKey = vm.envBytes32("BATCH_VKEY");   // vkey of zk-batch guest (not used by the stand-in)
        bytes32 pkA = vm.envBytes32("PK_A");
        bytes32 pkB = vm.envBytes32("PK_B");
        string memory fx = vm.readFile("test/fixtures/groth16-mldsa-route.json");

        vm.startBroadcast();
        address me = msg.sender;
        MockToken t0 = new MockToken("Base", "BASE", 18);
        MockToken t1 = new MockToken("Quote", "QUOTE", 18);
        MiniAMM pool = new MiniAMM(address(t0), address(t1));
        MockToken b = MockToken(address(pool.token0()));
        MockToken q = MockToken(address(pool.token1()));
        for (uint256 k; k < 5; ++k) { b.faucet(100_000e18); q.faucet(100_000e18); q.faucet(100_000e18); }
        b.approve(address(pool), type(uint256).max);
        q.approve(address(pool), type(uint256).max);
        pool.addLiquidity(250_000e18, 500_000e18, me); // 2 quote per base

        AgentRegistry reg = new AgentRegistry(me, me, 1 ether);
        StandInGroth16Verifier ver = new StandInGroth16Verifier(
            ISP1Verifier(realVerifier),
            vm.parseJsonBytes32(fx, ".vkey"),
            vm.parseJsonBytes32(fx, ".orderHash"),
            vm.parseJsonBytes32(fx, ".pkHash")
        );
        BatchSettlement bs = new BatchSettlement(ver, batchVKey, reg, pool);
        uint32 idA = reg.registerAgent{ value: 1 ether }(me, pkA, 1_000_000e18, 2_000_000e18);
        uint32 idB = reg.registerAgent{ value: 1 ether }(me, pkB, 1_000_000e18, 2_000_000e18);
        for (uint256 k; k < 4; ++k) { b.faucet(100_000e18); q.faucet(100_000e18); q.faucet(100_000e18); }
        b.approve(address(bs), type(uint256).max);
        q.approve(address(bs), type(uint256).max);
        bs.deposit(idA, 200_000e18, 400_000e18);
        bs.deposit(idB, 200_000e18, 400_000e18);
        vm.stopBroadcast();

        console.log("BASE", address(b));
        console.log("QUOTE", address(q));
        console.log("POOL", address(pool));
        console.log("REGISTRY", address(reg));
        console.log("STANDIN_VERIFIER", address(ver));
        console.log("SETTLEMENT", address(bs));
    }
}
