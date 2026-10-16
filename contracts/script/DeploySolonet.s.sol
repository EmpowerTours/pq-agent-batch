// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";
import { MiniAMM } from "../src/dex/MiniAMM.sol";
import { MockToken } from "../src/dex/MockToken.sol";
import { ISP1Verifier } from "../src/interfaces/ISP1Verifier.sol";

/// Devnet stack for REAL proofs: AgentRegistry + BatchSettlementV2 wired to the real SP1 v6.1.0
/// Groth16 verifier and the guest vkey produced by the prove workflow (`vkey.txt`). Registers the two
/// TEST agents (ids 1, 2, bound in every proved batch) and deposits working balances.
///   env (required): BATCH_VKEY
///   env (optional): VERIFIER (existing SP1 Groth16 verifier; default: deploy bytecode/sp1-verifier-groth16-v6.1.0.init.hex)
///                   POOL     (existing MiniAMM; default: deploy MockToken pair + MiniAMM with 250k/500k liquidity)
///                   PK_A, PK_B (agent pkHashes; default: the repo's deterministic TEST keys)
///                   FEE_PER_ACTION (native MON fee per settled order; default 0 = fees off). When set, both
///                   TEST agents also get FEE_DEPOSIT (default 1 MON) of prepaid native fee balance.
///                   OPEN_REGISTRATION (bool, default false): let anyone selfRegister() (used by the SDK/CLI);
///                   SELF_CAP_BASE / SELF_CAP_QUOTE (self-registration max caps; default 10k / 20k tokens);
///                   REGISTRATION_FEE (one-time MON fee on top of the 1 MON bond; default 0).
/// Monad: broadcast with --gas-estimate-multiplier 300 (forge under-estimates Monad storage cost).
contract DeploySolonet is Script {
    bytes32 constant TEST_PK_A = 0x8b1551c421b573beeaebb39debb1e0371e13c93155a7a5be60b29dd691095b05;
    bytes32 constant TEST_PK_B = 0x62d3462f41b0be23edd19e0aa7477bf95edcf207d9d325ddd73298cb14a946e3;

    function run() external {
        bytes32 vkey = vm.envBytes32("BATCH_VKEY");
        address verAddr = vm.envOr("VERIFIER", address(0));
        address poolAddr = vm.envOr("POOL", address(0));
        bytes memory init = vm.parseBytes(vm.trim(vm.readFile("bytecode/sp1-verifier-groth16-v6.1.0.init.hex")));

        vm.startBroadcast();
        address me = msg.sender;
        if (verAddr == address(0)) {
            assembly { verAddr := create(0, add(init, 0x20), mload(init)) }
            require(verAddr != address(0), "verifier deploy failed");
        }
        MiniAMM pool;
        if (poolAddr == address(0)) {
            MockToken t0 = new MockToken("Base", "BASE", 18);
            MockToken t1 = new MockToken("Quote", "QUOTE", 18);
            pool = new MiniAMM(address(t0), address(t1));
            MockToken pb = MockToken(address(pool.token0()));
            MockToken pq = MockToken(address(pool.token1()));
            for (uint256 k; k < 3; ++k) { pb.faucet(100_000e18); pq.faucet(100_000e18); pq.faucet(100_000e18); }
            pb.approve(address(pool), type(uint256).max);
            pq.approve(address(pool), type(uint256).max);
            pool.addLiquidity(250_000e18, 500_000e18, me); // 2 quote per base
        } else {
            pool = MiniAMM(poolAddr);
        }
        MockToken b = MockToken(address(pool.token0()));
        MockToken q = MockToken(address(pool.token1()));

        AgentRegistry reg = new AgentRegistry(me, me, 1 ether);
        BatchSettlementV2 bs = new BatchSettlementV2(ISP1Verifier(verAddr), vkey, reg, pool);
        uint32 idA = reg.registerAgent{ value: 1 ether }(me, vm.envOr("PK_A", TEST_PK_A), 1_000_000e18, 2_000_000e18);
        uint32 idB = reg.registerAgent{ value: 1 ether }(me, vm.envOr("PK_B", TEST_PK_B), 1_000_000e18, 2_000_000e18);
        require(idA == 1 && idB == 2, "agent ids must be 1 and 2 (bound in the proved batch)");
        for (uint256 k; k < 4; ++k) { b.faucet(100_000e18); q.faucet(100_000e18); q.faucet(100_000e18); }
        b.approve(address(bs), type(uint256).max);
        q.approve(address(bs), type(uint256).max);
        bs.deposit(idA, 200_000e18, 400_000e18);
        bs.deposit(idB, 200_000e18, 400_000e18);
        uint72 feePerAction = uint72(vm.envOr("FEE_PER_ACTION", uint256(0)));
        if (feePerAction != 0) {
            uint256 dep = vm.envOr("FEE_DEPOSIT", uint256(1 ether));
            bs.setFeeConfig(0, feePerAction, 0, true);   // deployer is the registry admin
            bs.depositFeeNative{ value: dep }(idA);
            bs.depositFeeNative{ value: dep }(idB);
        }
        uint96 regFee = uint96(vm.envOr("REGISTRATION_FEE", uint256(0)));
        if (regFee != 0) reg.setRegistrationFee(regFee);
        if (vm.envOr("OPEN_REGISTRATION", false)) {
            reg.setOpenRegistration(true, uint128(vm.envOr("SELF_CAP_BASE", uint256(10_000e18))),
                uint128(vm.envOr("SELF_CAP_QUOTE", uint256(20_000e18))));
        }
        vm.stopBroadcast();
        console.log("VERIFIER", verAddr);
        console.log("POOL", address(pool));
        console.log("REGISTRY", address(reg));
        console.log("SETTLEMENT", address(bs));
    }
}
