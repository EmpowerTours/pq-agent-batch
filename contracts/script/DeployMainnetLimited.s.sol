// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";
import { MiniAMM } from "../src/dex/MiniAMM.sol";
import { ISP1Verifier } from "../src/interfaces/ISP1Verifier.sol";

interface ISP1VerifierInfo {
    function VERSION() external view returns (string memory);
    function VERIFIER_HASH() external view returns (bytes32);
}

/// LIMITED MAINNET launch (audit recommendation, see audits/REPORT.md). Not run by CI or by the audit: dry-run
/// it first with `forge script ... --fork-url <monad rpc>` (no --broadcast), then broadcast with the
/// deployer's own key only after review. Differences from DeploySolonet:
///   - no MockToken, no faucet, no test agents, no deposits;
///   - pins Succinct's deployed SP1 v6.1.0 Groth16 verifier (checks VERSION + VERIFIER_HASH) and a non-zero vkey;
///   - small caps / fees from env, a non-zero fee-withdrawal delay;
///   - ends by PROPOSING the multisig (or timelock) as admin; the multisig must call acceptAdmin().
///     Guardian (kill only) and treasury are set to the given multisigs.
///   env (required): BATCH_VKEY, ADMIN, GUARDIAN, TREASURY, and POOL (an existing, seeded MiniAMM)
///                   or TOKEN_A + TOKEN_B (deploys an EMPTY MiniAMM that must be seeded before trading).
///   env (optional): VERIFIER (default Monad mainnet v6.1.0 Groth16 0xb69f...f4e2), MIN_STAKE (1 MON),
///                   REGISTRATION_FEE (0.1 MON), FEE_PER_ACTION (0.001 MON), MAX_FEE_PER_BATCH (0 = none),
///                   FEE_WITHDRAW_DELAY (1 day), OPEN_REGISTRATION (false), SELF_CAP_BASE / SELF_CAP_QUOTE
///                   (default 1e15 = near-zero trading).
/// Monad: charges the gas LIMIT; broadcast with an explicit, measured gas limit per tx (forge under-estimates
/// Monad storage costs; --gas-estimate-multiplier 300 was needed on Solonet, which over-pays on mainnet).
contract DeployMainnetLimited is Script {
    address constant SP1_V610_GROTH16_MONAD = 0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2;
    bytes32 constant SP1_V610_GROTH16_HASH = 0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;

    function run() external returns (AgentRegistry reg, BatchSettlementV2 bs) {
        bytes32 vkey = vm.envBytes32("BATCH_VKEY");
        require(vkey != bytes32(0), "vkey");
        address admin = vm.envAddress("ADMIN");
        address guardian = vm.envAddress("GUARDIAN");
        address treasury = vm.envAddress("TREASURY");
        require(admin.code.length > 0, "ADMIN must be a contract (Safe multisig / timelock)");
        require(guardian.code.length > 0, "GUARDIAN must be a contract (Safe multisig)");
        require(treasury.code.length > 0, "TREASURY must be a contract (Safe multisig)");
        address verifier = vm.envOr("VERIFIER", SP1_V610_GROTH16_MONAD);
        require(keccak256(bytes(ISP1VerifierInfo(verifier).VERSION())) == keccak256("v6.1.0"), "verifier version");
        require(ISP1VerifierInfo(verifier).VERIFIER_HASH() == SP1_V610_GROTH16_HASH, "verifier hash");

        vm.startBroadcast();
        address me = msg.sender;
        MiniAMM pool;
        address poolAddr = vm.envOr("POOL", address(0));
        if (poolAddr == address(0)) {
            pool = new MiniAMM(vm.envAddress("TOKEN_A"), vm.envAddress("TOKEN_B"));
            console.log("NOTE: new MiniAMM is EMPTY; seed liquidity before any agent trades");
        } else {
            pool = MiniAMM(poolAddr);
        }
        reg = new AgentRegistry(me, guardian, uint96(vm.envOr("MIN_STAKE", uint256(1 ether))));
        bs = new BatchSettlementV2(ISP1Verifier(verifier), vkey, reg, pool);

        reg.setTreasury(treasury);
        reg.setRegistrationFee(uint96(vm.envOr("REGISTRATION_FEE", uint256(0.1 ether))));
        bs.setFeeConfig(0, uint72(vm.envOr("FEE_PER_ACTION", uint256(0.001 ether))),
            uint72(vm.envOr("MAX_FEE_PER_BATCH", uint256(0))), true);
        bs.setFeeWithdrawDelay(uint64(vm.envOr("FEE_WITHDRAW_DELAY", uint256(1 days))));
        reg.setOpenRegistration(vm.envOr("OPEN_REGISTRATION", false),
            uint128(vm.envOr("SELF_CAP_BASE", uint256(1e15))), uint128(vm.envOr("SELF_CAP_QUOTE", uint256(1e15))));
        reg.transferAdmin(admin);   // the multisig/timelock must acceptAdmin(); until then the deployer is admin
        vm.stopBroadcast();

        console.log("POOL", address(pool));
        console.log("REGISTRY", address(reg));
        console.log("SETTLEMENT", address(bs));
        console.log("PENDING ADMIN (must acceptAdmin)", admin);
    }
}
