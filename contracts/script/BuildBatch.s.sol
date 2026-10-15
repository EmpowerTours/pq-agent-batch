// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Script } from "forge-std/Script.sol";
import { BatchSettlement } from "../src/BatchSettlement.sol";

/// Builds settle() calldata for N orders (two agents, grouped, mixed buy/sell)
/// with the real route proof bytes as the stand-in proof. Writes hex to
/// measurements/calldata_<N>.hex. No broadcast.
contract BuildBatch is Script {
    function run(uint256 n, uint64 batchId, uint64 nonceBase) external {
        string memory fx = vm.readFile("test/fixtures/groth16-mldsa-route.json");
        bytes memory proof = vm.parseJsonBytes(fx, ".proof");
        bytes32 pkA = vm.envBytes32("PK_A");
        bytes32 pkB = vm.envBytes32("PK_B");
        bytes32 model = keccak256("quantum-portfolio model v1 (test)");
        BatchSettlement.Order[] memory os = new BatchSettlement.Order[](n);
        uint256 half = (n + 1) / 2;
        for (uint256 i; i < n; ++i) {
            bool a = i < half;
            bool buy = i % 2 == 0;
            os[i] = BatchSettlement.Order({
                agentId: a ? 1 : 2,
                buyBase: buy,
                nonce: nonceBase + uint64(i) + 1,
                expiry: type(uint64).max,
                amountIn: buy ? 2e18 + uint128(i) * 1e15 : 1e18 + uint128(i) * 1e15,
                minAmountOut: 1,
                pkHash: a ? pkA : pkB,
                modelHash: model
            });
        }
        bytes memory cd = abi.encodeCall(BatchSettlement.settle, (batchId, os, proof));
        vm.writeFile(string.concat("measurements/calldata_", vm.toString(n), ".hex"), vm.toString(cd));
    }
}
