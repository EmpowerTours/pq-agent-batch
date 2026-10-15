// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Script } from "forge-std/Script.sol";
import { BatchSettlementV2 } from "../src/BatchSettlementV2.sol";

/// Builds packed settle() calldata, using the same order pattern as BuildBatch (v1):
/// first half agent 1, rest agent 2, buy on even global index. The stand-in proof is
/// the real route proof. Output: measurements/calldata_<N>.hex
contract BuildBatchV2 is Script {
    function run(uint256 n, uint64 batchId, uint64 nonceBase) external {
        string memory fx = vm.readFile("test/fixtures/groth16-mldsa-route.json");
        bytes memory proof = vm.parseJsonBytes(fx, ".proof");
        bytes memory blob = buildBlob(n, nonceBase, vm.envBytes32("PK_A"), vm.envBytes32("PK_B"));
        bytes memory cd = abi.encodeCall(BatchSettlementV2.settle, (batchId, blob, proof));
        vm.writeFile(string.concat("measurements/calldata_", vm.toString(n), ".hex"), vm.toString(cd));
    }

    function buildBlob(uint256 n, uint64 nonceBase, bytes32 pkA, bytes32 pkB) public pure returns (bytes memory blob) {
        bytes32 model = keccak256("quantum-portfolio model v1 (test)");
        uint256 half = (n + 1) / 2;
        for (uint256 g; g < 2; ++g) {
            uint256 from = g == 0 ? 0 : half;
            uint256 to = g == 0 ? half : n;
            if (to == from) continue;
            blob = bytes.concat(blob, abi.encodePacked(uint32(g + 1), uint16(to - from), nonceBase + uint64(from) + 1, type(uint32).max,
                g == 0 ? pkA : pkB, model));
            for (uint256 i = from; i < to; ++i) {
                bool buy = i % 2 == 0;
                uint96 amt = buy ? uint96(2e18 + i * 1e15) : uint96(1e18 + i * 1e15);
                blob = bytes.concat(blob, abi.encodePacked(uint8(buy ? 1 : 0), amt, uint96(1)));
            }
        }
    }
}
