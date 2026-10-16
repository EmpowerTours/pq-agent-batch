// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test, Vm } from "forge-std/Test.sol";
import { AgentRegistry } from "../../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../../src/BatchSettlementV2.sol";
import { MiniAMM } from "../../src/dex/MiniAMM.sol";
import { MockToken } from "../../src/dex/MockToken.sol";
import { ISP1Verifier } from "../../src/interfaces/ISP1Verifier.sol";

interface ISP1VerifierInfo {
    function VERSION() external pure returns (string memory);
    function VERIFIER_HASH() external pure returns (bytes32);
}

/// Shared setUp for the real-proof suites: real SP1 v6.1.0 verifier bytecode, settlement at the
/// Solonet address the committed proofs are bound to, chain id 20143, two funded TEST agents.
abstract contract RealProofFixture is Test {
    address constant SETTLEMENT = 0x46658F507877C3Ec5180De4D60cdbb41A846Ab3e; // bound in both proofs
    uint64 constant CHAIN = 20143;
    bytes32 constant VKEY = 0x0020ed358e42b85560d3f4114c57cd2b767e130766caf8bcaec7842799fd7d9d;
    bytes32 constant PK_A = 0x8b1551c421b573beeaebb39debb1e0371e13c93155a7a5be60b29dd691095b05; // TEST key
    bytes32 constant PK_B = 0x62d3462f41b0be23edd19e0aa7477bf95edcf207d9d325ddd73298cb14a946e3; // TEST key
    bytes4 constant PROOF_INVALID = 0x7fcdd1f4; // Groth16 Verifier.ProofInvalid()

    ISP1Verifier ver;
    AgentRegistry reg;
    BatchSettlementV2 bs;
    MiniAMM pool;

    struct Fx {
        bytes batch;
        bytes proof;
        bytes32 digest;
        uint64 batchId;
        uint256 n;
    }

    function setUp() public {
        vm.chainId(CHAIN);
        bytes memory init = vm.parseBytes(vm.trim(vm.readFile("bytecode/sp1-verifier-groth16-v6.1.0.init.hex")));
        address v;
        assembly { v := create(0, add(init, 0x20), mload(init)) }
        require(v != address(0) && v.code.length > 0, "verifier deploy failed");
        ver = ISP1Verifier(v);

        MockToken t0 = new MockToken("Base", "BASE", 18);
        MockToken t1 = new MockToken("Quote", "QUOTE", 18);
        pool = new MiniAMM(address(t0), address(t1));
        MockToken b = MockToken(address(pool.token0()));
        MockToken q = MockToken(address(pool.token1()));
        for (uint256 k; k < 9; ++k) { b.faucet(100_000e18); q.faucet(100_000e18); q.faucet(100_000e18); }
        b.approve(address(pool), type(uint256).max);
        q.approve(address(pool), type(uint256).max);
        pool.addLiquidity(250_000e18, 500_000e18, address(this)); // 2 quote per base, as on Solonet

        reg = new AgentRegistry(address(this), address(this), 1 ether);
        deployCodeTo("BatchSettlementV2.sol:BatchSettlementV2", abi.encode(ver, VKEY, reg, pool), SETTLEMENT);
        bs = BatchSettlementV2(SETTLEMENT);
        assertEq(reg.registerAgent{ value: 1 ether }(address(this), PK_A, 1_000_000e18, 2_000_000e18), 1);
        assertEq(reg.registerAgent{ value: 1 ether }(address(this), PK_B, 1_000_000e18, 2_000_000e18), 2);
        b.approve(address(bs), type(uint256).max);
        q.approve(address(bs), type(uint256).max);
        bs.deposit(1, 200_000e18, 400_000e18);
        bs.deposit(2, 200_000e18, 400_000e18);
    }

    function _load(string memory path) internal view returns (Fx memory f) {
        string memory j = vm.readFile(path);
        assertEq(vm.parseJsonUint(j, ".chainId"), CHAIN, "fixture chain");
        assertEq(vm.parseJsonAddress(j, ".settlement"), SETTLEMENT, "fixture settlement");
        assertEq(vm.parseJsonBytes32(j, ".vkey"), VKEY, "fixture vkey");
        f.batch = vm.parseJsonBytes(j, ".batch");
        f.proof = vm.parseJsonBytes(j, ".proof");
        f.digest = vm.parseJsonBytes32(j, ".digest");
        f.batchId = uint64(vm.parseJsonUint(j, ".batchId"));
        f.n = vm.parseJsonUint(j, ".n");
        assertEq(vm.parseJsonBytes32(j, ".publicValues"), f.digest, "publicValues == digest");
    }

    function _b1() internal view returns (Fx memory) { return _load("../results/solonet/b1-n10/groth16-batch-fixture.json"); }
    function _b2() internal view returns (Fx memory) { return _load("../results/solonet/b2-n100/groth16-batch-fixture.json"); }

    function _settle(Fx memory f) internal {
        assertEq(bs.batchDigest(f.batchId, f.batch), f.digest, "contract digest == guest digest");
        vm.recordLogs();
        bs.settle(f.batchId, f.batch, f.proof);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (bytes32 d, uint256 n,,,,) = abi.decode(logs[logs.length - 1].data, (bytes32, uint256, uint256, uint256, uint256, uint256));
        assertEq(d, f.digest);
        assertEq(n, f.n, "order count");
    }

    function _lastNonce(uint32 id) internal view returns (uint64 n) { (,, n) = bs.agentState(id); }

}
