// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// Shared setUp + helpers for the BatchSettlementV2 test suites (mock verifier, two TEST agents).

import { Test, Vm } from "forge-std/Test.sol";
import { AgentRegistry } from "../../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../../src/BatchSettlementV2.sol";
import { AgentFees } from "../../src/AgentFees.sol";
import { MiniAMM } from "../../src/dex/MiniAMM.sol";
import { MockToken } from "../../src/dex/MockToken.sol";
import { HashBoundMockVerifier } from "./HashBoundMockVerifier.sol";

abstract contract V2Fixture is Test {
    bytes32 constant VKEY = keccak256("batch-guest-vkey-v2");
    // pkHashes of the two deterministic TEST keys used by zk-batch's host (parity fixture)
    bytes32 constant PK_A = 0x8b1551c421b573beeaebb39debb1e0371e13c93155a7a5be60b29dd691095b05;
    bytes32 constant PK_B = 0x62d3462f41b0be23edd19e0aa7477bf95edcf207d9d325ddd73298cb14a946e3;
    bytes32 constant MODEL = keccak256("quantum-portfolio model v1 (test)");
    address constant BS_ADDR = 0x5e77000000000000000000000000000000005E77; // fixed so the guest fixture binds it
    uint64 constant CHAIN = 20143;

    address admin = address(0xA11CE);
    address guardian = address(0x6A2D);
    address opA = makeAddr("operatorA");
    address opB = makeAddr("operatorB");

    MockToken baseTok;
    MockToken quoteTok;
    MiniAMM pool;
    AgentRegistry reg;
    HashBoundMockVerifier ver;
    BatchSettlementV2 bs;
    uint32 idA;
    uint32 idB;
    uint32 exp;

    function setUp() public virtual {
        vm.chainId(CHAIN);
        vm.warp(1_800_000_000);
        exp = uint32(block.timestamp + 60);
        MockToken t0 = new MockToken("Base", "BASE", 18);
        MockToken t1 = new MockToken("Quote", "QUOTE", 18);
        pool = new MiniAMM(address(t0), address(t1));
        baseTok = MockToken(address(pool.token0()));
        quoteTok = MockToken(address(pool.token1()));
        _mint(baseTok, address(this), 50_000e18);
        _mint(quoteTok, address(this), 100_000e18);
        baseTok.approve(address(pool), type(uint256).max);
        quoteTok.approve(address(pool), type(uint256).max);
        pool.addLiquidity(50_000e18, 100_000e18, address(this)); // 2 quote per base

        reg = new AgentRegistry(admin, guardian, 1 ether);
        ver = new HashBoundMockVerifier();
        deployCodeTo("BatchSettlementV2.sol:BatchSettlementV2", abi.encode(ver, VKEY, reg, pool), BS_ADDR);
        bs = BatchSettlementV2(BS_ADDR);

        vm.deal(admin, 10 ether);
        vm.startPrank(admin);
        idA = reg.registerAgent{ value: 1 ether }(opA, PK_A, 1_000e18, 2_000e18);
        idB = reg.registerAgent{ value: 1 ether }(opB, PK_B, 1_000e18, 2_000e18);
        vm.stopPrank();
        _fund(idA, 1_000e18, 2_000e18);
        _fund(idB, 1_000e18, 2_000e18);
    }

    // ------------------------------------------------------------ helpers

    function _mint(MockToken t, address to, uint256 amt) internal {
        vm.startPrank(to);
        while (amt > 0) {
            uint256 a = amt > 100_000e18 ? 100_000e18 : amt;
            t.faucet(a);
            amt -= a;
        }
        vm.stopPrank();
    }

    function _fund(uint32 id, uint96 b, uint96 q) internal {
        _mint(baseTok, address(this), b);
        _mint(quoteTok, address(this), q);
        baseTok.approve(address(bs), type(uint256).max);
        quoteTok.approve(address(bs), type(uint256).max);
        bs.deposit(id, b, q);
    }

    function _hdr(uint32 id, uint16 count, uint64 firstNonce, uint32 expiry, bytes32 pk)
        internal pure returns (bytes memory)
    {
        return abi.encodePacked(id, count, firstNonce, expiry, pk, MODEL);
    }

    function _ord(bool buy, uint96 amt, uint96 minOut) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(buy ? 1 : 0), amt, minOut);
    }

    function _proof(uint64 batchId, bytes memory blob) internal view returns (bytes memory) {
        return ver.proofFor(VKEY, abi.encode(bs.batchDigest(batchId, blob)));
    }

    function _twoAgentBatch() internal view returns (bytes memory) {
        return bytes.concat(
            _hdr(idA, 2, 1, exp, PK_A), _ord(false, 100e18, 0), _ord(false, 50e18, 0), // A sells 150 base
            _hdr(idB, 1, 1, exp, PK_B), _ord(true, 200e18, 0)                          // B buys with 200 quote
        );
    }

    function _state(uint32 id) internal view returns (uint96 b, uint96 q, uint64 n) {
        (b, q, n) = bs.agentState(id);
    }

    function _assertSolvent() internal view {
        (uint96 aB, uint96 aQ,) = _state(idA);
        (uint96 bB, uint96 bQ,) = _state(idB);
        assertLe(uint256(aB) + bB, baseTok.balanceOf(address(bs)), "base solvent");
        assertLe(uint256(aQ) + bQ, quoteTok.balanceOf(address(bs)), "quote solvent");
    }

}
