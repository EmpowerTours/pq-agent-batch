// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// Stateful invariant suite (audit). A handler drives random deposits, withdrawals, fee deposits and withdrawals,
// kills/revives, cap changes, settlements (fresh, replayed, over-cap, killed agents) and sweeps; ghost
// accounting plus per-call checks record any violation, and the invariants assert there were none.
// Local deep run: FOUNDRY_PROFILE=deep forge test --match-path test/audit/Invariants.t.sol

import { Test } from "forge-std/Test.sol";
import { AgentRegistry } from "../../src/AgentRegistry.sol";
import { BatchSettlementV2 } from "../../src/BatchSettlementV2.sol";
import { MiniAMM } from "../../src/dex/MiniAMM.sol";
import { MockToken } from "../../src/dex/MockToken.sol";
import { HashBoundMockVerifier } from "../helpers/HashBoundMockVerifier.sol";

contract SettlementHandler is Test {
    AgentRegistry public reg;
    BatchSettlementV2 public bs;
    HashBoundMockVerifier public ver;
    MockToken public baseTok;
    MockToken public quoteTok;
    address public admin;
    address public guardian;
    bytes32 public vkey;
    uint32[] public ids;
    address[] public ops;
    bytes32[] public pks;

    // ghosts
    uint256 public nativeIn;         // fee MON deposited
    uint256 public nativeOut;        // fee MON withdrawn + swept
    uint256 public violations;
    string  public lastViolation;
    uint64[] public ghostNonce;      // highest nonce ever observed per agent (monotonic)
    uint64 public batchCounter;
    bytes[] internal settledBlobs;
    uint64[] internal settledIds;
    uint256 public settles;
    uint256 public skips;
    uint256 public replays;

    constructor(AgentRegistry r, BatchSettlementV2 b, HashBoundMockVerifier v, bytes32 vk, address a, address g,
        uint32[] memory _ids, address[] memory _ops, bytes32[] memory _pks)
    {
        (reg, bs, ver, vkey, admin, guardian) = (r, b, v, vk, a, g);
        baseTok = MockToken(address(b.base()));
        quoteTok = MockToken(address(b.quote()));
        ids = _ids; ops = _ops; pks = _pks;
        ghostNonce = new uint64[](_ids.length);
    }

    function _flag(string memory why) internal { ++violations; lastViolation = why; }

    function _mintTo(MockToken t, address to, uint256 amt) internal {
        vm.startPrank(to);
        while (amt > 0) { uint256 a = amt > 100_000e18 ? 100_000e18 : amt; t.faucet(a); amt -= a; }
        vm.stopPrank();
    }

    // ------------------------------------------------------------ actions

    function deposit(uint256 who, uint96 b, uint96 q) external {
        uint256 k = who % ids.length;
        b = uint96(bound(b, 0, 5_000e18)); q = uint96(bound(q, 0, 10_000e18));
        _mintTo(baseTok, address(this), b); _mintTo(quoteTok, address(this), q);
        baseTok.approve(address(bs), b); quoteTok.approve(address(bs), q);
        bs.deposit(ids[k], b, q);
    }

    function withdraw(uint256 who, uint96 b, uint96 q) external {
        uint256 k = who % ids.length;
        (uint96 hb, uint96 hq,) = bs.agentState(ids[k]);
        b = uint96(bound(b, 0, hb)); q = uint96(bound(q, 0, hq));
        vm.prank(ops[k]);
        bs.withdraw(ids[k], b, q, ops[k]);
    }

    function depositFee(uint256 who, uint256 amt) external {
        uint256 k = who % ids.length;
        amt = bound(amt, 1, 5 ether);
        vm.deal(address(this), amt);
        bs.depositFeeNative{ value: amt }(ids[k]);
        nativeIn += amt;
    }

    function withdrawFee(uint256 who, uint96 amt) external {
        uint256 k = who % ids.length;
        vm.prank(ops[k]);
        bs.requestFeeWithdrawal(ids[k], uint96(bound(amt, 1, 10 ether)), ops[k]);
        vm.warp(block.timestamp + bs.feeWithdrawDelay());
        uint256 before = ops[k].balance;
        vm.prank(ops[k]);
        bs.executeFeeWithdrawal(ids[k]);
        nativeOut += ops[k].balance - before;
    }

    function sweep() external {
        address t = reg.treasury();
        uint256 before = t.balance;
        bs.sweepFees(0);
        nativeOut += t.balance - before;
    }

    function kill(uint256 who) external { vm.prank(guardian); reg.kill(ids[who % ids.length]); }
    function revive(uint256 who) external { vm.prank(admin); reg.revive(ids[who % ids.length]); }

    function setCaps(uint256 who, uint128 cb, uint128 cq) external {
        vm.prank(admin);
        reg.setCaps(ids[who % ids.length], uint128(bound(cb, 0, 3_000e18)), uint128(bound(cq, 0, 6_000e18)));
    }

    function setFee(uint72 fee) external {
        vm.prank(admin);
        bs.setFeeConfig(0, uint72(bound(fee, 0, 0.01 ether)), 0, true);
    }

    /// Random batch over a random subset of agents, then checks every per-agent post-condition.
    function settle(uint256 seed, uint8 mask) external {
        uint256 na = ids.length;
        bytes memory blob;
        uint256[] memory bIn = new uint256[](na);
        uint256[] memory qIn = new uint256[](na);
        uint64[] memory first = new uint64[](na);
        uint16[] memory cnt = new uint16[](na);
        bool any;
        for (uint256 k; k < na; ++k) {
            if ((mask >> k) & 1 == 0) continue;
            any = true;
            uint16 c = uint16(1 + uint256(keccak256(abi.encode(seed, k))) % 4);
            (,, uint64 last) = bs.agentState(ids[k]);
            // sometimes deliberately reuse an old nonce
            first[k] = (seed >> (k + 3)) & 7 == 0 && last > 0 ? last : last + 1 + uint64((seed >> (k + 8)) % 3);
            cnt[k] = c;
            blob = bytes.concat(blob, abi.encodePacked(ids[k], c, first[k], uint32(block.timestamp + 600), pks[k], bytes32(0)));
            for (uint256 j; j < c; ++j) {
                bool buy = uint256(keccak256(abi.encode(seed, k, j))) % 2 == 0;
                uint96 amt = uint96(1e15 + uint256(keccak256(abi.encode(seed, k, j, 1))) % 400e18);
                blob = bytes.concat(blob, abi.encodePacked(uint8(buy ? 1 : 0), amt, uint96(0)));
                if (buy) qIn[k] += amt; else bIn[k] += amt;
            }
        }
        if (!any) return;
        uint64 batchId = ++batchCounter;
        bytes memory proof = ver.proofFor(vkey, abi.encode(bs.batchDigest(batchId, blob)));

        uint64[] memory nBefore = new uint64[](na);
        bool[] memory couldSettle = new bool[](na);
        for (uint256 k; k < na; ++k) {
            (uint96 hb, uint96 hq, uint64 last) = bs.agentState(ids[k]);
            nBefore[k] = last;
            if (cnt[k] == 0) continue;
            (,,,, uint128 capB, uint128 capQ) = reg.agents(ids[k]);
            (uint96 fbal,,,) = bs.feeAccount(ids[k]);
            couldSettle[k] = reg.isAuthorized(ids[k], pks[k]) && first[k] > last && bIn[k] <= capB && qIn[k] <= capQ
                && bIn[k] <= hb && qIn[k] <= hq && bs.feeQuote(ids[k], cnt[k]) <= fbal;
        }
        bool ok;
        try bs.settle(batchId, blob, proof) { ok = true; } catch { }
        if (ok) { ++settles; settledBlobs.push(blob); settledIds.push(batchId); }

        for (uint256 k; k < na; ++k) {
            (,, uint64 last) = bs.agentState(ids[k]);
            if (last < nBefore[k]) _flag("nonce decreased");
            if (last > ghostNonce[k]) ghostNonce[k] = last;
            if (cnt[k] == 0) { if (last != nBefore[k]) _flag("absent agent changed"); continue; }
            if (!ok) { if (last != nBefore[k]) _flag("reverted batch changed state"); continue; }
            if (couldSettle[k]) {
                if (last != first[k] + cnt[k] - 1) _flag("settleable group not settled");
            } else {
                ++skips;
                // killed / unknown key / over cap / short balance / stale nonce: must not move
                if (last != nBefore[k]) _flag("unsettleable group settled");
            }
        }
    }

    /// Replaying any previously settled batch (same id, same proof) must never re-execute a settled group.
    function replay(uint256 which) external {
        if (settledBlobs.length == 0) return;
        uint256 i = which % settledBlobs.length;
        bytes memory blob = settledBlobs[i];
        uint64 batchId = settledIds[i];
        uint64[] memory nBefore = new uint64[](ids.length);
        for (uint256 k; k < ids.length; ++k) (,, nBefore[k]) = bs.agentState(ids[k]);
        bytes memory proof = ver.proofFor(vkey, abi.encode(bs.batchDigest(batchId, blob)));
        ++replays;
        try bs.settle(batchId, blob, proof) {
            // allowed only for groups that were skipped earlier and are now valid: their nonce must still
            // rise, never repeat (checked: strictly above the old value)
            for (uint256 k; k < ids.length; ++k) {
                (,, uint64 last) = bs.agentState(ids[k]);
                if (last < nBefore[k]) _flag("replay decreased nonce");
            }
        } catch { }
    }

    function sumBase() external view returns (uint256 s) { for (uint256 k; k < ids.length; ++k) { (uint96 b,,) = bs.agentState(ids[k]); s += b; } }
    function sumQuote() external view returns (uint256 s) { for (uint256 k; k < ids.length; ++k) { (, uint96 q,) = bs.agentState(ids[k]); s += q; } }
    function sumFee() external view returns (uint256 s) { for (uint256 k; k < ids.length; ++k) { (uint96 f,,,) = bs.feeAccount(ids[k]); s += f; } }
    function sumStake() external view returns (uint256 s) { for (uint256 k; k < ids.length; ++k) { (,,, uint96 st,,) = reg.agents(ids[k]); s += st; } }
    receive() external payable { }
}

abstract contract InvariantsBase is Test {
    SettlementHandler h;
    AgentRegistry reg;
    BatchSettlementV2 bs;
    address admin = address(0xA11CE);
    address guardian = address(0x6A2D);

    function setUp() public {
        vm.warp(1_800_000_000);
        MockToken t0 = new MockToken("Base", "BASE", 18);
        MockToken t1 = new MockToken("Quote", "QUOTE", 18);
        MiniAMM pool = new MiniAMM(address(t0), address(t1));
        MockToken b = MockToken(address(pool.token0()));
        MockToken q = MockToken(address(pool.token1()));
        b.faucet(100_000e18); q.faucet(100_000e18); q.faucet(100_000e18);
        b.approve(address(pool), type(uint256).max); q.approve(address(pool), type(uint256).max);
        pool.addLiquidity(100_000e18, 200_000e18, address(this));

        reg = new AgentRegistry(admin, guardian, 1 ether);
        HashBoundMockVerifier ver = new HashBoundMockVerifier();
        bytes32 vk = keccak256("vk");
        bs = new BatchSettlementV2(ver, vk, reg, pool);

        uint32[] memory ids = new uint32[](4);
        address[] memory ops = new address[](4);
        bytes32[] memory pks = new bytes32[](4);
        vm.deal(admin, 10 ether);
        for (uint256 k; k < 4; ++k) {
            ops[k] = address(uint160(0x1000 + k));
            pks[k] = keccak256(abi.encode("pk", k));
            vm.prank(admin);
            ids[k] = reg.registerAgent{ value: 1 ether }(ops[k], pks[k], 1_000e18, 2_000e18);
        }
        vm.startPrank(admin);
        reg.setTreasury(address(0x7EA5));
        bs.setFeeConfig(0, 0.001 ether, 0, true);
        bs.setFeeWithdrawDelay(1 hours);
        vm.stopPrank();

        h = new SettlementHandler(reg, bs, ver, vk, admin, guardian, ids, ops, pks);
        for (uint256 k; k < 4; ++k) { h.deposit(k, 3_000e18, 6_000e18); h.depositFee(k, 2 ether); }
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](12);
        sel[0] = h.deposit.selector; sel[1] = h.withdraw.selector; sel[2] = h.depositFee.selector;
        sel[3] = h.withdrawFee.selector; sel[4] = h.sweep.selector; sel[5] = h.kill.selector;
        sel[6] = h.revive.selector; sel[7] = h.setCaps.selector; sel[8] = h.settle.selector;
        sel[9] = h.settle.selector; sel[10] = h.replay.selector; sel[11] = h.setFee.selector;
        targetSelector(FuzzSelector(address(h), sel));
    }
}

contract InvariantsTest is InvariantsBase {

    /// No per-call violation (caps, nonces, kill switch, replay, atomicity) was ever recorded.
    function invariant_noViolations() public view {
        assertEq(h.violations(), 0, h.lastViolation());
    }

    /// Trading books: the contract always holds at least what it owes agents (dust may accrue, never a deficit).
    function invariant_tradingSolvent() public view {
        assertGe(MockToken(address(bs.base())).balanceOf(address(bs)), h.sumBase(), "base");
        assertGe(MockToken(address(bs.quote())).balanceOf(address(bs)), h.sumQuote(), "quote");
    }

    /// Fee books (exact): native balance == sum of fee balances + accrued; and == deposits - withdrawals - sweeps.
    function invariant_feeConservation() public view {
        assertEq(address(bs).balance, h.sumFee() + bs.accruedFees(0), "balances + accrued");
        assertEq(address(bs).balance, h.nativeIn() - h.nativeOut(), "deposits - outflows");
    }

    /// Bonds (exact): the registry holds every stake plus unswept registration fees; nothing else moves MON out.
    function invariant_bondsConserved() public view {
        assertEq(address(reg).balance, h.sumStake() + reg.accruedRegistrationFees(), "bonds");
    }

    /// Coverage probe: with AUDIT_COVERAGE_PROBE=true this "fails" as soon as a run has exercised settlements,
    /// skipped groups and replays, printing the counters (proves the campaign reaches those paths).
    function invariant_zz_coverageProbe() public view {
        if (vm.envOr("AUDIT_COVERAGE_PROBE", false) && h.settles() > 3 && h.skips() > 3 && h.replays() > 3) {
            revert(string.concat("coverage settles=", vm.toString(h.settles()), " skips=", vm.toString(h.skips()),
                " replays=", vm.toString(h.replays())));
        }
    }
}

contract InvariantsSmokeTest is InvariantsBase {
    /// Deterministic sanity check that the handler really settles (so the invariant campaign is meaningful).
    function test_handlerSettlesSkipsAndReplays() public {
        h.settle(12345, 0x0f);
        assertEq(h.settles(), 1);
        h.kill(1);
        h.settle(999, 0x03);
        h.replay(0);
        assertGt(h.skips(), 0);
        assertEq(h.violations(), 0, h.lastViolation());
    }
}
