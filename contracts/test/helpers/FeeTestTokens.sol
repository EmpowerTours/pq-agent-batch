// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// NOT FOR DEPLOYMENT. Test helpers for the fee/top-up reentrancy tests.

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// ERC20 that, once armed, re-enters a target during transferFrom/transfer and records the revert data.
contract ReentrantToken is ERC20 {
    address public target;
    bytes public payload;
    bool public reentered;
    bytes public lastRevert;

    constructor() ERC20("Reentrant", "RE") {}

    function mint(address to, uint256 amt) external { _mint(to, amt); }

    function arm(address t, bytes calldata p) external {
        target = t;
        payload = p;
    }

    function _hook() internal {
        if (target == address(0) || reentered) return;
        reentered = true;
        (bool ok, bytes memory ret) = target.call(payload);
        require(!ok, "reentrant call succeeded");
        lastRevert = ret;
    }

    function transferFrom(address from, address to, uint256 v) public override returns (bool) {
        _hook();
        return super.transferFrom(from, to, v);
    }

    function transfer(address to, uint256 v) public override returns (bool) {
        _hook();
        return super.transfer(to, v);
    }
}

/// Contract operator whose receive() re-enters the settlement when it is paid in native MON.
contract ReentrantOperator {
    address public target;
    bytes public payload;
    bool public reentered;
    bytes public lastRevert;

    function arm(address t, bytes calldata p) external {
        target = t;
        payload = p;
    }

    function exec(address t, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = t.call{ value: msg.value }(data);
        if (!ok) assembly { revert(add(ret, 0x20), mload(ret)) }
        return ret;
    }

    receive() external payable {
        if (target == address(0) || reentered) return;
        reentered = true;
        (bool ok, bytes memory ret) = target.call(payload);
        require(!ok, "reentrant call succeeded");
        lastRevert = ret;
    }
}
