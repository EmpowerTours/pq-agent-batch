// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title  MockToken — testnet ERC20 with a public faucet
/// @notice Anyone can call `faucet(amount)` to mint up to `MAX_PER_CALL`
///         tokens to their own address. Used to bootstrap test stablecoins
///         (mUSDC, mUSDT) for the agent's DeFi-pool selection demo.
/// @dev    Testnet-only — `faucet()` mints unbounded over time; for
///         mainnet, deploy a real bridged token instead.
contract MockToken is ERC20 {
    uint256 public constant MAX_PER_CALL = 100_000 * 10 ** 18; // 100k tokens per call
    uint8 private immutable _DECIMALS;

    error AmountTooLarge();

    constructor(string memory _name, string memory _symbol, uint8 decimals_)
        ERC20(_name, _symbol)
    {
        _DECIMALS = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _DECIMALS;
    }

    /// @notice Public mint - anyone can claim up to MAX_PER_CALL tokens.
    function faucet(uint256 amount) external {
        if (amount > MAX_PER_CALL) revert AmountTooLarge();
        _mint(msg.sender, amount);
    }
}
