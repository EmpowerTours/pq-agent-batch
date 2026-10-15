// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title  MiniAMM — minimal constant-product AMM (one pair per contract)
/// @notice Mirrors Uniswap V2's `x*y=k` AMM math at a fraction of the
///         contract surface. One pair (token0/token1) per deployed
///         instance. Liquidity providers mint LP tokens proportional
///         to their contribution; swappers pay a 0.3% fee that stays
///         in the reserves (no protocol fee).
/// @dev    Built fresh against OpenZeppelin's audited ERC20 because the
///         canonical Uniswap V2 source targets solc 0.5.x and porting
///         the legacy pragmas + math under-flow guards is more work than
///         restating the AMM cleanly under 0.8.28's checked arithmetic.
///         Honest framing: this is "Uniswap V2-style AMM math" — the
///         constant-product invariant and 0.3% fee are identical; the
///         LP token bookkeeping is identical; the wire-protocol of swap
///         events follows the same shape so indexers can recognise it.
contract MiniAMM is ERC20, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable token0;
    IERC20 public immutable token1;

    uint112 private _reserve0;
    uint112 private _reserve1;

    uint256 public constant MINIMUM_LIQUIDITY = 1_000;
    /// @notice Swap fee in per-mille (parts per 1000). V2-canonical value
    ///         is 3 = 0.3%. Initial deployment used FEE_BPS = 30 (a
    ///         misnamed constant that produced an actual 3% fee). Fixed
    ///         in the v2 redeploy of the mini-DEX stack.
    uint256 public constant FEE_PER_MILLE = 3;

    event Mint(address indexed sender, uint256 amount0, uint256 amount1, uint256 liquidity);
    event Burn(address indexed sender, uint256 amount0, uint256 amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    error ZeroLiquidity();
    error InsufficientOutput();
    error InsufficientInput();
    error InvalidK();
    error IdenticalTokens();
    error Overflow();

    constructor(address _token0, address _token1)
        ERC20("MiniAMM LP", "MAMM-LP")
    {
        if (_token0 == _token1) revert IdenticalTokens();
        // Sort so lower address is token0 — same convention as Uniswap V2.
        (address t0, address t1) = _token0 < _token1
            ? (_token0, _token1)
            : (_token1, _token0);
        token0 = IERC20(t0);
        token1 = IERC20(t1);
    }

    function getReserves() public view returns (uint112 r0, uint112 r1) {
        return (_reserve0, _reserve1);
    }

    /// @notice Add liquidity by depositing token0+token1 in current ratio.
    ///         Caller must have approved this contract beforehand.
    /// @param  amount0Desired   max token0 to spend
    /// @param  amount1Desired   max token1 to spend
    /// @param  to               LP token recipient
    /// @return amount0          actual token0 spent
    /// @return amount1          actual token1 spent
    /// @return liquidity        LP tokens minted
    function addLiquidity(
        uint256 amount0Desired,
        uint256 amount1Desired,
        address to
    ) external nonReentrant returns (uint256 amount0, uint256 amount1, uint256 liquidity) {
        (uint112 r0, uint112 r1) = getReserves();
        if (r0 == 0 && r1 == 0) {
            // First deposit sets the price.
            amount0 = amount0Desired;
            amount1 = amount1Desired;
        } else {
            uint256 amount1Optimal = (amount0Desired * r1) / r0;
            if (amount1Optimal <= amount1Desired) {
                amount0 = amount0Desired;
                amount1 = amount1Optimal;
            } else {
                uint256 amount0Optimal = (amount1Desired * r0) / r1;
                amount0 = amount0Optimal;
                amount1 = amount1Desired;
            }
        }
        token0.safeTransferFrom(msg.sender, address(this), amount0);
        token1.safeTransferFrom(msg.sender, address(this), amount1);

        uint256 _totalSupply = totalSupply();
        if (_totalSupply == 0) {
            liquidity = _sqrt(amount0 * amount1);
            if (liquidity <= MINIMUM_LIQUIDITY) revert ZeroLiquidity();
            liquidity -= MINIMUM_LIQUIDITY;
            _mint(address(0xdead), MINIMUM_LIQUIDITY); // lock against vampire dust
        } else {
            uint256 liq0 = (amount0 * _totalSupply) / r0;
            uint256 liq1 = (amount1 * _totalSupply) / r1;
            liquidity = liq0 < liq1 ? liq0 : liq1;
        }
        if (liquidity == 0) revert ZeroLiquidity();
        _mint(to, liquidity);
        _update();
        emit Mint(msg.sender, amount0, amount1, liquidity);
    }

    /// @notice Burn LP tokens to redeem underlying token0+token1.
    function removeLiquidity(uint256 liquidity, address to)
        external
        nonReentrant
        returns (uint256 amount0, uint256 amount1)
    {
        uint256 _totalSupply = totalSupply();
        uint256 bal0 = token0.balanceOf(address(this));
        uint256 bal1 = token1.balanceOf(address(this));
        amount0 = (liquidity * bal0) / _totalSupply;
        amount1 = (liquidity * bal1) / _totalSupply;
        if (amount0 == 0 || amount1 == 0) revert ZeroLiquidity();
        _burn(msg.sender, liquidity);
        token0.safeTransfer(to, amount0);
        token1.safeTransfer(to, amount1);
        _update();
        emit Burn(msg.sender, amount0, amount1, to);
    }

    /// @notice Constant-product swap with 0.3% fee.
    /// @param  amount0Out       token0 to send out (0 if swapping token0→token1)
    /// @param  amount1Out       token1 to send out (0 if swapping token1→token0)
    /// @param  to               recipient of the output token
    function swap(uint256 amount0Out, uint256 amount1Out, address to) external nonReentrant {
        if (amount0Out == 0 && amount1Out == 0) revert InsufficientOutput();
        (uint112 r0, uint112 r1) = getReserves();
        if (amount0Out >= r0 || amount1Out >= r1) revert InsufficientOutput();

        // Caller must have already transferred input tokens to this contract.
        // (Standard V2 callback pattern simplified for our routing vault use.)
        uint256 balance0 = token0.balanceOf(address(this)) - amount0Out;
        uint256 balance1 = token1.balanceOf(address(this)) - amount1Out;
        uint256 amount0In = balance0 + amount0Out > r0
            ? balance0 + amount0Out - r0
            : 0;
        uint256 amount1In = balance1 + amount1Out > r1
            ? balance1 + amount1Out - r1
            : 0;
        if (amount0In == 0 && amount1In == 0) revert InsufficientInput();

        // Apply 0.3% fee. Multiply balances by 1000 - fee_bps; the k
        // invariant becomes: balance0Adjusted * balance1Adjusted >= r0 * r1 * 1000 * 1000.
        uint256 balance0Adjusted = balance0 * 1000 - amount0In * FEE_PER_MILLE;
        uint256 balance1Adjusted = balance1 * 1000 - amount1In * FEE_PER_MILLE;
        if (balance0Adjusted * balance1Adjusted < uint256(r0) * uint256(r1) * 1_000_000) {
            revert InvalidK();
        }

        if (amount0Out > 0) token0.safeTransfer(to, amount0Out);
        if (amount1Out > 0) token1.safeTransfer(to, amount1Out);
        _update();
        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

    /// @notice View helper — how much token1 you get for `amountIn` of token0.
    function quoteToken1Out(uint256 amountIn) external view returns (uint256) {
        (uint112 r0, uint112 r1) = getReserves();
        if (r0 == 0 || r1 == 0 || amountIn == 0) return 0;
        uint256 amountInWithFee = amountIn * (1000 - FEE_PER_MILLE);
        uint256 numerator = amountInWithFee * r1;
        uint256 denominator = uint256(r0) * 1000 + amountInWithFee;
        return numerator / denominator;
    }

    /// @notice View helper — how much token0 you get for `amountIn` of token1.
    function quoteToken0Out(uint256 amountIn) external view returns (uint256) {
        (uint112 r0, uint112 r1) = getReserves();
        if (r0 == 0 || r1 == 0 || amountIn == 0) return 0;
        uint256 amountInWithFee = amountIn * (1000 - FEE_PER_MILLE);
        uint256 numerator = amountInWithFee * r0;
        uint256 denominator = uint256(r1) * 1000 + amountInWithFee;
        return numerator / denominator;
    }

    /// @notice Recover tokens force-credited to the pair (SELFDESTRUCT,
    ///         coinbase, direct transfer, or any other vector that
    ///         pushes balance above reserve). Without this, an attacker
    ///         could donate enough tokens to overflow uint112 and
    ///         permanently DoS the pair. Anyone may call; the excess
    ///         tokens go to `to`. (Audit fix M-2.)
    function skim(address to) external nonReentrant {
        uint256 bal0 = token0.balanceOf(address(this));
        uint256 bal1 = token1.balanceOf(address(this));
        if (bal0 > _reserve0) {
            token0.safeTransfer(to, bal0 - _reserve0);
        }
        if (bal1 > _reserve1) {
            token1.safeTransfer(to, bal1 - _reserve1);
        }
    }

    /// @notice Force the reserves to match the actual balance. Companion
    ///         to skim; lets anyone reset the accounting after force-credit.
    function sync() external nonReentrant {
        _update();
    }

    function _update() internal {
        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));
        if (b0 > type(uint112).max || b1 > type(uint112).max) revert Overflow();
        _reserve0 = uint112(b0);
        _reserve1 = uint112(b1);
        emit Sync(_reserve0, _reserve1);
    }

    function _sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) { z = x; x = (y / x + x) / 2; }
        } else if (y != 0) {
            z = 1;
        }
    }
}
