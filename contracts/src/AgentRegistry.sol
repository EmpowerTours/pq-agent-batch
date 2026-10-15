// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title  AgentRegistry
/// @notice Who may trade through BatchSettlementV2, with which post-quantum keys,
///         and how much per batch.
/// @dev    Milestone scope: permissioned registration by `admin`. Each agent has
///         a set of ML-DSA-65 key commitments (SHA-256 of the encoded public
///         key, the same `pkHash` the SP1 guest commits), a MON stake, per-batch
///         caps on what it can spend of each side of the market, and a kill
///         switch. Slashing is NOT implemented yet; stake is only escrowed.
contract AgentRegistry {
    struct Agent {
        address operator;     // can manage its own keys, kill itself, withdraw stake once retired
        bool    active;       // registered
        bool    killed;       // kill switch; settlement rejects every order while set
        uint96  stake;        // MON escrowed at registration
        uint128 capBaseIn;    // max base token the agent may sell per batch
        uint128 capQuoteIn;   // max quote token the agent may spend per batch
    }

    address public admin;
    address public guardian;   // may only kill, never unkill or register
    uint96  public immutable minStake;
    uint32  public agentCount;

    mapping(uint32 => Agent) public agents;
    mapping(uint32 => mapping(bytes32 => bool)) public isAgentKey;
    mapping(uint32 => uint32) public keyCount;

    event AgentRegistered(uint32 indexed agentId, address operator, bytes32 pkHash, uint96 stake);
    event KeyAdded(uint32 indexed agentId, bytes32 pkHash);
    event KeyRevoked(uint32 indexed agentId, bytes32 pkHash);
    event CapsSet(uint32 indexed agentId, uint128 capBaseIn, uint128 capQuoteIn);
    event Killed(uint32 indexed agentId, address by);
    event Revived(uint32 indexed agentId);
    event GuardianSet(address previous, address next);
    event Slashed(uint32 indexed agentId, uint96 amount, address to);
    event Retired(uint32 indexed agentId, uint96 refund);

    error NotAdmin();
    error NotAuthorised();
    error UnknownAgent(uint32 agentId);
    error AgentKilled(uint32 agentId);
    error UnknownKey(uint32 agentId, bytes32 pkHash);
    error StakeTooLow(uint256 sent, uint256 min);
    error LastKey();
    error ZeroValue();
    error TransferFailed();

    constructor(address _admin, address _guardian, uint96 _minStake) {
        if (_admin == address(0) || _guardian == address(0)) revert ZeroValue();
        admin = _admin;
        guardian = _guardian;
        minStake = _minStake;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyAdminOrOperator(uint32 id) {
        if (msg.sender != admin && msg.sender != agents[id].operator) revert NotAuthorised();
        _;
    }

    // ------------------------------------------------------------ registration

    function registerAgent(address operator, bytes32 pkHash, uint128 capBaseIn, uint128 capQuoteIn)
        external
        payable
        onlyAdmin
        returns (uint32 id)
    {
        if (operator == address(0) || pkHash == bytes32(0)) revert ZeroValue();
        if (msg.value < minStake) revert StakeTooLow(msg.value, minStake);
        id = ++agentCount;
        agents[id] = Agent(operator, true, false, uint96(msg.value), capBaseIn, capQuoteIn);
        isAgentKey[id][pkHash] = true;
        keyCount[id] = 1;
        emit AgentRegistered(id, operator, pkHash, uint96(msg.value));
        emit CapsSet(id, capBaseIn, capQuoteIn);
    }

    function addKey(uint32 id, bytes32 pkHash) external onlyAdminOrOperator(id) {
        if (!agents[id].active) revert UnknownAgent(id);
        if (pkHash == bytes32(0)) revert ZeroValue();
        if (!isAgentKey[id][pkHash]) {
            isAgentKey[id][pkHash] = true;
            keyCount[id] += 1;
            emit KeyAdded(id, pkHash);
        }
    }

    /// @dev Never leaves an agent with zero keys (mirrors MLDSAAttestationV2's no-brick rule).
    function revokeKey(uint32 id, bytes32 pkHash) external onlyAdminOrOperator(id) {
        if (!isAgentKey[id][pkHash]) revert UnknownKey(id, pkHash);
        if (keyCount[id] == 1) revert LastKey();
        isAgentKey[id][pkHash] = false;
        keyCount[id] -= 1;
        emit KeyRevoked(id, pkHash);
    }

    function setCaps(uint32 id, uint128 capBaseIn, uint128 capQuoteIn) external onlyAdmin {
        if (!agents[id].active) revert UnknownAgent(id);
        agents[id].capBaseIn = capBaseIn;
        agents[id].capQuoteIn = capQuoteIn;
        emit CapsSet(id, capBaseIn, capQuoteIn);
    }

    // ------------------------------------------------------------ kill switch

    /// @notice Admin, guardian or the agent's own operator can stop an agent instantly.
    function kill(uint32 id) external {
        if (msg.sender != admin && msg.sender != guardian && msg.sender != agents[id].operator) {
            revert NotAuthorised();
        }
        if (!agents[id].active) revert UnknownAgent(id);
        agents[id].killed = true;
        emit Killed(id, msg.sender);
    }

    /// @notice Only the admin can bring an agent back.
    function revive(uint32 id) external onlyAdmin {
        agents[id].killed = false;
        emit Revived(id);
    }

    function setGuardian(address g) external onlyAdmin {
        if (g == address(0)) revert ZeroValue();
        emit GuardianSet(guardian, g);
        guardian = g;
    }

    // ------------------------------------------------------------ stake

    /// @notice Placeholder for the slashing policy: admin moves stake out.
    function slash(uint32 id, uint96 amount, address payable to) external onlyAdmin {
        agents[id].stake -= amount;
        emit Slashed(id, amount, to);
        (bool ok,) = to.call{ value: amount }("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Retire an agent (permanently inactive) and refund remaining stake to its operator.
    function retire(uint32 id) external onlyAdmin {
        Agent storage a = agents[id];
        if (!a.active) revert UnknownAgent(id);
        uint96 refund = a.stake;
        a.active = false;
        a.stake = 0;
        emit Retired(id, refund);
        (bool ok,) = payable(a.operator).call{ value: refund }("");
        if (!ok) revert TransferFailed();
    }

    // ------------------------------------------------------------ settlement view

    /// @notice One call per agent per batch: reverts unless the agent may trade.
    function tradingLimits(uint32 id) external view returns (uint128 capBaseIn, uint128 capQuoteIn) {
        Agent storage a = agents[id];
        if (!a.active) revert UnknownAgent(id);
        if (a.killed) revert AgentKilled(id);
        return (a.capBaseIn, a.capQuoteIn);
    }

    /// @notice tradingLimits + requireKey in ONE call (used by BatchSettlementV2, once per agent group).
    function checkAgent(uint32 id, bytes32 pkHash) external view returns (uint128 capBaseIn, uint128 capQuoteIn) {
        Agent storage a = agents[id];
        if (!a.active) revert UnknownAgent(id);
        if (a.killed) revert AgentKilled(id);
        if (!isAgentKey[id][pkHash]) revert UnknownKey(id, pkHash);
        return (a.capBaseIn, a.capQuoteIn);
    }

    /// @notice Reverts unless `pkHash` is a currently authorised key of agent `id`.
    function requireKey(uint32 id, bytes32 pkHash) external view {
        if (!isAgentKey[id][pkHash]) revert UnknownKey(id, pkHash);
    }
}
