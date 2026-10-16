// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title  AgentRegistry
/// @notice Who may trade through BatchSettlementV2, with which post-quantum keys,
///         and how much per batch.
/// @dev    Admin powers (register, caps, revive, fees, slash, retire) are meant for a multisig behind a
///         timelock; the guardian (kill only) for a fast multisig. Admin is transferable in two steps.
///         Milestone scope: permissioned registration by `admin`. Each agent has
///         a set of ML-DSA-65 key commitments (SHA-256 of the encoded public
///         key, the same `pkHash` the SP1 guest commits), a MON stake, per-batch
///         caps on what it can spend of each side of the market, and a kill
///         switch. Slashing is NOT implemented yet; stake is only escrowed.
///
///         Payments: registration costs a one-time, non-refundable `registrationFee` (accrued for
///         the treasury) plus a refundable bond (`stake`, at least `minStake`, returned on
///         retire). `treasury` (intended: a multisig) also receives the settlement's action fees.
///         Admin may open self-registration, where anyone registers an agent for themselves with
///         the admin's default caps.
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
    address public pendingAdmin;   // two-step admin transfer (audit L-04)
    address public guardian;   // may only kill, never unkill or register
    uint96  public immutable minStake;
    uint32  public agentCount;

    mapping(uint32 => Agent) public agents;
    mapping(uint32 => mapping(bytes32 => bool)) public isAgentKey;
    mapping(uint32 => uint32) public keyCount;

    address public treasury;                 // fee recipient (registration + settlement fees)
    uint96  public registrationFee;          // one-time, non-refundable, on top of the bond
    uint256 public accruedRegistrationFees;  // owed to the treasury
    bool    public openRegistration;         // anyone may selfRegister()
    uint128 public defaultCapBaseIn;         // maximum (and default) caps for self-registered agents
    uint128 public defaultCapQuoteIn;

    event AgentRegistered(uint32 indexed agentId, address operator, bytes32 pkHash, uint96 stake);
    event KeyAdded(uint32 indexed agentId, bytes32 pkHash);
    event KeyRevoked(uint32 indexed agentId, bytes32 pkHash);
    event CapsSet(uint32 indexed agentId, uint128 capBaseIn, uint128 capQuoteIn);
    event Killed(uint32 indexed agentId, address by);
    event Revived(uint32 indexed agentId);
    event GuardianSet(address previous, address next);
    event Slashed(uint32 indexed agentId, uint96 amount, address to);
    event Retired(uint32 indexed agentId, uint96 refund);
    event TreasurySet(address previous, address next);
    event RegistrationFeeSet(uint96 fee);
    event RegistrationFeePaid(uint32 indexed agentId, uint96 fee);
    event OpenRegistrationSet(bool open, uint128 capBaseIn, uint128 capQuoteIn);
    event RegistrationFeesSwept(uint256 amount, address to);
    event AdminTransferStarted(address indexed current, address indexed pending);
    event AdminTransferred(address indexed previous, address indexed next);

    error NotAdmin();
    error NotAuthorised();
    error UnknownAgent(uint32 agentId);
    error AgentKilled(uint32 agentId);
    error UnknownKey(uint32 agentId, bytes32 pkHash);
    error StakeTooLow(uint256 sent, uint256 min);
    error RegistrationClosed();
    error CapsTooHigh(uint128 capBaseIn, uint128 capQuoteIn, uint128 maxBaseIn, uint128 maxQuoteIn);
    error LastKey();
    error ZeroValue();
    error TransferFailed();
    error NotPendingAdmin();

    /// Non-reverting status codes returned by agentStatus().
    uint8 public constant STATUS_OK = 0;
    uint8 public constant STATUS_UNKNOWN_AGENT = 1;
    uint8 public constant STATUS_KILLED = 2;
    uint8 public constant STATUS_UNKNOWN_KEY = 3;

    constructor(address _admin, address _guardian, uint96 _minStake) {
        if (_admin == address(0) || _guardian == address(0)) revert ZeroValue();
        admin = _admin;
        guardian = _guardian;
        minStake = _minStake;
        treasury = _admin;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyAdminOrOperator(uint32 id) {
        if (msg.sender != admin && msg.sender != agents[id].operator) revert NotAuthorised();
        _;
    }

    // ------------------------------------------------------------ admin handover

    /// @notice Step 1 of 2: propose a new admin (e.g. a Safe multisig or a timelock). address(0) cancels.
    function transferAdmin(address next) external onlyAdmin {
        pendingAdmin = next;
        emit AdminTransferStarted(admin, next);
    }

    /// @notice Step 2 of 2: the proposed admin accepts. Prevents handing control to a wrong address.
    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        emit AdminTransferred(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }

    // ------------------------------------------------------------ registration

    /// @notice msg.value = registrationFee (to treasury) + bond (>= minStake, refundable on retire).
    function registerAgent(address operator, bytes32 pkHash, uint128 capBaseIn, uint128 capQuoteIn)
        external
        payable
        onlyAdmin
        returns (uint32 id)
    {
        return _register(operator, pkHash, capBaseIn, capQuoteIn);
    }

    /// @notice Permissionless registration (only while `openRegistration`): msg.sender becomes the
    ///         operator. Requested caps may not exceed the admin's self-registration maximums
    ///         (`defaultCapBaseIn/QuoteIn`); 0 means "the maximum". Same fee + bond rule as registerAgent.
    function selfRegister(bytes32 pkHash, uint128 capBaseIn, uint128 capQuoteIn) external payable returns (uint32 id) {
        if (!openRegistration) revert RegistrationClosed();
        uint128 maxB = defaultCapBaseIn;
        uint128 maxQ = defaultCapQuoteIn;
        if (capBaseIn > maxB || capQuoteIn > maxQ) revert CapsTooHigh(capBaseIn, capQuoteIn, maxB, maxQ);
        return _register(msg.sender, pkHash, capBaseIn == 0 ? maxB : capBaseIn, capQuoteIn == 0 ? maxQ : capQuoteIn);
    }

    function _register(address operator, bytes32 pkHash, uint128 capBaseIn, uint128 capQuoteIn)
        private
        returns (uint32 id)
    {
        if (operator == address(0) || pkHash == bytes32(0)) revert ZeroValue();
        uint96 fee = registrationFee;
        if (msg.value < uint256(minStake) + fee) revert StakeTooLow(msg.value, uint256(minStake) + fee);
        if (msg.value - fee > type(uint96).max) revert StakeTooLow(msg.value, type(uint96).max); // bond is uint96
        uint96 bond = uint96(msg.value - fee);
        id = ++agentCount;
        agents[id] = Agent(operator, true, false, bond, capBaseIn, capQuoteIn);
        isAgentKey[id][pkHash] = true;
        keyCount[id] = 1;
        if (fee != 0) {
            accruedRegistrationFees += fee;
            emit RegistrationFeePaid(id, fee);
        }
        emit AgentRegistered(id, operator, pkHash, bond);
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

    // ------------------------------------------------------------ payments config

    function setTreasury(address t) external onlyAdmin {
        if (t == address(0)) revert ZeroValue();
        emit TreasurySet(treasury, t);
        treasury = t;
    }

    function setRegistrationFee(uint96 fee) external onlyAdmin {
        registrationFee = fee;
        emit RegistrationFeeSet(fee);
    }

    function setOpenRegistration(bool open, uint128 capBaseIn, uint128 capQuoteIn) external onlyAdmin {
        openRegistration = open;
        defaultCapBaseIn = capBaseIn;
        defaultCapQuoteIn = capQuoteIn;
        emit OpenRegistrationSet(open, capBaseIn, capQuoteIn);
    }

    /// @notice Permissionless: send accrued registration fees to the treasury.
    function sweepRegistrationFees() external {
        uint256 amt = accruedRegistrationFees;
        accruedRegistrationFees = 0;
        address to = treasury;
        emit RegistrationFeesSwept(amt, to);
        // slither-disable-next-line arbitrary-send-eth (audit S-02: `to` is the admin-set treasury, amount is accrued fees)
        (bool ok,) = payable(to).call{ value: amt }("");
        if (!ok) revert TransferFailed();
    }

    function setGuardian(address g) external onlyAdmin {
        if (g == address(0)) revert ZeroValue();
        emit GuardianSet(guardian, g);
        guardian = g;
    }

    // ------------------------------------------------------------ stake

    /// @notice Placeholder for the slashing policy: admin moves stake out.
    function slash(uint32 id, uint96 amount, address payable to) external onlyAdmin {
        if (to == address(0)) revert ZeroValue();
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

    /// @notice Non-reverting form of checkAgent, used by BatchSettlementV2 so that one bad agent group is
    ///         skipped instead of reverting the whole proved batch (audit M-01). status: see STATUS_*.
    function agentStatus(uint32 id, bytes32 pkHash)
        external
        view
        returns (uint8 status, uint128 capBaseIn, uint128 capQuoteIn)
    {
        Agent storage a = agents[id];
        if (!a.active) return (STATUS_UNKNOWN_AGENT, 0, 0);
        if (a.killed) return (STATUS_KILLED, 0, 0);
        if (!isAgentKey[id][pkHash]) return (STATUS_UNKNOWN_KEY, 0, 0);
        return (STATUS_OK, a.capBaseIn, a.capQuoteIn);
    }

    /// @notice For apps: is `pkHash` a current key of a live (registered, not killed) agent?
    function isAuthorized(uint32 id, bytes32 pkHash) external view returns (bool) {
        Agent storage a = agents[id];
        return a.active && !a.killed && isAgentKey[id][pkHash];
    }

    /// @notice Reverts unless `pkHash` is a currently authorised key of agent `id`.
    function requireKey(uint32 id, bytes32 pkHash) external view {
        if (!isAgentKey[id][pkHash]) revert UnknownKey(id, pkHash);
    }
}
