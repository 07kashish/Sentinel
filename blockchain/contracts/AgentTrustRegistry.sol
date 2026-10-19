// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AgentTrustRegistry
 * @dev Tamper-evident registry of agent security incidents.
 *
 * COUNCIL FINDING 4 (Critical): the previous version declared
 * `recordIncident(...) public` with no modifier and no validation. Any address on
 * the network could record any hash against any agent for the cost of gas. A
 * "trust registry" whose writes are unauthenticated is a public bulletin board
 * with permanent ink: an attacker could flood it with fabricated accusations
 * against a competitor's agents, and nothing distinguished those entries from
 * Sentinel's own.
 *
 * This version adds:
 *   - An owner, set at deployment.
 *   - An explicit writer allow-list; only allow-listed addresses may record.
 *   - Severity validation (1..100), matching the off-chain schema.
 *   - Non-zero agent validation, so a blank/fabricated subject cannot be
 *     recorded even by an authorised-but-buggy writer.
 *   - `recordedBy` stored and emitted, so every entry is attributable.
 *   - Events for authorisation changes, making the writer set itself auditable.
 *
 * DEPLOYMENT NOTE: this changes storage layout and the external API, and there is
 * no proxy, so the contract CANNOT be upgraded in place. A fresh deployment is
 * required and CONTRACT_ADDRESS must be repointed at it. Entries recorded against
 * the previous contract remain readable there but are unauthenticated by
 * construction and must not be treated as evidence.
 */
contract AgentTrustRegistry {

    struct Incident {
        bytes32 incidentHash;
        address agent;
        uint256 severity;
        uint256 timestamp;
        address recordedBy;
    }

    address public owner;
    mapping(address => bool) public authorizedWriters;
    mapping(address => Incident[]) private incidents;
    mapping(bytes32 => bool) public recordedIncidents;

    event IncidentRecorded(
        address indexed agent,
        bytes32 indexed incidentHash,
        uint256 severity,
        uint256 timestamp,
        address indexed recordedBy
    );
    event WriterAuthorized(address indexed writer);
    event WriterRevoked(address indexed writer);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotAuthorized();
    error InvalidSeverity(uint256 severity);
    error InvalidAgent();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyAuthorized() {
        if (!authorizedWriters[msg.sender]) revert NotAuthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
        // The deployer is the first authorised writer. Revoke explicitly if the
        // recording key should differ from the owning key.
        authorizedWriters[msg.sender] = true;
        emit WriterAuthorized(msg.sender);
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function authorizeWriter(address writer) external onlyOwner {
        if (writer == address(0)) revert InvalidAgent();
        authorizedWriters[writer] = true;
        emit WriterAuthorized(writer);
    }

    function revokeWriter(address writer) external onlyOwner {
        authorizedWriters[writer] = false;
        emit WriterRevoked(writer);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidAgent();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /**
     * @dev Record an incident. Restricted to allow-listed writers.
     * @param incidentHash Hash of the canonical off-chain evidence object.
     * @param agent The agent's address. Must be the signature-recovered identity
     *              of the agent, never a generated stand-in (council Finding 5).
     * @param severity Assessed severity, 1..100.
     */
    function recordIncident(
        bytes32 incidentHash,
        address agent,
        uint256 severity
    ) external onlyAuthorized {
        if (agent == address(0)) revert InvalidAgent();
        if (severity == 0 || severity > 100) revert InvalidSeverity(severity);

        // Idempotency is enforced by the destination, not by hoping the caller
        // never retries. A worker can crash after this transaction is mined but
        // before its outbox receipt commits; replaying the same evidence is a
        // successful no-op and can never create a duplicate permanent record.
        bytes32 recordKey = keccak256(abi.encode(msg.sender, incidentHash, agent));
        if (recordedIncidents[recordKey]) return;
        recordedIncidents[recordKey] = true;

        incidents[agent].push(
            Incident(incidentHash, agent, severity, block.timestamp, msg.sender)
        );

        emit IncidentRecorded(agent, incidentHash, severity, block.timestamp, msg.sender);
    }

    function getIncidents(address agent) external view returns (Incident[] memory) {
        return incidents[agent];
    }

    function incidentCount(address agent) external view returns (uint256) {
        return incidents[agent].length;
    }
}
