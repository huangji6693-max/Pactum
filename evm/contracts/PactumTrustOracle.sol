// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IPactumTrustOracle} from "./interfaces/IPactumTrustOracle.sol";
import {IPactumMessageReceiver} from "./interfaces/IPactumMessageReceiver.sol";
import {PactumStateProofVerifier} from "./libraries/PactumStateProofVerifier.sol";
import {PactumZeroTrustOracle} from "./PactumZeroTrustOracle.sol";

/// @title PactumTrustOracle
/// @notice Destination-chain proof of concept for the Cross-Chain Reputation Bridging Standard.
/// Caches Pactum trust scores bridged from the Soroban registry contract on Stellar. See
/// docs/cross-chain-trust-bridge.md for the full design and rationale for each check below.
/// @dev This contract implements Layer 2 (application-level integrity) of the verification model.
/// Layer 1 (transport authenticity) is delegated to `messagingEndpoint`, restricted via
/// `onlyEndpoint`, mirroring the standard LayerZero/CCIP "trusted peer" pattern. In this proof of
/// concept `messagingEndpoint` is a mock (see contracts/mocks/MockMessagingEndpoint.sol); in
/// production it would be a real provider's verified endpoint contract.
contract PactumTrustOracle is IPactumTrustOracle, IPactumMessageReceiver, Ownable {
    /// @notice Current schema version this contract knows how to decode.
    uint8 public constant SCHEMA_VERSION = 1;

    /// @notice Upper bound on entries per batch, so processing one message has predictable gas.
    uint256 public constant MAX_BATCH_SIZE = 50;

    /// @notice The messaging network's verified endpoint. Only this address may call
    /// `receiveMessage`.
    address public messagingEndpoint;

    /// @notice Allow-listed source chain id -> allow-listed source (Soroban) contract address,
    /// mirroring the LayerZero/CCIP "trusted remote" pattern: a message is only accepted if it
    /// both arrives via `messagingEndpoint` AND declares a (sourceChainId, sourceAddress) pair
    /// registered here.
    mapping(uint32 => bytes32) public trustedRemotes;

    /// @notice The single Soroban registry contract id this Oracle accepts batches from.
    bytes32 public registryId;

    /// @notice Maximum age, in seconds, a batch's `batchTimestamp` may have relative to
    /// `block.timestamp` at delivery before it is rejected as stale.
    uint256 public maxBatchAge;

    /// @notice If true, emit a `TrustScoreUpdated` event per entry in addition to the per-batch
    /// event. Off by default: most consumers only need current state via `getTrustScore`, and
    /// per-entry events are a meaningful share of a batch's gas cost.
    bool public emitDetailedEvents;

    /// @notice Last applied batch nonce for `registryId`. Batches must strictly increase this.
    uint64 public lastBatchNonce;

    /// @notice Default optimistic challenge window (24 hours) during which proposed updates
    /// are locked and can be contested by submitting a contradictory Stellar Merkle proof.
    uint256 public challengeWindow = 24 hours;

    /// @notice Minimum ETH bond required from a relayer proposing an optimistic score update.
    uint256 public minRelayerBond = 0.1 ether;

    /// @notice Minimum ETH bond required from a challenger contesting a pending optimistic update.
    uint256 public minChallengerBond = 0.05 ether;

    /// @notice Optional linked `PactumZeroTrustOracle` holding canonical Stellar ledger headers.
    PactumZeroTrustOracle public zeroTrustOracle;

    /// @notice Local fallback mapping of trusted Stellar ledger sequence -> block header hash.
    mapping(uint64 => bytes32) public trustedLedgerHeaders;

    /// @notice Auto-incrementing optimistic proposal identifier.
    uint256 public nextProposalId = 1;

    enum ProposalStatus {
        None,
        Pending,
        Finalized,
        Slashed
    }

    struct OptimisticProposal {
        uint256 proposalId;
        address relayer;
        uint256 relayerBond;
        uint64 proposedAt;
        uint64 challengeDeadline;
        ProposalStatus status;
        TrustScoreEntry entry;
    }

    mapping(uint256 => OptimisticProposal) private _proposals;
    mapping(bytes32 => uint256) public activeProposalByAddress;

    mapping(bytes32 => TrustScore) private _scores;

    error NotMessagingEndpoint(address caller);
    error UntrustedRemote(uint32 sourceChainId, bytes32 sourceAddress);
    error UnsupportedVersion(uint8 version);
    error UnknownRegistry(bytes32 registryId);
    error BatchTooLarge(uint256 size, uint256 max);
    error NonceNotIncreasing(uint64 batchNonce, uint64 lastBatchNonce);
    error BatchTooStale(uint64 batchTimestamp, uint256 nowTimestamp, uint256 maxBatchAge);
    error LedgerSeqNotIncreasing(bytes32 stellarAddress, uint64 sourceLedgerSeq, uint64 lastLedgerSeq);
    error InvalidChallengeWindow(uint256 window);
    error InsufficientRelayerBond(uint256 provided, uint256 required);
    error InsufficientChallengerBond(uint256 provided, uint256 required);
    error ActiveProposalExists(bytes32 stellarAddress, uint256 proposalId);
    error ProposalNotPending(uint256 proposalId);
    error ChallengePeriodActive(uint256 proposalId, uint64 challengeDeadline, uint256 nowTimestamp);
    error ChallengePeriodExpired(uint256 proposalId, uint64 challengeDeadline, uint256 nowTimestamp);
    error InvalidChallengeTarget(bytes32 expectedAddress, bytes32 actualAddress);
    error UntrustedCanonicalHeader(uint64 ledgerSeq, bytes32 headerHash);
    error InvalidCanonicalProof(uint256 proposalId);
    error NoContradictionProven(uint256 proposalId);
    error PayoutTransferFailed(address recipient, uint256 amount);

    event MessagingEndpointUpdated(address indexed endpoint);
    event TrustedRemoteUpdated(uint32 indexed sourceChainId, bytes32 sourceAddress);
    event RegistryIdUpdated(bytes32 indexed registryId);
    event MaxBatchAgeUpdated(uint256 maxBatchAge);
    event EmitDetailedEventsUpdated(bool enabled);
    event ChallengeWindowUpdated(uint256 challengeWindow);
    event MinBondsUpdated(uint256 minRelayerBond, uint256 minChallengerBond);
    event ZeroTrustOracleUpdated(address indexed zeroTrustOracle);
    event TrustedLedgerHeaderUpdated(uint64 indexed ledgerSeq, bytes32 headerHash);
    event OptimisticUpdateProposed(
        uint256 indexed proposalId,
        bytes32 indexed stellarAddress,
        address indexed relayer,
        int64 score,
        uint64 sourceLedgerSeq,
        uint64 challengeDeadline,
        uint256 relayerBond
    );
    event OptimisticUpdateFinalized(
        uint256 indexed proposalId,
        bytes32 indexed stellarAddress,
        address indexed relayer,
        int64 score,
        uint256 refundedBond
    );
    event OptimisticUpdateSlashed(
        uint256 indexed proposalId,
        bytes32 indexed stellarAddress,
        address indexed relayer,
        address challenger,
        uint256 totalReward,
        uint32 canonicalScore
    );

    struct TrustScoreEntry {
        bytes32 stellarAddress;
        int64 score;
        uint32 fulfilledCount;
        uint32 lateCount;
        uint32 breachedCount;
        uint64 sourceLedgerSeq;
    }

    struct TrustScoreBatch {
        uint8 version;
        bytes32 registryId;
        uint64 batchNonce;
        uint64 batchTimestamp;
        TrustScoreEntry[] entries;
    }

    constructor(
        address initialOwner,
        address initialMessagingEndpoint,
        bytes32 initialRegistryId,
        uint256 initialMaxBatchAge
    ) Ownable(initialOwner) {
        messagingEndpoint = initialMessagingEndpoint;
        registryId = initialRegistryId;
        maxBatchAge = initialMaxBatchAge;
        emit MessagingEndpointUpdated(initialMessagingEndpoint);
        emit RegistryIdUpdated(initialRegistryId);
        emit MaxBatchAgeUpdated(initialMaxBatchAge);
    }

    modifier onlyEndpoint() {
        if (msg.sender != messagingEndpoint) {
            revert NotMessagingEndpoint(msg.sender);
        }
        _;
    }

    // ---------------------------------------------------------------------
    // Owner configuration
    // ---------------------------------------------------------------------

    function setMessagingEndpoint(address endpoint) external onlyOwner {
        messagingEndpoint = endpoint;
        emit MessagingEndpointUpdated(endpoint);
    }

    function setTrustedRemote(uint32 sourceChainId, bytes32 sourceAddress) external onlyOwner {
        trustedRemotes[sourceChainId] = sourceAddress;
        emit TrustedRemoteUpdated(sourceChainId, sourceAddress);
    }

    function setRegistryId(bytes32 newRegistryId) external onlyOwner {
        registryId = newRegistryId;
        emit RegistryIdUpdated(newRegistryId);
    }

    function setMaxBatchAge(uint256 newMaxBatchAge) external onlyOwner {
        maxBatchAge = newMaxBatchAge;
        emit MaxBatchAgeUpdated(newMaxBatchAge);
    }

    function setEmitDetailedEvents(bool enabled) external onlyOwner {
        emitDetailedEvents = enabled;
        emit EmitDetailedEventsUpdated(enabled);
    }

    function setChallengeWindow(uint256 newChallengeWindow) external onlyOwner {
        if (newChallengeWindow == 0) {
            revert InvalidChallengeWindow(newChallengeWindow);
        }
        challengeWindow = newChallengeWindow;
        emit ChallengeWindowUpdated(newChallengeWindow);
    }

    function setMinBonds(uint256 newMinRelayerBond, uint256 newMinChallengerBond) external onlyOwner {
        minRelayerBond = newMinRelayerBond;
        minChallengerBond = newMinChallengerBond;
        emit MinBondsUpdated(newMinRelayerBond, newMinChallengerBond);
    }

    function setZeroTrustOracle(address oracleAddr) external onlyOwner {
        zeroTrustOracle = PactumZeroTrustOracle(oracleAddr);
        emit ZeroTrustOracleUpdated(oracleAddr);
    }

    function setTrustedLedgerHeader(uint64 ledgerSeq, bytes32 headerHash) external onlyOwner {
        trustedLedgerHeaders[ledgerSeq] = headerHash;
        emit TrustedLedgerHeaderUpdated(ledgerSeq, headerHash);
    }

    // ---------------------------------------------------------------------
    // Optimistic Fraud-Proof Challenge Layer (Issue #307)
    // ---------------------------------------------------------------------

    /// @notice Proposes an optimistic trust score update backed by an ETH relayer bond.
    /// The score remains locked in pending state until `challengeWindow` elapses.
    function proposeOptimisticUpdate(
        TrustScoreEntry calldata entry
    ) external payable returns (uint256 proposalId) {
        if (msg.value < minRelayerBond) {
            revert InsufficientRelayerBond(msg.value, minRelayerBond);
        }

        uint256 existingProposalId = activeProposalByAddress[entry.stellarAddress];
        if (existingProposalId != 0) {
            revert ActiveProposalExists(entry.stellarAddress, existingProposalId);
        }

        TrustScore storage existing = _scores[entry.stellarAddress];
        if (entry.sourceLedgerSeq <= existing.sourceLedgerSeq && existing.updatedAt != 0) {
            revert LedgerSeqNotIncreasing(
                entry.stellarAddress,
                entry.sourceLedgerSeq,
                existing.sourceLedgerSeq
            );
        }

        proposalId = nextProposalId++;
        uint64 deadline = uint64(block.timestamp + challengeWindow);

        _proposals[proposalId] = OptimisticProposal({
            proposalId: proposalId,
            relayer: msg.sender,
            relayerBond: msg.value,
            proposedAt: uint64(block.timestamp),
            challengeDeadline: deadline,
            status: ProposalStatus.Pending,
            entry: entry
        });
        activeProposalByAddress[entry.stellarAddress] = proposalId;

        emit OptimisticUpdateProposed(
            proposalId,
            entry.stellarAddress,
            msg.sender,
            entry.score,
            entry.sourceLedgerSeq,
            deadline,
            msg.value
        );
    }

    /// @notice Finalizes an unchallenged optimistic score update after its challenge window expires,
    /// applying the score to `_scores` and refunding the relayer's bond.
    function finalizeOptimisticUpdate(uint256 proposalId) external {
        OptimisticProposal storage prop = _proposals[proposalId];
        if (prop.status != ProposalStatus.Pending) {
            revert ProposalNotPending(proposalId);
        }
        if (block.timestamp < prop.challengeDeadline) {
            revert ChallengePeriodActive(proposalId, prop.challengeDeadline, block.timestamp);
        }

        TrustScoreEntry memory entry = prop.entry;
        address relayer = prop.relayer;
        uint256 bond = prop.relayerBond;

        prop.status = ProposalStatus.Finalized;
        prop.relayerBond = 0;
        delete activeProposalByAddress[entry.stellarAddress];

        TrustScore storage existing = _scores[entry.stellarAddress];
        if (entry.sourceLedgerSeq <= existing.sourceLedgerSeq && existing.updatedAt != 0) {
            revert LedgerSeqNotIncreasing(
                entry.stellarAddress,
                entry.sourceLedgerSeq,
                existing.sourceLedgerSeq
            );
        }

        existing.score = entry.score;
        existing.fulfilledCount = entry.fulfilledCount;
        existing.lateCount = entry.lateCount;
        existing.breachedCount = entry.breachedCount;
        existing.sourceLedgerSeq = entry.sourceLedgerSeq;
        existing.updatedAt = uint64(block.timestamp);

        if (emitDetailedEvents) {
            emit TrustScoreUpdated(entry.stellarAddress, entry.score, entry.sourceLedgerSeq);
        }

        (bool ok, ) = payable(relayer).call{value: bond}("");
        if (!ok) {
            revert PayoutTransferFailed(relayer, bond);
        }

        emit OptimisticUpdateFinalized(
            proposalId,
            entry.stellarAddress,
            relayer,
            entry.score,
            bond
        );
    }

    /// @notice Challenges a pending optimistic update using a canonical Stellar Merkle state proof.
    /// If the proof is cryptographically valid against a trusted Stellar ledger header and contradicts
    /// the optimistic proposal, the pending update is cancelled and the relayer's bond is slashed
    /// and paid out to the challenger along with the challenger's bond.
    function challengeOptimisticUpdate(
        uint256 proposalId,
        PactumStateProofVerifier.StateProof calldata canonicalProof
    ) external payable {
        OptimisticProposal storage prop = _proposals[proposalId];
        if (prop.status != ProposalStatus.Pending) {
            revert ProposalNotPending(proposalId);
        }
        if (block.timestamp >= prop.challengeDeadline) {
            revert ChallengePeriodExpired(proposalId, prop.challengeDeadline, block.timestamp);
        }
        if (msg.value < minChallengerBond) {
            revert InsufficientChallengerBond(msg.value, minChallengerBond);
        }

        TrustScoreEntry memory proposed = prop.entry;
        if (canonicalProof.stellarAddress != proposed.stellarAddress) {
            revert InvalidChallengeTarget(proposed.stellarAddress, canonicalProof.stellarAddress);
        }
        if (canonicalProof.contractId != registryId) {
            revert UnknownRegistry(canonicalProof.contractId);
        }
        if (canonicalProof.scoreData.sourceLedgerSeq < proposed.sourceLedgerSeq) {
            revert LedgerSeqNotIncreasing(
                proposed.stellarAddress,
                canonicalProof.scoreData.sourceLedgerSeq,
                proposed.sourceLedgerSeq
            );
        }

        uint32 canonicalScore;
        if (address(zeroTrustOracle) != address(0)) {
            (canonicalScore, ) = zeroTrustOracle.verifyCanonicalProof(canonicalProof);
        } else {
            bytes32 trustedHeader = trustedLedgerHeaders[canonicalProof.ledgerSeq];
            if (trustedHeader == bytes32(0) || trustedHeader != canonicalProof.ledgerHeaderHash) {
                revert UntrustedCanonicalHeader(
                    canonicalProof.ledgerSeq,
                    canonicalProof.ledgerHeaderHash
                );
            }
            bool isValid;
            (isValid, canonicalScore) = PactumStateProofVerifier.verifyProof(
                canonicalProof,
                trustedHeader
            );
            if (!isValid) {
                revert InvalidCanonicalProof(proposalId);
            }
        }

        bool contradicts = (int64(uint64(canonicalScore)) != proposed.score) ||
            (canonicalProof.scoreData.fulfilledCount != proposed.fulfilledCount) ||
            (canonicalProof.scoreData.lateCount != proposed.lateCount) ||
            (canonicalProof.scoreData.breachedCount != proposed.breachedCount);

        if (!contradicts) {
            revert NoContradictionProven(proposalId);
        }

        address slashedRelayer = prop.relayer;
        uint256 totalReward = prop.relayerBond + msg.value;

        prop.status = ProposalStatus.Slashed;
        prop.relayerBond = 0;
        delete activeProposalByAddress[proposed.stellarAddress];

        (bool ok, ) = payable(msg.sender).call{value: totalReward}("");
        if (!ok) {
            revert PayoutTransferFailed(msg.sender, totalReward);
        }

        emit OptimisticUpdateSlashed(
            proposalId,
            proposed.stellarAddress,
            slashedRelayer,
            msg.sender,
            totalReward,
            canonicalScore
        );
    }

    /// @notice Returns the stored optimistic proposal for `proposalId`.
    function getOptimisticProposal(
        uint256 proposalId
    ) external view returns (OptimisticProposal memory) {
        return _proposals[proposalId];
    }

    // ---------------------------------------------------------------------
    // IPactumMessageReceiver
    // ---------------------------------------------------------------------

    /// @inheritdoc IPactumMessageReceiver
    /// @dev Layer 1 (transport authenticity): restricted to `messagingEndpoint` and a registered
    /// (sourceChainId, sourceAddress) pair. Layer 2 (application-level integrity): every check in
    /// `_applyBatch`. See docs/cross-chain-trust-bridge.md §5.
    function receiveMessage(
        uint32 sourceChainId,
        bytes calldata sourceAddress,
        bytes calldata payload
    ) external onlyEndpoint {
        bytes32 remote = trustedRemotes[sourceChainId];
        if (remote == bytes32(0) || bytes32(sourceAddress) != remote) {
            revert UntrustedRemote(sourceChainId, bytes32(sourceAddress));
        }

        TrustScoreBatch memory batch = abi.decode(payload, (TrustScoreBatch));
        _applyBatch(batch);
    }

    // ---------------------------------------------------------------------
    // IPactumTrustOracle
    // ---------------------------------------------------------------------

    /// @inheritdoc IPactumTrustOracle
    function getTrustScore(bytes32 stellarAddress) external view returns (TrustScore memory) {
        return _scores[stellarAddress];
    }

    /// @inheritdoc IPactumTrustOracle
    function isStale(bytes32 stellarAddress, uint256 maxAge) external view returns (bool) {
        uint64 updatedAt = _scores[stellarAddress].updatedAt;
        if (updatedAt == 0) {
            return true;
        }
        return block.timestamp - uint256(updatedAt) > maxAge;
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    function _applyBatch(TrustScoreBatch memory batch) internal {
        if (batch.version != SCHEMA_VERSION) {
            revert UnsupportedVersion(batch.version);
        }
        if (batch.registryId != registryId) {
            revert UnknownRegistry(batch.registryId);
        }
        if (batch.entries.length > MAX_BATCH_SIZE) {
            revert BatchTooLarge(batch.entries.length, MAX_BATCH_SIZE);
        }
        if (batch.batchNonce <= lastBatchNonce) {
            revert NonceNotIncreasing(batch.batchNonce, lastBatchNonce);
        }
        if (block.timestamp > uint256(batch.batchTimestamp) + maxBatchAge) {
            revert BatchTooStale(batch.batchTimestamp, block.timestamp, maxBatchAge);
        }

        lastBatchNonce = batch.batchNonce;

        uint256 length = batch.entries.length;
        for (uint256 i = 0; i < length; i++) {
            TrustScoreEntry memory entry = batch.entries[i];
            TrustScore storage existing = _scores[entry.stellarAddress];

            if (entry.sourceLedgerSeq <= existing.sourceLedgerSeq && existing.updatedAt != 0) {
                revert LedgerSeqNotIncreasing(
                    entry.stellarAddress,
                    entry.sourceLedgerSeq,
                    existing.sourceLedgerSeq
                );
            }

            existing.score = entry.score;
            existing.fulfilledCount = entry.fulfilledCount;
            existing.lateCount = entry.lateCount;
            existing.breachedCount = entry.breachedCount;
            existing.sourceLedgerSeq = entry.sourceLedgerSeq;
            existing.updatedAt = uint64(block.timestamp);

            if (emitDetailedEvents) {
                emit TrustScoreUpdated(entry.stellarAddress, entry.score, entry.sourceLedgerSeq);
            }
        }

        emit TrustScoreBatchUpdated(batch.registryId, batch.batchNonce, length);
    }
}
