//! BFT consensus protocol implementation (Chained `HotStuff`).
//!
//! This module implements the core types and state machine for Chained
//! `HotStuff` BFT consensus. It is designed for small validator sets (4-7
//! nodes) with infrequent control-plane state changes.
//!
//! # Protocol Overview
//!
//! Chained `HotStuff` achieves BFT consensus with `O(n)` message complexity per
//! view by pipelining the prepare, pre-commit, and commit phases into single
//! voting rounds. A block is committed when it becomes the head of a 3-chain
//! of certified blocks.
//!
//! # Security Properties
//!
//! - **Safety**: No two honest validators commit different blocks at the same
//!   height (`HotStuff` Theorem 2)
//! - **Liveness**: After GST, decisions are reached in `O(n)` messages
//!   (`HotStuff` Theorem 3)
//!
//! # References
//!
//! - Yin et al. "`HotStuff`: BFT Consensus with Linearity and Responsiveness."
//!   PODC 2019.
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00186: BFT Library Evaluation Spike
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::consensus::bft::{HotStuffConfig, HotStuffState, Proposal};
//!
//! // Initialize consensus state
//! let config = HotStuffConfig::builder()
//!     .validator_id(my_validator_id)
//!     .validators(validator_set)
//!     .quorum_threshold(3) // 2f+1 for f=1
//!     .build()?;
//!
//! let mut state = HotStuffState::new(config);
//!
//! // Process incoming proposal
//! match state.on_proposal(proposal)? {
//!     Some(vote) => send_vote(vote),
//!     None => {} // Already voted or invalid
//! }
//! ```

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of validators in a consensus group.
///
/// Bounded to prevent denial-of-service via large validator sets. 16 validators
/// supports `f=5` Byzantine faults which is sufficient for most deployments.
pub const MAX_VALIDATORS: usize = 16;

/// Maximum number of signatures in a quorum certificate.
///
/// Must be at least `2f+1` where `f = (MAX_VALIDATORS - 1) / 3`.
pub const MAX_QC_SIGNATURES: usize = 16;

/// Maximum payload size in bytes.
///
/// Control-plane events are small; 64KB is generous.
pub const MAX_PAYLOAD_SIZE: usize = 65536;

/// Default round timeout duration.
pub const DEFAULT_ROUND_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum round timeout duration.
pub const MIN_ROUND_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum round timeout duration.
pub const MAX_ROUND_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout multiplier for exponential backoff on view change.
pub const TIMEOUT_MULTIPLIER: f64 = 1.5;

// ============================================================================
// Types
// ============================================================================

/// Validator identifier (BLAKE3 hash of `Ed25519` public key).
pub type ValidatorId = [u8; 32];

/// Block hash (BLAKE3).
pub type BlockHash = [u8; 32];

/// Signature bytes (`Ed25519`).
pub type SignatureBytes = [u8; 64];

// ============================================================================
// Serde Helpers
// ============================================================================

/// Serde helper for 64-byte arrays (signatures).
mod serde_signature {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur in BFT consensus operations.
#[derive(Debug, Error)]
pub enum BftError {
    /// Invalid signature.
    #[error("invalid signature from validator {validator_id}")]
    InvalidSignature {
        /// The validator whose signature was invalid.
        validator_id: String,
    },

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// Unknown validator.
    #[error("unknown validator: {0}")]
    UnknownValidator(String),

    /// Invalid proposal.
    #[error("invalid proposal: {0}")]
    InvalidProposal(String),

    /// Invalid vote.
    #[error("invalid vote: {0}")]
    InvalidVote(String),

    /// Invalid quorum certificate.
    #[error("invalid quorum certificate: {0}")]
    InvalidQc(String),

    /// Insufficient quorum.
    #[error("insufficient quorum: {have} of {need} required")]
    InsufficientQuorum {
        /// Number of valid signatures.
        have: usize,
        /// Number required.
        need: usize,
    },

    /// Duplicate vote.
    #[error("duplicate vote from validator {0} in round {1}")]
    DuplicateVote(String, u64),

    /// Stale message (old epoch or round).
    #[error(
        "stale message: epoch {msg_epoch}/{msg_round} < current {current_epoch}/{current_round}"
    )]
    StaleMessage {
        /// Message epoch.
        msg_epoch: u64,
        /// Message round.
        msg_round: u64,
        /// Current epoch.
        current_epoch: u64,
        /// Current round.
        current_round: u64,
    },

    /// Future message (ahead of current view).
    #[error(
        "future message: epoch {msg_epoch}/{msg_round} > current {current_epoch}/{current_round}"
    )]
    FutureMessage {
        /// Message epoch.
        msg_epoch: u64,
        /// Message round.
        msg_round: u64,
        /// Current epoch.
        current_epoch: u64,
        /// Current round.
        current_round: u64,
    },

    /// Not the leader.
    #[error("not the leader for round {round}: expected {expected}, got {actual}")]
    NotLeader {
        /// Current round.
        round: u64,
        /// Expected leader.
        expected: String,
        /// Actual proposer.
        actual: String,
    },

    /// Already voted in this round.
    #[error("already voted in round {0}")]
    AlreadyVoted(u64),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

// ============================================================================
// Message Types (EVID-0007)
// ============================================================================

/// A validator's signature in a quorum certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// The validator who signed.
    pub validator_id: ValidatorId,
    /// The `Ed25519` signature bytes.
    #[serde(with = "serde_signature")]
    pub signature: SignatureBytes,
}

impl ValidatorSignature {
    /// Creates a new validator signature.
    #[must_use]
    pub const fn new(validator_id: ValidatorId, signature: SignatureBytes) -> Self {
        Self {
            validator_id,
            signature,
        }
    }
}

/// A consensus proposal from the leader.
///
/// The leader proposes a new block containing a batch of control-plane events.
/// The proposal includes a quorum certificate for the parent block, proving
/// the chain is valid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Current epoch (incremented on reconfiguration).
    pub epoch: u64,
    /// Round number within the epoch.
    pub round: u64,
    /// Proposer's validator ID.
    pub proposer_id: ValidatorId,
    /// BLAKE3 hash of the proposed block.
    pub block_hash: BlockHash,
    /// Quorum certificate for the parent block.
    pub parent_qc: QuorumCertificate,
    /// BLAKE3 hash of the payload (event batch).
    pub payload_hash: BlockHash,
    /// `Ed25519` signature over the canonical proposal message.
    #[serde(with = "serde_signature")]
    pub signature: SignatureBytes,
}

impl Proposal {
    /// Returns the message bytes to be signed.
    ///
    /// Format: `"PROPOSAL" || epoch || round || block_hash || payload_hash`
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(8 + 8 + 8 + 32 + 32);
        msg.extend_from_slice(b"PROPOSAL");
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        msg.extend_from_slice(&self.round.to_le_bytes());
        msg.extend_from_slice(&self.block_hash);
        msg.extend_from_slice(&self.payload_hash);
        msg
    }

    /// Validates the proposal structure (not cryptographic validity).
    ///
    /// # Errors
    ///
    /// Returns an error if the proposal is malformed.
    pub fn validate_structure(&self) -> Result<(), BftError> {
        // Parent QC round must be less than proposal round
        if self.parent_qc.round >= self.round {
            return Err(BftError::InvalidProposal(format!(
                "parent QC round {} >= proposal round {}",
                self.parent_qc.round, self.round
            )));
        }
        // Parent QC epoch must not exceed proposal epoch
        if self.parent_qc.epoch > self.epoch {
            return Err(BftError::InvalidProposal(format!(
                "parent QC epoch {} > proposal epoch {}",
                self.parent_qc.epoch, self.epoch
            )));
        }
        Ok(())
    }
}

/// A vote for a proposal.
///
/// Validators broadcast votes after validating a proposal. When `2f+1` votes
/// are collected, a quorum certificate is formed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// Current epoch.
    pub epoch: u64,
    /// Round being voted on.
    pub round: u64,
    /// Voter's validator ID.
    pub voter_id: ValidatorId,
    /// Hash of the block being voted for.
    pub block_hash: BlockHash,
    /// `Ed25519` signature over the canonical vote message.
    #[serde(with = "serde_signature")]
    pub signature: SignatureBytes,
}

impl Vote {
    /// Returns the message bytes to be signed.
    ///
    /// Format: `"VOTE" || epoch || round || block_hash`
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(4 + 8 + 8 + 32);
        msg.extend_from_slice(b"VOTE");
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        msg.extend_from_slice(&self.round.to_le_bytes());
        msg.extend_from_slice(&self.block_hash);
        msg
    }
}

/// A quorum certificate proving `2f+1` validators voted for a block.
///
/// The QC is the core building block of `HotStuff`. A chain of QCs proves
/// consensus progress. When a block has 3 consecutive QCs (3-chain), it
/// is committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// Epoch of the certified block.
    pub epoch: u64,
    /// Round of the certified block.
    pub round: u64,
    /// Hash of the certified block.
    pub block_hash: BlockHash,
    /// Aggregated signatures from `2f+1` validators.
    pub signatures: Vec<ValidatorSignature>,
}

impl QuorumCertificate {
    /// Creates a genesis QC (round 0, empty signatures).
    ///
    /// The genesis QC bootstraps the protocol by providing a valid parent
    /// for the first proposal.
    #[must_use]
    pub const fn genesis(epoch: u64, genesis_hash: BlockHash) -> Self {
        Self {
            epoch,
            round: 0,
            block_hash: genesis_hash,
            signatures: Vec::new(),
        }
    }

    /// Returns true if this is a genesis QC.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.round == 0 && self.signatures.is_empty()
    }

    /// Returns the number of signatures.
    #[must_use]
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Validates that the QC has sufficient signatures.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature count is below the quorum threshold.
    pub fn validate_quorum(&self, quorum_threshold: usize) -> Result<(), BftError> {
        if self.is_genesis() {
            return Ok(());
        }
        if self.signatures.len() < quorum_threshold {
            return Err(BftError::InsufficientQuorum {
                have: self.signatures.len(),
                need: quorum_threshold,
            });
        }
        if self.signatures.len() > MAX_QC_SIGNATURES {
            return Err(BftError::InvalidQc(format!(
                "too many signatures: {} > {}",
                self.signatures.len(),
                MAX_QC_SIGNATURES
            )));
        }
        Ok(())
    }
}

impl Default for QuorumCertificate {
    fn default() -> Self {
        Self::genesis(0, [0u8; 32])
    }
}

/// A new-view message for view change.
///
/// When a round times out, validators send their highest QC to the new leader.
/// The new leader aggregates these and starts the new round with the highest
/// QC as the parent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewView {
    /// New epoch (if reconfiguration) or current epoch.
    pub epoch: u64,
    /// New round number.
    pub round: u64,
    /// Sender's validator ID.
    pub sender_id: ValidatorId,
    /// Highest QC known to the sender.
    pub high_qc: QuorumCertificate,
    /// `Ed25519` signature over the canonical new-view message.
    #[serde(with = "serde_signature")]
    pub signature: SignatureBytes,
}

impl NewView {
    /// Returns the message bytes to be signed.
    ///
    /// Format: `"NEWVIEW" || epoch || round || high_qc.block_hash`
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(7 + 8 + 8 + 32);
        msg.extend_from_slice(b"NEWVIEW");
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        msg.extend_from_slice(&self.round.to_le_bytes());
        msg.extend_from_slice(&self.high_qc.block_hash);
        msg
    }
}

// ============================================================================
// State Machine (EVID-0007)
// ============================================================================

/// The current phase of the consensus state machine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Waiting for a proposal from the leader.
    #[default]
    Idle,
    /// Received a proposal, collecting votes.
    Voting,
    /// Formed a QC, waiting for next round or commit.
    Certified,
    /// Block committed to ledger.
    Committed,
    /// View change in progress.
    ViewChange,
}

/// Information about a validator in the consensus group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator ID (BLAKE3 hash of public key).
    pub id: ValidatorId,
    /// Index in the validator set (for leader rotation).
    pub index: usize,
    /// `Ed25519` public key bytes.
    pub public_key: [u8; 32],
}

/// Configuration for the `HotStuff` consensus.
#[derive(Clone, Debug)]
pub struct HotStuffConfig {
    /// This node's validator ID.
    pub validator_id: ValidatorId,
    /// This node's validator index.
    pub validator_index: usize,
    /// All validators in the consensus group.
    pub validators: Vec<ValidatorInfo>,
    /// Quorum threshold (`2f+1`).
    pub quorum_threshold: usize,
    /// Round timeout duration.
    pub round_timeout: Duration,
}

impl HotStuffConfig {
    /// Creates a new configuration builder.
    #[must_use]
    pub const fn builder() -> HotStuffConfigBuilder {
        HotStuffConfigBuilder::new()
    }

    /// Returns the number of validators.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Returns the leader for a given round (round-robin).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn leader_for_round(&self, round: u64) -> &ValidatorInfo {
        let index = (round as usize) % self.validators.len();
        &self.validators[index]
    }

    /// Returns true if this node is the leader for the given round.
    #[must_use]
    pub fn is_leader(&self, round: u64) -> bool {
        self.leader_for_round(round).id == self.validator_id
    }

    /// Looks up a validator by ID.
    #[must_use]
    pub fn get_validator(&self, id: &ValidatorId) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| &v.id == id)
    }
}

/// Builder for `HotStuffConfig`.
#[derive(Default)]
pub struct HotStuffConfigBuilder {
    validator_id: Option<ValidatorId>,
    validators: Vec<ValidatorInfo>,
    quorum_threshold: Option<usize>,
    round_timeout: Duration,
}

impl HotStuffConfigBuilder {
    /// Creates a new builder with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            validator_id: None,
            validators: Vec::new(),
            quorum_threshold: None,
            round_timeout: DEFAULT_ROUND_TIMEOUT,
        }
    }

    /// Sets this node's validator ID.
    #[must_use]
    pub const fn validator_id(mut self, id: ValidatorId) -> Self {
        self.validator_id = Some(id);
        self
    }

    /// Adds a validator to the consensus group.
    ///
    /// # Errors
    ///
    /// Returns an error if maximum validators exceeded.
    pub fn add_validator(mut self, info: ValidatorInfo) -> Result<Self, BftError> {
        if self.validators.len() >= MAX_VALIDATORS {
            return Err(BftError::Configuration(format!(
                "maximum validators {MAX_VALIDATORS} exceeded",
            )));
        }
        self.validators.push(info);
        Ok(self)
    }

    /// Sets the quorum threshold (`2f+1`).
    #[must_use]
    pub const fn quorum_threshold(mut self, threshold: usize) -> Self {
        self.quorum_threshold = Some(threshold);
        self
    }

    /// Sets the round timeout duration.
    ///
    /// # Errors
    ///
    /// Returns an error if timeout is out of bounds.
    pub fn round_timeout(mut self, timeout: Duration) -> Result<Self, BftError> {
        if timeout < MIN_ROUND_TIMEOUT {
            return Err(BftError::Configuration(format!(
                "round timeout {timeout:?} < minimum {MIN_ROUND_TIMEOUT:?}",
            )));
        }
        if timeout > MAX_ROUND_TIMEOUT {
            return Err(BftError::Configuration(format!(
                "round timeout {timeout:?} > maximum {MAX_ROUND_TIMEOUT:?}",
            )));
        }
        self.round_timeout = timeout;
        Ok(self)
    }

    /// Builds the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or invalid.
    pub fn build(self) -> Result<HotStuffConfig, BftError> {
        let validator_id = self
            .validator_id
            .ok_or_else(|| BftError::Configuration("validator_id required".into()))?;

        if self.validators.is_empty() {
            return Err(BftError::Configuration("no validators specified".into()));
        }

        // Find this node's index
        let validator_index = self
            .validators
            .iter()
            .position(|v| v.id == validator_id)
            .ok_or_else(|| BftError::Configuration("validator_id not in validator set".into()))?;

        // Default quorum threshold: 2f+1 where n = 3f+1 validators
        let n = self.validators.len();
        let f = (n - 1) / 3;
        let default_threshold = 2 * f + 1;
        let quorum_threshold = self.quorum_threshold.unwrap_or(default_threshold);

        if quorum_threshold > n {
            return Err(BftError::Configuration(format!(
                "quorum threshold {quorum_threshold} > validator count {n}",
            )));
        }

        Ok(HotStuffConfig {
            validator_id,
            validator_index,
            validators: self.validators,
            quorum_threshold,
            round_timeout: self.round_timeout,
        })
    }
}

/// The consensus state machine.
///
/// Tracks the current view (epoch, round), votes collected, and committed
/// blocks. The state machine processes incoming messages and produces
/// outgoing messages.
#[derive(Clone, Debug)]
pub struct HotStuffState {
    /// Configuration.
    config: HotStuffConfig,
    /// Current epoch.
    epoch: u64,
    /// Current round.
    round: u64,
    /// Current phase.
    phase: Phase,
    /// Last round we voted in (prevents double voting).
    last_voted_round: u64,
    /// Highest QC seen.
    high_qc: QuorumCertificate,
    /// Votes collected for current round (`validator_id` -> vote).
    votes: HashMap<ValidatorId, Vote>,
    /// Pending blocks (`block_hash` -> (round, `parent_hash`)).
    pending_blocks: HashMap<BlockHash, (u64, BlockHash)>,
    /// Committed block hashes in order.
    committed: Vec<BlockHash>,
}

impl HotStuffState {
    /// Creates a new consensus state.
    #[must_use]
    pub fn new(config: HotStuffConfig) -> Self {
        Self {
            config,
            epoch: 0,
            round: 1,
            phase: Phase::Idle,
            last_voted_round: 0,
            high_qc: QuorumCertificate::default(),
            votes: HashMap::new(),
            pending_blocks: HashMap::new(),
            committed: Vec::new(),
        }
    }

    /// Returns the current epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the current round.
    #[must_use]
    pub const fn round(&self) -> u64 {
        self.round
    }

    /// Returns the current phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Returns the highest QC seen.
    #[must_use]
    pub const fn high_qc(&self) -> &QuorumCertificate {
        &self.high_qc
    }

    /// Returns true if this node is the current leader.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.config.is_leader(self.round)
    }

    /// Returns the current leader's info.
    #[must_use]
    pub fn current_leader(&self) -> &ValidatorInfo {
        self.config.leader_for_round(self.round)
    }

    /// Returns the number of committed blocks.
    #[must_use]
    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }

    /// Processes an incoming proposal.
    ///
    /// If the proposal is valid and we haven't voted yet, returns a vote
    /// to broadcast.
    ///
    /// # Errors
    ///
    /// Returns an error if the proposal is invalid.
    pub fn on_proposal(&mut self, proposal: &Proposal) -> Result<Option<Vote>, BftError> {
        // Validate epoch and round
        if proposal.epoch < self.epoch
            || (proposal.epoch == self.epoch && proposal.round < self.round)
        {
            return Err(BftError::StaleMessage {
                msg_epoch: proposal.epoch,
                msg_round: proposal.round,
                current_epoch: self.epoch,
                current_round: self.round,
            });
        }

        // Validate proposer is leader
        let expected_leader = self.config.leader_for_round(proposal.round);
        if proposal.proposer_id != expected_leader.id {
            return Err(BftError::NotLeader {
                round: proposal.round,
                expected: hex::encode(expected_leader.id),
                actual: hex::encode(proposal.proposer_id),
            });
        }

        // Validate structure
        proposal.validate_structure()?;

        // Check if we already voted
        if proposal.round <= self.last_voted_round {
            return Err(BftError::AlreadyVoted(proposal.round));
        }

        // TODO: Verify signature (requires ed25519-dalek integration)

        // Update state
        self.round = proposal.round;
        self.phase = Phase::Voting;

        // Track pending block
        self.pending_blocks.insert(
            proposal.block_hash,
            (proposal.round, proposal.parent_qc.block_hash),
        );

        // Update high_qc if proposal's parent_qc is higher
        if proposal.parent_qc.round > self.high_qc.round {
            self.high_qc = proposal.parent_qc.clone();
        }

        // Create vote
        self.last_voted_round = proposal.round;
        let vote = Vote {
            epoch: proposal.epoch,
            round: proposal.round,
            voter_id: self.config.validator_id,
            block_hash: proposal.block_hash,
            signature: [0u8; 64], // TODO: Sign with private key
        };

        Ok(Some(vote))
    }

    /// Processes an incoming vote.
    ///
    /// Collects votes and returns a QC when quorum is reached.
    ///
    /// # Errors
    ///
    /// Returns an error if the vote is invalid.
    pub fn on_vote(&mut self, vote: &Vote) -> Result<Option<QuorumCertificate>, BftError> {
        // Validate epoch and round
        if vote.epoch != self.epoch || vote.round != self.round {
            return Err(BftError::StaleMessage {
                msg_epoch: vote.epoch,
                msg_round: vote.round,
                current_epoch: self.epoch,
                current_round: self.round,
            });
        }

        // Validate voter is in validator set
        if self.config.get_validator(&vote.voter_id).is_none() {
            return Err(BftError::UnknownValidator(hex::encode(vote.voter_id)));
        }

        // Check for duplicate vote
        if self.votes.contains_key(&vote.voter_id) {
            return Err(BftError::DuplicateVote(
                hex::encode(vote.voter_id),
                vote.round,
            ));
        }

        // TODO: Verify signature

        // Collect vote
        self.votes.insert(vote.voter_id, vote.clone());

        // Check for quorum
        if self.votes.len() >= self.config.quorum_threshold {
            let signatures: Vec<ValidatorSignature> = self
                .votes
                .values()
                .map(|v| ValidatorSignature::new(v.voter_id, v.signature))
                .collect();

            let qc = QuorumCertificate {
                epoch: vote.epoch,
                round: vote.round,
                block_hash: vote.block_hash,
                signatures,
            };

            // Update state
            self.phase = Phase::Certified;
            if qc.round > self.high_qc.round {
                self.high_qc = qc.clone();
            }

            // Check 3-chain commit rule
            self.try_commit();

            return Ok(Some(qc));
        }

        Ok(None)
    }

    /// Processes a timeout event.
    ///
    /// Returns a `NewView` message to broadcast.
    #[must_use]
    pub fn on_timeout(&mut self) -> NewView {
        self.phase = Phase::ViewChange;

        NewView {
            epoch: self.epoch,
            round: self.round + 1,
            sender_id: self.config.validator_id,
            high_qc: self.high_qc.clone(),
            signature: [0u8; 64], // TODO: Sign
        }
    }

    /// Processes a `NewView` message.
    ///
    /// For leaders: collect new-views and start new round.
    /// For replicas: adopt the new view.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is invalid.
    pub fn on_new_view(&mut self, new_view: &NewView) -> Result<(), BftError> {
        // Validate round is advancement
        if new_view.round <= self.round {
            return Ok(()); // Ignore stale new-view
        }

        // Update high_qc if theirs is higher
        if new_view.high_qc.round > self.high_qc.round {
            self.high_qc = new_view.high_qc.clone();
        }

        // Advance to new round
        self.round = new_view.round;
        self.phase = Phase::Idle;
        self.votes.clear();

        Ok(())
    }

    /// Attempts to commit blocks using the 3-chain rule.
    ///
    /// A block B is committed when there exists a 3-chain:
    /// B <- B' <- B'' where B', B'' have consecutive rounds.
    #[allow(clippy::missing_const_for_fn)]
    fn try_commit(&mut self) {
        // Simplified 3-chain check
        // In full implementation, we'd walk the chain from high_qc
        // and commit the block 2 rounds back if it forms a 3-chain.

        // For now, just mark phase as committed if we're past round 3
        if self.high_qc.round >= 3 {
            self.phase = Phase::Committed;
            // TODO: Identify and record the committed block
        }
    }

    /// Advances to the next round (called after QC is formed and broadcast).
    pub fn advance_round(&mut self) {
        self.round += 1;
        self.phase = Phase::Idle;
        self.votes.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::cast_possible_truncation)]
    fn test_validator(index: usize) -> ValidatorInfo {
        let mut id = [0u8; 32];
        id[0] = index as u8;
        let mut pk = [0u8; 32];
        pk[0] = index as u8;
        ValidatorInfo {
            id,
            index,
            public_key: pk,
        }
    }

    fn test_config(validator_index: usize) -> HotStuffConfig {
        let validators: Vec<ValidatorInfo> = (0..4).map(test_validator).collect();
        let validator_id = validators[validator_index].id;

        HotStuffConfig::builder()
            .validator_id(validator_id)
            .add_validator(validators[0].clone())
            .unwrap()
            .add_validator(validators[1].clone())
            .unwrap()
            .add_validator(validators[2].clone())
            .unwrap()
            .add_validator(validators[3].clone())
            .unwrap()
            .quorum_threshold(3) // 2f+1 for f=1
            .build()
            .unwrap()
    }

    #[test]
    fn test_genesis_qc() {
        let qc = QuorumCertificate::genesis(0, [1u8; 32]);
        assert!(qc.is_genesis());
        assert_eq!(qc.round, 0);
        assert!(qc.signatures.is_empty());
    }

    #[test]
    fn test_qc_validate_quorum() {
        let mut qc = QuorumCertificate {
            epoch: 0,
            round: 1,
            block_hash: [1u8; 32],
            signatures: vec![
                ValidatorSignature::new([1u8; 32], [0u8; 64]),
                ValidatorSignature::new([2u8; 32], [0u8; 64]),
                ValidatorSignature::new([3u8; 32], [0u8; 64]),
            ],
        };

        // Should pass with threshold 3
        assert!(qc.validate_quorum(3).is_ok());

        // Should fail with threshold 4
        let err = qc.validate_quorum(4).unwrap_err();
        assert!(matches!(
            err,
            BftError::InsufficientQuorum { have: 3, need: 4 }
        ));

        // Genesis should always pass
        let genesis_qc = QuorumCertificate::genesis(0, [0u8; 32]);
        assert!(genesis_qc.validate_quorum(100).is_ok());

        // Too many signatures should fail
        qc.signatures = (0..20)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i;
                ValidatorSignature::new(id, [0u8; 64])
            })
            .collect();
        let err = qc.validate_quorum(3).unwrap_err();
        assert!(matches!(err, BftError::InvalidQc(_)));
    }

    #[test]
    fn test_config_builder() {
        let config = test_config(0);
        assert_eq!(config.validator_count(), 4);
        assert_eq!(config.quorum_threshold, 3);
        assert_eq!(config.validator_index, 0);
    }

    #[test]
    fn test_leader_rotation() {
        let config = test_config(0);

        // Round-robin leader selection
        assert_eq!(config.leader_for_round(0).index, 0);
        assert_eq!(config.leader_for_round(1).index, 1);
        assert_eq!(config.leader_for_round(2).index, 2);
        assert_eq!(config.leader_for_round(3).index, 3);
        assert_eq!(config.leader_for_round(4).index, 0); // Wraps around
    }

    #[test]
    fn test_state_initialization() {
        let config = test_config(0);
        let state = HotStuffState::new(config);

        assert_eq!(state.epoch(), 0);
        assert_eq!(state.round(), 1);
        assert_eq!(state.phase(), Phase::Idle);
        assert_eq!(state.committed_count(), 0);
    }

    #[test]
    fn test_proposal_structure_validation() {
        let parent_qc = QuorumCertificate::genesis(0, [0u8; 32]);

        let valid_proposal = Proposal {
            epoch: 0,
            round: 1,
            proposer_id: [0u8; 32],
            block_hash: [1u8; 32],
            parent_qc,
            payload_hash: [2u8; 32],
            signature: [0u8; 64],
        };

        assert!(valid_proposal.validate_structure().is_ok());

        // Parent QC round >= proposal round should fail
        let invalid_proposal = Proposal {
            epoch: 0,
            round: 1,
            proposer_id: [0u8; 32],
            block_hash: [1u8; 32],
            parent_qc: QuorumCertificate {
                epoch: 0,
                round: 1,
                block_hash: [0u8; 32],
                signatures: vec![],
            },
            payload_hash: [2u8; 32],
            signature: [0u8; 64],
        };

        assert!(invalid_proposal.validate_structure().is_err());
    }

    #[test]
    fn test_signing_message_formats() {
        let proposal = Proposal {
            epoch: 1,
            round: 5,
            proposer_id: [0u8; 32],
            block_hash: [1u8; 32],
            parent_qc: QuorumCertificate::default(),
            payload_hash: [2u8; 32],
            signature: [0u8; 64],
        };

        let msg = proposal.signing_message();
        assert!(msg.starts_with(b"PROPOSAL"));

        let vote = Vote {
            epoch: 1,
            round: 5,
            voter_id: [0u8; 32],
            block_hash: [1u8; 32],
            signature: [0u8; 64],
        };

        let msg = vote.signing_message();
        assert!(msg.starts_with(b"VOTE"));

        let new_view = NewView {
            epoch: 1,
            round: 6,
            sender_id: [0u8; 32],
            high_qc: QuorumCertificate::default(),
            signature: [0u8; 64],
        };

        let msg = new_view.signing_message();
        assert!(msg.starts_with(b"NEWVIEW"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let qc = QuorumCertificate {
            epoch: 1,
            round: 5,
            block_hash: [0xab; 32],
            signatures: vec![
                ValidatorSignature::new([1u8; 32], [0xcd; 64]),
                ValidatorSignature::new([2u8; 32], [0xef; 64]),
            ],
        };

        let json = serde_json::to_string(&qc).expect("serialize");
        let qc2: QuorumCertificate = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(qc, qc2);
    }

    /// Test for TCK-00186 ticket verification.
    #[test]
    #[allow(clippy::no_effect_underscore_binding)]
    fn tck_00186_bft_types_defined() {
        // Verify all required types exist and have expected fields
        let _proposal = Proposal {
            epoch: 0,
            round: 0,
            proposer_id: [0u8; 32],
            block_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            payload_hash: [0u8; 32],
            signature: [0u8; 64],
        };

        let _vote = Vote {
            epoch: 0,
            round: 0,
            voter_id: [0u8; 32],
            block_hash: [0u8; 32],
            signature: [0u8; 64],
        };

        let _qc = QuorumCertificate {
            epoch: 0,
            round: 0,
            block_hash: [0u8; 32],
            signatures: vec![],
        };

        let _new_view = NewView {
            epoch: 0,
            round: 0,
            sender_id: [0u8; 32],
            high_qc: QuorumCertificate::default(),
            signature: [0u8; 64],
        };

        // Verify state machine phases
        assert_eq!(Phase::default(), Phase::Idle);
    }
}
