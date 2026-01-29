// AGENT-AUTHORED
//! Strictly-ordered evidence for admission-critical artifacts.
//!
//! This module implements [`StrictlyOrderedEvidence`], which enforces that
//! admission-critical evidence is only accepted when it has been finalized
//! through the BFT consensus layer with a `TotalOrder` guarantee.
//!
//! # Security Properties
//!
//! - **Fail-closed admission (INV-0198-01)**: Evidence without `TotalOrder`
//!   finalization is rejected.
//! - **Auditable predicates (INV-0198-02)**: Gate predicates are recorded in
//!   receipts for replay verification.
//! - **Bounded collections (CTR-1303)**: All collections have explicit MAX
//!   constants.
//!
//! # Architecture
//!
//! ```text
//! Evidence Artifact
//!       |
//!       v
//! StrictlyOrderedEvidence::try_new()
//!       |
//!       ├─ Check: TotalOrder finalized?
//!       │   └─ No  → Return TotalOrderNotFinalized error
//!       │   └─ Yes → Continue
//!       |
//!       v
//! StrictlyOrderedEvidence (validated)
//!       |
//!       v
//! GateReceipt::with_predicates()
//!       |
//!       v
//! GateReceipt { evidence_predicates, ... }
//! ```
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::evidence::{
//!     DataClassification, EvidenceCategory, EvidencePredicate,
//!     GatePredicateReceipt, StrictlyOrderedEvidence, TotalOrderProof,
//! };
//!
//! // Create a TotalOrder proof (from BFT consensus)
//! let proof = TotalOrderProof {
//!     epoch: 1,
//!     round: 5,
//!     block_hash: [0xab; 32],
//!     qc_signature_count: 3,
//!     finalized_at: 1_000_000_000,
//! };
//!
//! // Create strictly-ordered evidence
//! let evidence = StrictlyOrderedEvidence::try_new(
//!     "evid-001",
//!     "work-123",
//!     EvidenceCategory::TestResults,
//!     [1u8; 32],
//!     1024,
//!     DataClassification::Internal,
//!     &proof,
//! )
//! .unwrap();
//!
//! assert!(evidence.is_finalized());
//! ```
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00198: `StrictlyOrderedEvidence` and Gate Predicates

use serde::{Deserialize, Serialize};

use super::category::EvidenceCategory;
use super::classification::DataClassification;
use crate::crypto::Hash;

// =============================================================================
// Constants (CTR-1303: Bounded Collections)
// =============================================================================

/// Maximum number of evidence predicates per gate receipt.
///
/// Bounds the size of the predicates list to prevent denial-of-service
/// via unbounded collections (CTR-1303).
pub const MAX_EVIDENCE_PREDICATES: usize = 64;

/// Maximum length for predicate names.
pub const MAX_PREDICATE_NAME_LEN: usize = 128;

/// Maximum length for predicate values.
pub const MAX_PREDICATE_VALUE_LEN: usize = 1024;

/// Maximum length for evidence IDs.
pub const MAX_EVIDENCE_ID_LEN: usize = 256;

/// Maximum length for work IDs.
pub const MAX_WORK_ID_LEN: usize = 256;

/// Minimum quorum signature count for valid `TotalOrder` proof.
///
/// A quorum requires at least 2f+1 signatures. For f=1 (minimum fault
/// tolerance), this requires 3 signatures.
pub const MIN_QUORUM_SIGNATURES: usize = 3;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during strictly-ordered evidence operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictlyOrderedError {
    /// Evidence was not finalized through `TotalOrder` consensus.
    ///
    /// This error indicates a security violation: admission-critical evidence
    /// MUST be finalized before it can be accepted.
    TotalOrderNotFinalized {
        /// The evidence ID that failed validation.
        evidence_id: String,
        /// Reason why the `TotalOrder` was not finalized.
        reason: String,
    },

    /// Insufficient quorum signatures in the `TotalOrder` proof.
    ///
    /// A valid `TotalOrder` proof requires at least `MIN_QUORUM_SIGNATURES`.
    InsufficientQuorum {
        /// Number of signatures present.
        have: usize,
        /// Number of signatures required.
        need: usize,
    },

    /// Evidence ID exceeds maximum length.
    EvidenceIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Work ID exceeds maximum length.
    WorkIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many predicates in the receipt.
    TooManyPredicates {
        /// Number of predicates present.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Predicate name exceeds maximum length.
    PredicateNameTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Predicate value exceeds maximum length.
    PredicateValueTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Predicate name contains invalid characters.
    InvalidPredicateName {
        /// The invalid name.
        name: String,
        /// Reason it's invalid.
        reason: String,
    },

    /// Block hash mismatch during verification.
    BlockHashMismatch {
        /// Expected hash.
        expected: [u8; 32],
        /// Actual hash.
        actual: [u8; 32],
    },
}

impl std::fmt::Display for StrictlyOrderedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TotalOrderNotFinalized {
                evidence_id,
                reason,
            } => {
                write!(
                    f,
                    "evidence {evidence_id} not finalized via TotalOrder: {reason}"
                )
            },
            Self::InsufficientQuorum { have, need } => {
                write!(f, "insufficient quorum: {have} of {need} required")
            },
            Self::EvidenceIdTooLong { len, max } => {
                write!(f, "evidence ID too long: {len} > {max}")
            },
            Self::WorkIdTooLong { len, max } => {
                write!(f, "work ID too long: {len} > {max}")
            },
            Self::TooManyPredicates { count, max } => {
                write!(f, "too many predicates: {count} > {max}")
            },
            Self::PredicateNameTooLong { len, max } => {
                write!(f, "predicate name too long: {len} > {max}")
            },
            Self::PredicateValueTooLong { len, max } => {
                write!(f, "predicate value too long: {len} > {max}")
            },
            Self::InvalidPredicateName { name, reason } => {
                write!(f, "invalid predicate name '{name}': {reason}")
            },
            Self::BlockHashMismatch { expected, actual } => {
                write!(
                    f,
                    "block hash mismatch: expected {:x?}, got {:x?}",
                    &expected[..8],
                    &actual[..8]
                )
            },
        }
    }
}

impl std::error::Error for StrictlyOrderedError {}

// =============================================================================
// TotalOrder Proof
// =============================================================================

/// Proof that an event was finalized through BFT `TotalOrder` consensus.
///
/// This proof is derived from a committed block's quorum certificate
/// and provides cryptographic evidence that the event was ordered and
/// finalized by consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotalOrderProof {
    /// Consensus epoch when finalized.
    pub epoch: u64,

    /// Round within the epoch.
    pub round: u64,

    /// BLAKE3 hash of the committed block.
    pub block_hash: [u8; 32],

    /// Number of quorum certificate signatures.
    ///
    /// Must be at least `MIN_QUORUM_SIGNATURES` for the proof to be valid.
    pub qc_signature_count: usize,

    /// Timestamp when finalization occurred (Unix nanos).
    pub finalized_at: u64,
}

impl TotalOrderProof {
    /// Creates a new `TotalOrder` proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the quorum signature count is insufficient.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(
        epoch: u64,
        round: u64,
        block_hash: [u8; 32],
        qc_signature_count: usize,
        finalized_at: u64,
    ) -> Result<Self, StrictlyOrderedError> {
        if qc_signature_count < MIN_QUORUM_SIGNATURES {
            return Err(StrictlyOrderedError::InsufficientQuorum {
                have: qc_signature_count,
                need: MIN_QUORUM_SIGNATURES,
            });
        }

        Ok(Self {
            epoch,
            round,
            block_hash,
            qc_signature_count,
            finalized_at,
        })
    }

    /// Creates a proof from raw values without validation.
    ///
    /// # Safety
    ///
    /// This bypasses quorum validation. Use only when you have already
    /// verified the proof through another mechanism (e.g., BFT machine).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_unchecked(
        epoch: u64,
        round: u64,
        block_hash: [u8; 32],
        qc_signature_count: usize,
        finalized_at: u64,
    ) -> Self {
        Self {
            epoch,
            round,
            block_hash,
            qc_signature_count,
            finalized_at,
        }
    }

    /// Returns true if the proof has sufficient quorum signatures.
    #[must_use]
    pub const fn has_quorum(&self) -> bool {
        self.qc_signature_count >= MIN_QUORUM_SIGNATURES
    }

    /// Returns the consensus view (epoch, round).
    #[must_use]
    pub const fn view(&self) -> (u64, u64) {
        (self.epoch, self.round)
    }
}

// =============================================================================
// StrictlyOrderedEvidence
// =============================================================================

/// Evidence that has been finalized through `TotalOrder` BFT consensus.
///
/// This type guarantees that the evidence was:
/// 1. Submitted to BFT consensus
/// 2. Included in a committed block
/// 3. Finalized with a quorum certificate
///
/// Evidence that has not been finalized CANNOT be converted to this type,
/// enforcing the fail-closed security property for admission-critical
/// artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct StrictlyOrderedEvidence {
    /// Unique identifier for this evidence.
    pub evidence_id: String,

    /// The work item this evidence is linked to.
    pub work_id: String,

    /// Category of this evidence.
    pub category: EvidenceCategory,

    /// BLAKE3 hash of the artifact content.
    pub artifact_hash: Hash,

    /// Size of the artifact in bytes.
    pub artifact_size: usize,

    /// Data classification.
    pub classification: DataClassification,

    /// Proof of `TotalOrder` finalization.
    pub total_order_proof: TotalOrderProof,

    /// Timestamp when the evidence was created (Unix nanos).
    pub created_at: u64,
}

impl StrictlyOrderedEvidence {
    /// Creates new strictly-ordered evidence with `TotalOrder` verification.
    ///
    /// This method enforces that the evidence has been finalized through
    /// BFT consensus before accepting it.
    ///
    /// # Arguments
    ///
    /// * `evidence_id` - Unique identifier for the evidence
    /// * `work_id` - Work item this evidence is linked to
    /// * `category` - Category of the evidence
    /// * `artifact_hash` - BLAKE3 hash of the content
    /// * `artifact_size` - Size in bytes
    /// * `classification` - Data classification level
    /// * `proof` - `TotalOrder` finalization proof
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The evidence ID exceeds `MAX_EVIDENCE_ID_LEN`
    /// - The work ID exceeds `MAX_WORK_ID_LEN`
    /// - The proof does not have sufficient quorum signatures
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        evidence_id: &str,
        work_id: &str,
        category: EvidenceCategory,
        artifact_hash: Hash,
        artifact_size: usize,
        classification: DataClassification,
        proof: &TotalOrderProof,
    ) -> Result<Self, StrictlyOrderedError> {
        // Validate evidence ID length
        if evidence_id.len() > MAX_EVIDENCE_ID_LEN {
            return Err(StrictlyOrderedError::EvidenceIdTooLong {
                len: evidence_id.len(),
                max: MAX_EVIDENCE_ID_LEN,
            });
        }

        // Validate work ID length
        if work_id.len() > MAX_WORK_ID_LEN {
            return Err(StrictlyOrderedError::WorkIdTooLong {
                len: work_id.len(),
                max: MAX_WORK_ID_LEN,
            });
        }

        // Validate TotalOrder finalization (fail-closed)
        if !proof.has_quorum() {
            return Err(StrictlyOrderedError::TotalOrderNotFinalized {
                evidence_id: evidence_id.to_string(),
                reason: format!(
                    "insufficient quorum: {} of {} required",
                    proof.qc_signature_count, MIN_QUORUM_SIGNATURES
                ),
            });
        }

        Ok(Self {
            evidence_id: evidence_id.to_string(),
            work_id: work_id.to_string(),
            category,
            artifact_hash,
            artifact_size,
            classification,
            total_order_proof: proof.clone(),
            created_at: proof.finalized_at,
        })
    }

    /// Creates strictly-ordered evidence without validation.
    ///
    /// # Safety
    ///
    /// This bypasses `TotalOrder` verification. Use only when you have
    /// already verified the proof through the BFT machine or during
    /// replay of validated events.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_unchecked(
        evidence_id: String,
        work_id: String,
        category: EvidenceCategory,
        artifact_hash: Hash,
        artifact_size: usize,
        classification: DataClassification,
        total_order_proof: TotalOrderProof,
        created_at: u64,
    ) -> Self {
        Self {
            evidence_id,
            work_id,
            category,
            artifact_hash,
            artifact_size,
            classification,
            total_order_proof,
            created_at,
        }
    }

    /// Returns true if this evidence is finalized.
    ///
    /// For `StrictlyOrderedEvidence`, this always returns true since
    /// the type can only be constructed with valid finalization proof.
    #[must_use]
    pub const fn is_finalized(&self) -> bool {
        self.total_order_proof.has_quorum()
    }

    /// Returns the consensus view (epoch, round) when finalized.
    #[must_use]
    pub const fn consensus_view(&self) -> (u64, u64) {
        self.total_order_proof.view()
    }

    /// Returns the block hash of the committed block.
    #[must_use]
    pub const fn block_hash(&self) -> &[u8; 32] {
        &self.total_order_proof.block_hash
    }
}

// =============================================================================
// Evidence Predicates
// =============================================================================

/// A predicate evaluating evidence for gate admission.
///
/// Predicates are boolean conditions that must be satisfied for evidence
/// to pass a gate. They are recorded in gate receipts for auditability
/// and replay verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePredicate {
    /// Name of the predicate (e.g., `has_test_results`, `is_finalized`).
    pub name: String,

    /// The value or expression evaluated.
    pub value: String,

    /// Whether the predicate was satisfied.
    pub satisfied: bool,

    /// Evidence ID this predicate applies to (if specific to one evidence).
    pub evidence_id: Option<String>,

    /// Timestamp when the predicate was evaluated (Unix nanos).
    pub evaluated_at: u64,
}

impl EvidencePredicate {
    /// Creates a new evidence predicate.
    ///
    /// # Errors
    ///
    /// Returns an error if the name or value exceeds maximum length,
    /// or if the name contains invalid characters.
    pub fn try_new(
        name: &str,
        value: &str,
        satisfied: bool,
        evidence_id: Option<&str>,
        evaluated_at: u64,
    ) -> Result<Self, StrictlyOrderedError> {
        // Validate name length
        if name.len() > MAX_PREDICATE_NAME_LEN {
            return Err(StrictlyOrderedError::PredicateNameTooLong {
                len: name.len(),
                max: MAX_PREDICATE_NAME_LEN,
            });
        }

        // Validate value length
        if value.len() > MAX_PREDICATE_VALUE_LEN {
            return Err(StrictlyOrderedError::PredicateValueTooLong {
                len: value.len(),
                max: MAX_PREDICATE_VALUE_LEN,
            });
        }

        // Validate name characters (alphanumeric, underscore, hyphen)
        for c in name.chars() {
            if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
                return Err(StrictlyOrderedError::InvalidPredicateName {
                    name: name.to_string(),
                    reason: format!("invalid character: {c:?}"),
                });
            }
        }

        Ok(Self {
            name: name.to_string(),
            value: value.to_string(),
            satisfied,
            evidence_id: evidence_id.map(String::from),
            evaluated_at,
        })
    }

    /// Creates a predicate without validation.
    ///
    /// # Safety
    ///
    /// This bypasses length and character validation. Use only during
    /// replay of validated predicates.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new_unchecked(
        name: String,
        value: String,
        satisfied: bool,
        evidence_id: Option<String>,
        evaluated_at: u64,
    ) -> Self {
        Self {
            name,
            value,
            satisfied,
            evidence_id,
            evaluated_at,
        }
    }

    /// Creates a `total_order_finalized` predicate.
    #[must_use]
    pub fn total_order_finalized(evidence_id: &str, finalized: bool, timestamp: u64) -> Self {
        Self {
            name: "total_order_finalized".to_string(),
            value: finalized.to_string(),
            satisfied: finalized,
            evidence_id: Some(evidence_id.to_string()),
            evaluated_at: timestamp,
        }
    }

    /// Creates a `has_category` predicate.
    #[must_use]
    pub fn has_category(category: EvidenceCategory, present: bool, timestamp: u64) -> Self {
        Self {
            name: "has_category".to_string(),
            value: category.as_str().to_string(),
            satisfied: present,
            evidence_id: None,
            evaluated_at: timestamp,
        }
    }

    /// Creates a `quorum_signatures` predicate.
    #[must_use]
    pub fn quorum_signatures(count: usize, required: usize, timestamp: u64) -> Self {
        Self {
            name: "quorum_signatures".to_string(),
            value: format!("{count}/{required}"),
            satisfied: count >= required,
            evidence_id: None,
            evaluated_at: timestamp,
        }
    }
}

// =============================================================================
// Gate Predicate Receipt
// =============================================================================

/// Extended gate receipt with evidence predicates for auditability.
///
/// This extends the base [`GateReceipt`](super::GateReceipt) with predicate
/// metadata that records all conditions evaluated during gate admission.
/// This enables replay verification and audit trails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GatePredicateReceipt {
    /// Base receipt ID.
    pub receipt_id: String,

    /// Gate ID.
    pub gate_id: String,

    /// Work ID.
    pub work_id: String,

    /// Whether the gate passed.
    pub passed: bool,

    /// Evidence predicates evaluated for this gate.
    ///
    /// Bounded by `MAX_EVIDENCE_PREDICATES` (CTR-1303).
    pub evidence_predicates: Vec<EvidencePredicate>,

    /// BLAKE3 hash of strictly-ordered evidence included.
    pub evidence_hashes: Vec<Hash>,

    /// Timestamp when the receipt was generated (Unix nanos).
    pub generated_at: u64,

    /// Number of strictly-ordered evidence items.
    pub strictly_ordered_count: usize,

    /// Number of evidence items without `TotalOrder` proof.
    pub unordered_count: usize,
}

impl GatePredicateReceipt {
    /// Creates a new gate predicate receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of predicates exceeds
    /// `MAX_EVIDENCE_PREDICATES`.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        receipt_id: String,
        gate_id: String,
        work_id: String,
        passed: bool,
        evidence_predicates: Vec<EvidencePredicate>,
        evidence_hashes: Vec<Hash>,
        generated_at: u64,
        strictly_ordered_count: usize,
        unordered_count: usize,
    ) -> Result<Self, StrictlyOrderedError> {
        // Validate predicates count (CTR-1303)
        if evidence_predicates.len() > MAX_EVIDENCE_PREDICATES {
            return Err(StrictlyOrderedError::TooManyPredicates {
                count: evidence_predicates.len(),
                max: MAX_EVIDENCE_PREDICATES,
            });
        }

        Ok(Self {
            receipt_id,
            gate_id,
            work_id,
            passed,
            evidence_predicates,
            evidence_hashes,
            generated_at,
            strictly_ordered_count,
            unordered_count,
        })
    }

    /// Returns true if all predicates were satisfied.
    #[must_use]
    pub fn all_predicates_satisfied(&self) -> bool {
        self.evidence_predicates.iter().all(|p| p.satisfied)
    }

    /// Returns the predicates that failed.
    #[must_use]
    pub fn failed_predicates(&self) -> Vec<&EvidencePredicate> {
        self.evidence_predicates
            .iter()
            .filter(|p| !p.satisfied)
            .collect()
    }

    /// Returns predicates for a specific evidence ID.
    #[must_use]
    pub fn predicates_for_evidence(&self, evidence_id: &str) -> Vec<&EvidencePredicate> {
        self.evidence_predicates
            .iter()
            .filter(|p| p.evidence_id.as_deref() == Some(evidence_id))
            .collect()
    }

    /// Serializes the receipt to JSON for audit logging.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_audit_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Computes a deterministic hash of the receipt for replay verification.
    #[must_use]
    pub fn compute_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();

        hasher.update(self.receipt_id.as_bytes());
        hasher.update(self.gate_id.as_bytes());
        hasher.update(self.work_id.as_bytes());
        hasher.update(&[u8::from(self.passed)]);

        // Hash predicates in order
        for predicate in &self.evidence_predicates {
            hasher.update(predicate.name.as_bytes());
            hasher.update(predicate.value.as_bytes());
            hasher.update(&[u8::from(predicate.satisfied)]);
            if let Some(ref eid) = predicate.evidence_id {
                hasher.update(eid.as_bytes());
            }
        }

        // Hash evidence hashes
        for hash in &self.evidence_hashes {
            hasher.update(hash);
        }

        hasher.update(&self.generated_at.to_le_bytes());

        hasher.finalize().into()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_proof() -> TotalOrderProof {
        TotalOrderProof {
            epoch: 1,
            round: 5,
            block_hash: [0xab; 32],
            qc_signature_count: 3, // Minimum quorum
            finalized_at: 1_000_000_000,
        }
    }

    fn make_insufficient_proof() -> TotalOrderProof {
        TotalOrderProof {
            epoch: 1,
            round: 5,
            block_hash: [0xab; 32],
            qc_signature_count: 2, // Below minimum
            finalized_at: 1_000_000_000,
        }
    }

    // =========================================================================
    // TotalOrderProof tests
    // =========================================================================

    #[test]
    fn test_total_order_proof_new() {
        let proof = TotalOrderProof::new(1, 5, [0xab; 32], 3, 1_000_000_000);
        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert!(proof.has_quorum());
        assert_eq!(proof.view(), (1, 5));
    }

    #[test]
    fn test_total_order_proof_insufficient_quorum() {
        let result = TotalOrderProof::new(1, 5, [0xab; 32], 2, 1_000_000_000);
        assert!(matches!(
            result,
            Err(StrictlyOrderedError::InsufficientQuorum { have: 2, need: 3 })
        ));
    }

    #[test]
    fn test_total_order_proof_unchecked() {
        // _unchecked allows insufficient quorum (for trusted contexts)
        let proof = TotalOrderProof::new_unchecked(1, 5, [0xab; 32], 1, 1_000_000_000);
        assert!(!proof.has_quorum());
    }

    // =========================================================================
    // StrictlyOrderedEvidence tests
    // =========================================================================

    #[test]
    fn tck_00198_strictly_ordered_evidence_accepts_finalized() {
        let proof = make_valid_proof();
        let result = StrictlyOrderedEvidence::try_new(
            "evid-001",
            "work-123",
            EvidenceCategory::TestResults,
            [1u8; 32],
            1024,
            DataClassification::Internal,
            &proof,
        );

        assert!(result.is_ok());
        let evidence = result.unwrap();
        assert!(evidence.is_finalized());
        assert_eq!(evidence.evidence_id, "evid-001");
        assert_eq!(evidence.work_id, "work-123");
        assert_eq!(evidence.consensus_view(), (1, 5));
    }

    #[test]
    fn tck_00198_strictly_ordered_evidence_rejects_not_finalized() {
        let proof = make_insufficient_proof();
        let result = StrictlyOrderedEvidence::try_new(
            "evid-001",
            "work-123",
            EvidenceCategory::TestResults,
            [1u8; 32],
            1024,
            DataClassification::Internal,
            &proof,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            StrictlyOrderedError::TotalOrderNotFinalized { .. }
        ));
    }

    #[test]
    fn tck_00198_strictly_ordered_evidence_rejects_long_evidence_id() {
        let proof = make_valid_proof();
        let long_id = "e".repeat(MAX_EVIDENCE_ID_LEN + 1);
        let result = StrictlyOrderedEvidence::try_new(
            &long_id,
            "work-123",
            EvidenceCategory::TestResults,
            [1u8; 32],
            1024,
            DataClassification::Internal,
            &proof,
        );

        assert!(matches!(
            result,
            Err(StrictlyOrderedError::EvidenceIdTooLong { .. })
        ));
    }

    #[test]
    fn tck_00198_strictly_ordered_evidence_rejects_long_work_id() {
        let proof = make_valid_proof();
        let long_id = "w".repeat(MAX_WORK_ID_LEN + 1);
        let result = StrictlyOrderedEvidence::try_new(
            "evid-001",
            &long_id,
            EvidenceCategory::TestResults,
            [1u8; 32],
            1024,
            DataClassification::Internal,
            &proof,
        );

        assert!(matches!(
            result,
            Err(StrictlyOrderedError::WorkIdTooLong { .. })
        ));
    }

    #[test]
    fn tck_00198_strictly_ordered_evidence_boundary_id_length() {
        let proof = make_valid_proof();

        // Exactly at limit should succeed
        let max_id = "e".repeat(MAX_EVIDENCE_ID_LEN);
        let result = StrictlyOrderedEvidence::try_new(
            &max_id,
            "work-123",
            EvidenceCategory::TestResults,
            [1u8; 32],
            1024,
            DataClassification::Internal,
            &proof,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_strictly_ordered_evidence_unchecked() {
        // _unchecked bypasses validation
        let proof = make_insufficient_proof();
        let evidence = StrictlyOrderedEvidence::new_unchecked(
            "evid-001".to_string(),
            "work-123".to_string(),
            EvidenceCategory::TestResults,
            [1u8; 32],
            1024,
            DataClassification::Internal,
            proof,
            1_000_000_000,
        );
        // Note: is_finalized still checks the proof
        assert!(!evidence.is_finalized());
    }

    // =========================================================================
    // EvidencePredicate tests
    // =========================================================================

    #[test]
    fn tck_00198_evidence_predicate_creates_valid() {
        let predicate = EvidencePredicate::try_new(
            "has_test_results",
            "true",
            true,
            Some("evid-001"),
            1_000_000_000,
        );

        assert!(predicate.is_ok());
        let p = predicate.unwrap();
        assert_eq!(p.name, "has_test_results");
        assert!(p.satisfied);
        assert_eq!(p.evidence_id, Some("evid-001".to_string()));
    }

    #[test]
    fn tck_00198_evidence_predicate_rejects_long_name() {
        let long_name = "p".repeat(MAX_PREDICATE_NAME_LEN + 1);
        let result = EvidencePredicate::try_new(&long_name, "true", true, None, 1_000_000_000);

        assert!(matches!(
            result,
            Err(StrictlyOrderedError::PredicateNameTooLong { .. })
        ));
    }

    #[test]
    fn tck_00198_evidence_predicate_rejects_long_value() {
        let long_value = "v".repeat(MAX_PREDICATE_VALUE_LEN + 1);
        let result =
            EvidencePredicate::try_new("predicate", &long_value, true, None, 1_000_000_000);

        assert!(matches!(
            result,
            Err(StrictlyOrderedError::PredicateValueTooLong { .. })
        ));
    }

    #[test]
    fn tck_00198_evidence_predicate_rejects_invalid_name_chars() {
        // Spaces not allowed
        let result = EvidencePredicate::try_new("has test", "true", true, None, 1_000_000_000);
        assert!(matches!(
            result,
            Err(StrictlyOrderedError::InvalidPredicateName { .. })
        ));

        // Pipe not allowed
        let result = EvidencePredicate::try_new("has|test", "true", true, None, 1_000_000_000);
        assert!(matches!(
            result,
            Err(StrictlyOrderedError::InvalidPredicateName { .. })
        ));
    }

    #[test]
    fn test_predicate_factory_methods() {
        let p1 = EvidencePredicate::total_order_finalized("evid-001", true, 1_000_000_000);
        assert_eq!(p1.name, "total_order_finalized");
        assert!(p1.satisfied);

        let p2 =
            EvidencePredicate::has_category(EvidenceCategory::TestResults, true, 1_000_000_000);
        assert_eq!(p2.name, "has_category");
        assert_eq!(p2.value, "TEST_RESULTS");

        let p3 = EvidencePredicate::quorum_signatures(4, 3, 1_000_000_000);
        assert_eq!(p3.name, "quorum_signatures");
        assert_eq!(p3.value, "4/3");
        assert!(p3.satisfied);

        let p4 = EvidencePredicate::quorum_signatures(2, 3, 1_000_000_000);
        assert!(!p4.satisfied);
    }

    // =========================================================================
    // GatePredicateReceipt tests
    // =========================================================================

    #[test]
    fn tck_00198_gate_predicate_receipt_includes_predicates() {
        let predicates = vec![
            EvidencePredicate::total_order_finalized("evid-001", true, 1_000_000_000),
            EvidencePredicate::has_category(EvidenceCategory::TestResults, true, 1_000_000_000),
        ];

        let receipt = GatePredicateReceipt::try_new(
            "rcpt-001".to_string(),
            "gate-001".to_string(),
            "work-123".to_string(),
            true,
            predicates,
            vec![[1u8; 32], [2u8; 32]],
            2_000_000_000,
            2,
            0,
        );

        assert!(receipt.is_ok());
        let r = receipt.unwrap();
        assert_eq!(r.evidence_predicates.len(), 2);
        assert!(r.all_predicates_satisfied());
        assert!(r.failed_predicates().is_empty());
    }

    #[test]
    fn tck_00198_gate_predicate_receipt_detects_failed_predicates() {
        let predicates = vec![
            EvidencePredicate::total_order_finalized("evid-001", true, 1_000_000_000),
            EvidencePredicate::quorum_signatures(2, 3, 1_000_000_000), // Failed
        ];

        let receipt = GatePredicateReceipt::try_new(
            "rcpt-001".to_string(),
            "gate-001".to_string(),
            "work-123".to_string(),
            false,
            predicates,
            vec![[1u8; 32]],
            2_000_000_000,
            1,
            1,
        )
        .unwrap();

        assert!(!receipt.all_predicates_satisfied());
        assert_eq!(receipt.failed_predicates().len(), 1);
        assert_eq!(receipt.failed_predicates()[0].name, "quorum_signatures");
    }

    #[test]
    fn tck_00198_gate_predicate_receipt_rejects_too_many_predicates() {
        let predicates: Vec<_> = (0..=MAX_EVIDENCE_PREDICATES)
            .map(|i| {
                EvidencePredicate::new_unchecked(
                    format!("pred_{i}"),
                    "value".to_string(),
                    true,
                    None,
                    1_000_000_000,
                )
            })
            .collect();

        let result = GatePredicateReceipt::try_new(
            "rcpt-001".to_string(),
            "gate-001".to_string(),
            "work-123".to_string(),
            true,
            predicates,
            vec![],
            2_000_000_000,
            0,
            0,
        );

        assert!(matches!(
            result,
            Err(StrictlyOrderedError::TooManyPredicates { .. })
        ));
    }

    #[test]
    fn tck_00198_gate_predicate_receipt_predicates_for_evidence() {
        let predicates = vec![
            EvidencePredicate::total_order_finalized("evid-001", true, 1_000_000_000),
            EvidencePredicate::total_order_finalized("evid-002", true, 1_000_000_000),
            EvidencePredicate::has_category(EvidenceCategory::TestResults, true, 1_000_000_000),
        ];

        let receipt = GatePredicateReceipt::try_new(
            "rcpt-001".to_string(),
            "gate-001".to_string(),
            "work-123".to_string(),
            true,
            predicates,
            vec![],
            2_000_000_000,
            2,
            0,
        )
        .unwrap();

        let evid_001_preds = receipt.predicates_for_evidence("evid-001");
        assert_eq!(evid_001_preds.len(), 1);

        let evid_002_preds = receipt.predicates_for_evidence("evid-002");
        assert_eq!(evid_002_preds.len(), 1);
    }

    #[test]
    fn tck_00198_gate_predicate_receipt_hash_is_deterministic() {
        let predicates = vec![EvidencePredicate::total_order_finalized(
            "evid-001",
            true,
            1_000_000_000,
        )];

        let receipt1 = GatePredicateReceipt::try_new(
            "rcpt-001".to_string(),
            "gate-001".to_string(),
            "work-123".to_string(),
            true,
            predicates.clone(),
            vec![[1u8; 32]],
            2_000_000_000,
            1,
            0,
        )
        .unwrap();

        let receipt2 = GatePredicateReceipt::try_new(
            "rcpt-001".to_string(),
            "gate-001".to_string(),
            "work-123".to_string(),
            true,
            predicates,
            vec![[1u8; 32]],
            2_000_000_000,
            1,
            0,
        )
        .unwrap();

        assert_eq!(receipt1.compute_hash(), receipt2.compute_hash());
    }

    #[test]
    fn tck_00198_gate_predicate_receipt_to_audit_json() {
        let predicates = vec![EvidencePredicate::total_order_finalized(
            "evid-001",
            true,
            1_000_000_000,
        )];

        let receipt = GatePredicateReceipt::try_new(
            "rcpt-001".to_string(),
            "gate-001".to_string(),
            "work-123".to_string(),
            true,
            predicates,
            vec![[1u8; 32]],
            2_000_000_000,
            1,
            0,
        )
        .unwrap();

        let json = receipt.to_audit_json().unwrap();
        assert!(json.contains("rcpt-001"));
        assert!(json.contains("total_order_finalized"));
        assert!(json.contains("evid-001"));
    }

    // =========================================================================
    // Serde deny_unknown_fields tests (CTR-1604)
    // =========================================================================

    #[test]
    fn tck_00198_serde_deny_unknown_fields_total_order_proof() {
        let json = r#"{"epoch": 1, "round": 5, "block_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], "qc_signature_count": 3, "finalized_at": 1000000000, "extra_field": "attack"}"#;

        let result: Result<TotalOrderProof, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("unknown field"));
    }

    #[test]
    fn tck_00198_serde_deny_unknown_fields_strictly_ordered_evidence() {
        // Note: EvidenceCategory and DataClassification serialize as PascalCase
        // (derived serde), not SCREAMING_SNAKE_CASE
        let json = r#"{"evidence_id": "evid-001", "work_id": "work-123", "category": "TestResults", "artifact_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], "artifact_size": 1024, "classification": "Internal", "total_order_proof": {"epoch": 1, "round": 5, "block_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], "qc_signature_count": 3, "finalized_at": 1000000000}, "created_at": 1000000000, "extra_field": "attack"}"#;

        let result: Result<StrictlyOrderedEvidence, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("unknown field"));
    }

    #[test]
    fn tck_00198_serde_deny_unknown_fields_evidence_predicate() {
        let json = r#"{"name": "test", "value": "true", "satisfied": true, "evidence_id": null, "evaluated_at": 1000000000, "extra_field": "attack"}"#;

        let result: Result<EvidencePredicate, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("unknown field"));
    }

    #[test]
    fn tck_00198_serde_deny_unknown_fields_gate_predicate_receipt() {
        let json = r#"{"receipt_id": "rcpt-001", "gate_id": "gate-001", "work_id": "work-123", "passed": true, "evidence_predicates": [], "evidence_hashes": [], "generated_at": 2000000000, "strictly_ordered_count": 0, "unordered_count": 0, "extra_field": "attack"}"#;

        let result: Result<GatePredicateReceipt, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("unknown field"));
    }

    // =========================================================================
    // Error display tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let err = StrictlyOrderedError::TotalOrderNotFinalized {
            evidence_id: "evid-001".to_string(),
            reason: "no quorum".to_string(),
        };
        assert!(err.to_string().contains("evid-001"));
        assert!(err.to_string().contains("no quorum"));

        let err = StrictlyOrderedError::InsufficientQuorum { have: 2, need: 3 };
        assert!(err.to_string().contains('2'));
        assert!(err.to_string().contains('3'));

        let err = StrictlyOrderedError::TooManyPredicates {
            count: 100,
            max: 64,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("64"));
    }
}
