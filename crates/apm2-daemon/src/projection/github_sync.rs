// AGENT-AUTHORED (TCK-00212)
//! GitHub projection adapter for the FAC (Forge Admission Cycle).
//!
//! This module implements a write-only projection adapter that synchronizes
//! ledger state to GitHub commit statuses. The adapter is write-only by design:
//! the ledger is always the source of truth, and GitHub is merely a projection
//! of that truth.
//!
//! # Security Model
//!
//! - **Write-only**: The adapter NEVER reads GitHub status as truth
//! - **Ledger is truth**: All decisions are made based on ledger state
//! - **Signed receipts**: Every projection generates a signed receipt
//! - **Idempotent**: Safe for retries with `(work_id, changeset_digest,
//!   ledger_head)` key
//!
//! # RFC-0015: FAC GitHub Projection
//!
//! Per RFC-0015, the GitHub projection adapter:
//!
//! 1. Receives status updates from the FAC ledger
//! 2. Projects those statuses to GitHub commit statuses
//! 3. Generates signed [`ProjectionReceipt`] proving the projection
//! 4. Maintains idempotency for safe retries
//!
//! # Divergence and Tamper Detection
//!
//! Divergence watchdog (TCK-00213) and tamper detection (TCK-00214) are
//! implemented separately. This module focuses solely on write-only projection.
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::crypto::Signer;
//! use apm2_daemon::projection::{
//!     GitHubProjectionAdapter, ProjectionAdapter, ProjectedStatus,
//! };
//!
//! let signer = Signer::generate();
//! let adapter = GitHubProjectionAdapter::new(signer, "https://api.github.com");
//!
//! let receipt = adapter.project_status(
//!     "work-001",
//!     [0x42; 32],
//!     [0xAB; 32],
//!     ProjectedStatus::Success,
//! ).await?;
//!
//! println!("Projected with receipt: {}", receipt.receipt_id);
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use apm2_core::crypto::Signer;
use thiserror::Error;
use uuid::Uuid;

use super::projection_receipt::{
    IdempotencyKey, ProjectedStatus, ProjectionReceipt, ProjectionReceiptBuilder,
};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during projection operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionError {
    /// GitHub API error.
    #[error("GitHub API error: {message}")]
    GitHubApiError {
        /// Error message from the API.
        message: String,
        /// HTTP status code, if available.
        status_code: Option<u16>,
    },

    /// Network error.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Authentication error.
    #[error("authentication error: {0}")]
    AuthenticationError(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded, retry after {retry_after_secs} seconds")]
    RateLimitExceeded {
        /// Seconds until rate limit resets.
        retry_after_secs: u64,
    },

    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Receipt generation failed.
    #[error("failed to generate receipt: {0}")]
    ReceiptGenerationFailed(String),
}

// =============================================================================
// ProjectionAdapter Trait
// =============================================================================

/// A write-only adapter for projecting ledger state to external systems.
///
/// The adapter projects status updates to an external system (e.g., GitHub)
/// and returns signed receipts as proof of projection. The adapter is
/// write-only by design - it never reads the external system as a source
/// of truth.
///
/// # Security Invariants
///
/// 1. The ledger is ALWAYS the source of truth
/// 2. The adapter NEVER reads external state as truth
/// 3. All projections generate signed receipts
/// 4. Projections are idempotent with `(work_id, changeset_digest,
///    ledger_head)` key
pub trait ProjectionAdapter: Send + Sync {
    /// Projects a status to the external system.
    ///
    /// This method is idempotent: calling it multiple times with the same
    /// `(work_id, changeset_digest, ledger_head)` tuple will return the
    /// same receipt (or a cached one).
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item identifier
    /// * `changeset_digest` - The changeset digest (32 bytes)
    /// * `ledger_head` - The ledger head hash at time of projection (32 bytes)
    /// * `status` - The status to project
    ///
    /// # Returns
    ///
    /// A signed [`ProjectionReceipt`] proving the projection occurred.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError`] if the projection fails.
    fn project_status(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
        status: ProjectedStatus,
    ) -> Result<ProjectionReceipt, ProjectionError>;

    /// Returns the adapter's verifying key for receipt validation.
    fn verifying_key(&self) -> apm2_core::crypto::VerifyingKey;
}

// =============================================================================
// GitHubProjectionAdapter
// =============================================================================

/// GitHub projection adapter configuration.
#[derive(Debug, Clone)]
pub struct GitHubAdapterConfig {
    /// GitHub API base URL (e.g., "<https://api.github.com>").
    pub api_base_url: String,

    /// Repository owner.
    pub owner: String,

    /// Repository name.
    pub repo: String,

    /// Context string for commit statuses (e.g., "apm2/gates").
    pub context: String,

    /// Target URL for status details (optional).
    pub target_url: Option<String>,
}

impl GitHubAdapterConfig {
    /// Creates a new configuration with required fields.
    #[must_use]
    pub fn new(
        api_base_url: impl Into<String>,
        owner: impl Into<String>,
        repo: impl Into<String>,
    ) -> Self {
        Self {
            api_base_url: api_base_url.into(),
            owner: owner.into(),
            repo: repo.into(),
            context: "apm2/gates".to_string(),
            target_url: None,
        }
    }

    /// Sets the context string for commit statuses.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = context.into();
        self
    }

    /// Sets the target URL for status details.
    #[must_use]
    pub fn with_target_url(mut self, url: impl Into<String>) -> Self {
        self.target_url = Some(url.into());
        self
    }
}

/// A write-only GitHub projection adapter.
///
/// This adapter projects ledger state to GitHub commit statuses. It is
/// write-only by design: the ledger is always the source of truth.
///
/// # Idempotency
///
/// The adapter maintains an internal cache keyed by `(work_id,
/// changeset_digest, ledger_head)`. If a projection is retried with the same
/// key, the cached receipt is returned without making another API call.
///
/// # Thread Safety
///
/// The adapter is thread-safe and can be shared across async tasks.
pub struct GitHubProjectionAdapter {
    /// Signer for generating receipts.
    signer: Signer,

    /// Adapter configuration.
    config: GitHubAdapterConfig,

    /// Idempotency cache: maps idempotency keys to receipts.
    ///
    /// In production, this would be backed by persistent storage.
    /// For now, we use an in-memory cache.
    idempotency_cache: Arc<RwLock<HashMap<IdempotencyKey, ProjectionReceipt>>>,

    /// Mock mode: if true, don't actually call GitHub API.
    ///
    /// Used for testing.
    mock_mode: bool,
}

impl GitHubProjectionAdapter {
    /// Creates a new GitHub projection adapter.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signer for generating receipts
    /// * `config` - The adapter configuration
    #[must_use]
    pub fn new(signer: Signer, config: GitHubAdapterConfig) -> Self {
        Self {
            signer,
            config,
            idempotency_cache: Arc::new(RwLock::new(HashMap::new())),
            mock_mode: false,
        }
    }

    /// Creates a new adapter in mock mode for testing.
    ///
    /// In mock mode, the adapter does not make actual GitHub API calls.
    #[must_use]
    pub fn new_mock(signer: Signer, config: GitHubAdapterConfig) -> Self {
        Self {
            signer,
            config,
            idempotency_cache: Arc::new(RwLock::new(HashMap::new())),
            mock_mode: true,
        }
    }

    /// Returns whether the adapter is in mock mode.
    #[must_use]
    pub const fn is_mock(&self) -> bool {
        self.mock_mode
    }

    /// Returns the adapter configuration.
    #[must_use]
    pub const fn config(&self) -> &GitHubAdapterConfig {
        &self.config
    }

    /// Clears the idempotency cache.
    ///
    /// This is primarily useful for testing.
    pub fn clear_cache(&self) {
        let mut cache = self.idempotency_cache.write().unwrap();
        cache.clear();
    }

    /// Returns the number of cached receipts.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        let cache = self.idempotency_cache.read().unwrap();
        cache.len()
    }

    /// Checks the idempotency cache for an existing receipt.
    fn check_cache(&self, key: &IdempotencyKey) -> Option<ProjectionReceipt> {
        let cache = self.idempotency_cache.read().unwrap();
        cache.get(key).cloned()
    }

    /// Stores a receipt in the idempotency cache.
    fn store_in_cache(&self, key: IdempotencyKey, receipt: ProjectionReceipt) {
        let mut cache = self.idempotency_cache.write().unwrap();
        cache.insert(key, receipt);
    }

    /// Generates a new receipt ID.
    fn generate_receipt_id() -> String {
        format!("proj-{}", Uuid::new_v4())
    }

    /// Projects a status to GitHub (internal implementation).
    ///
    /// In production, this would make an actual GitHub API call.
    /// In mock mode, this is a no-op.
    fn do_github_projection(
        &self,
        _changeset_digest: &[u8; 32],
        _status: ProjectedStatus,
    ) -> Result<(), ProjectionError> {
        if self.mock_mode {
            // In mock mode, pretend the API call succeeded
            return Ok(());
        }

        // TODO: In production, this would:
        // 1. Convert changeset_digest to a commit SHA (via lookup)
        // 2. Map ProjectedStatus to GitHub status state
        // 3. POST to /repos/{owner}/{repo}/statuses/{sha}
        //
        // For now, we return an error indicating not implemented
        Err(ProjectionError::InvalidConfiguration(
            "GitHub API integration not yet implemented - use mock mode for testing".to_string(),
        ))
    }
}

impl ProjectionAdapter for GitHubProjectionAdapter {
    fn project_status(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
        status: ProjectedStatus,
    ) -> Result<ProjectionReceipt, ProjectionError> {
        // Build the idempotency key
        let key = IdempotencyKey::new(work_id, changeset_digest, ledger_head);

        // Check cache first (idempotent)
        if let Some(cached_receipt) = self.check_cache(&key) {
            return Ok(cached_receipt);
        }

        // Perform the GitHub API call (or mock it)
        self.do_github_projection(&changeset_digest, status)?;

        // Generate the receipt
        let receipt = ProjectionReceiptBuilder::new(Self::generate_receipt_id(), work_id)
            .changeset_digest(changeset_digest)
            .ledger_head(ledger_head)
            .projected_status(status)
            .try_build_and_sign(&self.signer)
            .map_err(|e| ProjectionError::ReceiptGenerationFailed(e.to_string()))?;

        // Store in cache for idempotency
        self.store_in_cache(key, receipt.clone());

        Ok(receipt)
    }

    fn verifying_key(&self) -> apm2_core::crypto::VerifyingKey {
        self.signer.verifying_key()
    }
}

impl std::fmt::Debug for GitHubProjectionAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubProjectionAdapter")
            .field("config", &self.config)
            .field("mock_mode", &self.mock_mode)
            .field("cache_size", &self.cache_size())
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    fn create_test_adapter() -> GitHubProjectionAdapter {
        let signer = Signer::generate();
        let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")
            .with_context("apm2/test");
        GitHubProjectionAdapter::new_mock(signer, config)
    }

    // =========================================================================
    // GitHubAdapterConfig Tests
    // =========================================================================

    #[test]
    fn test_config_creation() {
        let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo");

        assert_eq!(config.api_base_url, "https://api.github.com");
        assert_eq!(config.owner, "owner");
        assert_eq!(config.repo, "repo");
        assert_eq!(config.context, "apm2/gates");
        assert!(config.target_url.is_none());
    }

    #[test]
    fn test_config_with_options() {
        let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")
            .with_context("custom/context")
            .with_target_url("https://example.com/details");

        assert_eq!(config.context, "custom/context");
        assert_eq!(
            config.target_url,
            Some("https://example.com/details".to_string())
        );
    }

    // =========================================================================
    // GitHubProjectionAdapter Tests
    // =========================================================================

    #[test]
    fn test_adapter_creation() {
        let adapter = create_test_adapter();

        assert!(adapter.is_mock());
        assert_eq!(adapter.cache_size(), 0);
    }

    #[test]
    fn test_project_status_success() {
        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        assert_eq!(receipt.work_id, "work-001");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.ledger_head, [0xAB; 32]);
        assert_eq!(receipt.projected_status, ProjectedStatus::Success);
        assert!(receipt.receipt_id.starts_with("proj-"));
    }

    #[test]
    fn test_project_status_idempotent() {
        let adapter = create_test_adapter();

        // First projection
        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        assert_eq!(adapter.cache_size(), 1);

        // Second projection with same key
        let receipt2 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        // Should return the same receipt (from cache)
        assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
        assert_eq!(receipt1.adapter_signature, receipt2.adapter_signature);

        // Cache size should still be 1
        assert_eq!(adapter.cache_size(), 1);
    }

    #[test]
    fn test_project_status_different_ledger_head() {
        let adapter = create_test_adapter();

        // First projection
        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        // Second projection with different ledger_head
        let receipt2 = adapter
            .project_status("work-001", [0x42; 32], [0xCD; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        // Should be different receipts
        assert_ne!(receipt1.receipt_id, receipt2.receipt_id);
        assert_ne!(receipt1.ledger_head, receipt2.ledger_head);

        // Cache should have 2 entries
        assert_eq!(adapter.cache_size(), 2);
    }

    #[test]
    fn test_project_status_different_work_id() {
        let adapter = create_test_adapter();

        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        let receipt2 = adapter
            .project_status("work-002", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        assert_ne!(receipt1.receipt_id, receipt2.receipt_id);
        assert_eq!(adapter.cache_size(), 2);
    }

    #[test]
    fn test_project_status_different_changeset() {
        let adapter = create_test_adapter();

        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        let receipt2 = adapter
            .project_status("work-001", [0x99; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        assert_ne!(receipt1.receipt_id, receipt2.receipt_id);
        assert_eq!(adapter.cache_size(), 2);
    }

    #[test]
    fn test_project_status_all_statuses() {
        let adapter = create_test_adapter();

        let statuses = [
            ProjectedStatus::Pending,
            ProjectedStatus::Success,
            ProjectedStatus::Failure,
            ProjectedStatus::Cancelled,
            ProjectedStatus::Error,
        ];

        for (i, status) in statuses.iter().enumerate() {
            let receipt = adapter
                .project_status(&format!("work-{i:03}"), [0x42; 32], [0xAB; 32], *status)
                .expect("projection should succeed");

            assert_eq!(receipt.projected_status, *status);
        }

        assert_eq!(adapter.cache_size(), 5);
    }

    #[test]
    fn test_receipt_signature_valid() {
        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        // Verify signature using adapter's verifying key
        assert!(receipt.validate_signature(&adapter.verifying_key()).is_ok());
    }

    #[test]
    fn test_receipt_signature_invalid_with_other_key() {
        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        // Verify with a different key should fail
        let other_signer = Signer::generate();
        assert!(
            receipt
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_clear_cache() {
        let adapter = create_test_adapter();

        adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        assert_eq!(adapter.cache_size(), 1);

        adapter.clear_cache();

        assert_eq!(adapter.cache_size(), 0);
    }

    #[test]
    fn test_clear_cache_allows_new_receipt() {
        let adapter = create_test_adapter();

        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        adapter.clear_cache();

        let receipt2 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        // After clearing cache, should get a new receipt with different ID
        assert_ne!(receipt1.receipt_id, receipt2.receipt_id);
    }

    #[test]
    fn test_non_mock_mode_returns_error() {
        let signer = Signer::generate();
        let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo");
        let adapter = GitHubProjectionAdapter::new(signer, config);

        assert!(!adapter.is_mock());

        // Non-mock mode should return an error until GitHub API is implemented
        let result =
            adapter.project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success);

        assert!(matches!(
            result,
            Err(ProjectionError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn test_idempotency_key_from_receipt() {
        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        let key = receipt.idempotency_key();
        assert_eq!(key.work_id, "work-001");
        assert_eq!(key.changeset_digest, [0x42; 32]);
        assert_eq!(key.ledger_head, [0xAB; 32]);
    }

    #[test]
    fn test_adapter_debug() {
        let adapter = create_test_adapter();
        let debug_str = format!("{adapter:?}");

        assert!(debug_str.contains("GitHubProjectionAdapter"));
        assert!(debug_str.contains("mock_mode: true"));
    }

    // =========================================================================
    // Domain Separator Tests
    // =========================================================================

    #[test]
    fn test_uses_projection_receipt_domain_separator() {
        use apm2_core::fac::PROJECTION_RECEIPT_PREFIX;

        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .expect("projection should succeed");

        // The receipt should use PROJECTION_RECEIPT: domain separator
        // We can verify this by checking that a signature without the prefix fails

        let canonical = receipt.canonical_bytes();

        // Create a signature without domain prefix
        let signer = Signer::generate();
        let _wrong_signature = signer.sign(&canonical);

        // Manually check that the adapter uses the correct prefix by verifying
        // that the receipt signature was created with PROJECTION_RECEIPT_PREFIX
        assert_eq!(PROJECTION_RECEIPT_PREFIX, b"PROJECTION_RECEIPT:");

        // Verify the signature is valid with the adapter's key
        assert!(receipt.validate_signature(&adapter.verifying_key()).is_ok());

        // Verify a raw signature without prefix would be different
        let expected_with_prefix = {
            let mut msg = Vec::new();
            msg.extend_from_slice(PROJECTION_RECEIPT_PREFIX);
            msg.extend_from_slice(&canonical);
            adapter.signer.sign(&msg)
        };

        // The receipt's signature should match what we'd get with the domain prefix
        assert_eq!(receipt.adapter_signature, expected_with_prefix.to_bytes());
    }
}
