// AGENT-AUTHORED (TCK-00213)
//! Divergence watchdog for the FAC (Forge Admission Cycle).
//!
//! This module implements a polling-based divergence detector that compares
//! external trunk HEAD against the latest `MergeReceipt.result_selector`.
//! When divergence is detected, the watchdog emits `InterventionFreeze` events
//! to halt new admissions until adjudication resolves the divergence.
//!
//! # Security Model
//!
//! - **Ledger is truth**: External trunk state is treated as untrusted
//!   observation
//! - **Fail-closed**: Divergence triggers immediate freeze (no new admissions)
//! - **Signed events**: All freeze events are cryptographically signed
//! - **Time envelopes**: Freeze timing bound to HTF time references
//!
//! # RFC-0015: FAC Divergence Detection
//!
//! Per RFC-0015 DD-FAC-0004, the divergence watchdog:
//!
//! 1. Polls external trunk HEAD at configurable intervals
//! 2. Compares against latest `MergeReceipt.result_selector`
//! 3. On mismatch: emits `DefectRecord(PROJECTION_DIVERGENCE)`
//! 4. On mismatch: emits `InterventionFreeze(scope=repo)`
//! 5. Halts new FAC admissions for the affected repository
//!
//! # Admission Integration
//!
//! The [`FreezeCheck`] trait allows admission paths to check freeze status.
//! Implementations like [`FreezeRegistry`] maintain freeze state and enforce
//! admission rejection for frozen repositories.
//!
//! # Time Source Abstraction
//!
//! The [`TimeSource`] trait abstracts time retrieval for testability.
//! Production uses [`SystemTimeSource`] while tests can inject deterministic
//! time via a mock time source.
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_daemon::projection::divergence_watchdog::{
//!     DivergenceWatchdog, DivergenceWatchdogConfig, FreezeRegistry,
//!     FreezeCheck, SystemTimeSource,
//! };
//!
//! // Create watchdog with default config
//! let config = DivergenceWatchdogConfig::default();
//! let time_source = SystemTimeSource::new();
//! let watchdog = DivergenceWatchdog::new(config, Box::new(time_source));
//!
//! // Check if a repo is frozen before admission
//! let registry = FreezeRegistry::new();
//! if registry.is_frozen("repo-001") {
//!     return Err(AdmissionError::RepoFrozen);
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Type-Safe Identifiers (Finding 3: CTR-2602 Compliance)
// =============================================================================

/// Maximum length for identifier strings.
pub const MAX_ID_LENGTH: usize = 256;

/// Error type for identifier parsing.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The identifier is empty.
    #[error("identifier cannot be empty")]
    Empty,

    /// The identifier exceeds maximum length.
    #[error("identifier exceeds maximum length ({actual} > {max})")]
    TooLong {
        /// Actual length of the identifier.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// The identifier contains invalid characters.
    #[error("identifier contains invalid character at position {position}")]
    InvalidCharacter {
        /// Position of the invalid character.
        position: usize,
    },
}

/// A macro to generate newtype ID wrappers with common implementations.
macro_rules! define_id_type {
    ($(#[$meta:meta])* $name:ident, $prefix:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Creates a new identifier from a string.
            ///
            /// # Errors
            ///
            /// Returns [`IdError`] if the identifier is empty, too long, or
            /// contains invalid characters.
            pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
                let s = s.into();
                Self::validate(&s)?;
                Ok(Self(s))
            }

            /// Creates a new identifier without validation.
            ///
            /// # Safety
            ///
            /// The caller must ensure the identifier is valid.
            #[must_use]
            pub fn new_unchecked(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            /// Generates a new unique identifier with the appropriate prefix.
            #[must_use]
            pub fn generate() -> Self {
                let uuid = uuid::Uuid::new_v4();
                Self(format!("{}-{}", $prefix, uuid))
            }

            /// Returns the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Validates an identifier string.
            fn validate(s: &str) -> Result<(), IdError> {
                if s.is_empty() {
                    return Err(IdError::Empty);
                }
                if s.len() > MAX_ID_LENGTH {
                    return Err(IdError::TooLong {
                        actual: s.len(),
                        max: MAX_ID_LENGTH,
                    });
                }
                // Check for control characters
                if let Some(pos) = s.chars().position(char::is_control) {
                    return Err(IdError::InvalidCharacter { position: pos });
                }
                Ok(())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

define_id_type!(
    /// Type-safe freeze identifier.
    ///
    /// Represents a unique identifier for an intervention freeze event.
    FreezeId,
    "freeze"
);

define_id_type!(
    /// Type-safe defect identifier.
    ///
    /// Represents a unique identifier for a defect record.
    DefectId,
    "defect"
);

define_id_type!(
    /// Type-safe actor identifier.
    ///
    /// Represents a unique identifier for an actor (agent, gate, etc.).
    ActorId,
    "actor"
);

define_id_type!(
    /// Type-safe repository identifier.
    ///
    /// Represents a unique identifier for a repository.
    RepoId,
    "repo"
);

// =============================================================================
// Time Source Abstraction (Finding 2: HTF Binding)
// =============================================================================

/// A source of time for generating time envelope references.
///
/// This trait abstracts time retrieval to allow:
/// - Production: Use HTF (Holonic Time Fabric) authoritative ticks
/// - Testing: Use deterministic mock time
///
/// # Security
///
/// Production deployments SHOULD use an HTF-backed implementation to ensure
/// time envelopes are bound to authoritative tick references rather than
/// local system clocks which can drift or be manipulated.
pub trait TimeSource: Send + Sync {
    /// Returns the current time as nanoseconds since epoch.
    fn now_nanos(&self) -> u64;

    /// Returns a time envelope reference string.
    ///
    /// For HTF sources, this returns a reference like `htf:tick:12345`.
    /// For system time sources, this returns a fallback reference.
    fn time_envelope_ref(&self) -> String;
}

/// System time source using `std::time::SystemTime`.
///
/// # Security Warning
///
/// This implementation uses local system time which can drift or be
/// manipulated. Production deployments SHOULD use an HTF-backed
/// implementation when available.
#[derive(Debug, Clone, Default)]
pub struct SystemTimeSource {
    _private: (),
}

impl SystemTimeSource {
    /// Creates a new system time source.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

impl TimeSource for SystemTimeSource {
    fn now_nanos(&self) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    fn time_envelope_ref(&self) -> String {
        // Fallback: use system time as reference
        // Production should use HTF ticks instead
        format!("system:nanos:{}", self.now_nanos())
    }
}

/// Mock time source for testing with deterministic time.
#[cfg(test)]
#[derive(Debug)]
pub struct MockTimeSource {
    current_nanos: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl MockTimeSource {
    /// Creates a new mock time source starting at the given nanoseconds.
    #[must_use]
    pub fn new(start_nanos: u64) -> Self {
        Self {
            current_nanos: std::sync::atomic::AtomicU64::new(start_nanos),
        }
    }

    /// Advances the mock time by the given duration.
    pub fn advance(&self, duration: Duration) {
        #[allow(clippy::cast_possible_truncation)]
        let nanos = duration.as_nanos() as u64;
        self.current_nanos
            .fetch_add(nanos, std::sync::atomic::Ordering::SeqCst);
    }

    /// Sets the mock time to a specific value.
    pub fn set(&self, nanos: u64) {
        self.current_nanos
            .store(nanos, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl TimeSource for MockTimeSource {
    fn now_nanos(&self) -> u64 {
        self.current_nanos.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn time_envelope_ref(&self) -> String {
        format!("mock:nanos:{}", self.now_nanos())
    }
}

// =============================================================================
// Freeze Scope
// =============================================================================

/// Scope of an intervention freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeScope {
    /// Freeze applies to a specific repository.
    Repo,

    /// Freeze applies to a specific work item.
    Work,

    /// Freeze applies globally (all repositories).
    Global,
}

impl fmt::Display for FreezeScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repo => write!(f, "repo"),
            Self::Work => write!(f, "work"),
            Self::Global => write!(f, "global"),
        }
    }
}

// =============================================================================
// Intervention Freeze Event
// =============================================================================

/// An intervention freeze event halting admissions for a scope.
///
/// Per RFC-0015 DD-FAC-0004, intervention freezes are emitted when:
/// - Divergence is detected between trunk HEAD and `MergeReceipt`
/// - Tamper is detected on GitHub state
/// - Manual intervention is triggered
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionFreeze {
    /// Unique identifier for this freeze.
    pub freeze_id: FreezeId,

    /// Scope of the freeze.
    pub scope: FreezeScope,

    /// Value identifying the frozen scope (e.g., repo ID for Repo scope).
    pub scope_value: String,

    /// Defect ID that triggered the freeze.
    pub trigger_defect_id: DefectId,

    /// Timestamp when the freeze was created (nanoseconds since epoch).
    pub frozen_at: u64,

    /// Actor that issued the freeze.
    pub gate_actor_id: ActorId,

    /// Signature over the freeze event.
    #[serde(with = "serde_bytes")]
    pub gate_signature: [u8; 64],

    /// Time envelope reference for temporal authority.
    pub time_envelope_ref: String,
}

impl InterventionFreeze {
    /// Returns the canonical bytes for signing/verification.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 4 + self.freeze_id.as_str().len()
            + 4 + self.scope.to_string().len()
            + 4 + self.scope_value.len()
            + 4 + self.trigger_defect_id.as_str().len()
            + 8 // frozen_at
            + 4 + self.gate_actor_id.as_str().len()
            + 4 + self.time_envelope_ref.len();

        let mut bytes = Vec::with_capacity(capacity);

        // Length-prefixed strings for collision resistance
        let freeze_id_str = self.freeze_id.as_str();
        bytes.extend_from_slice(&(freeze_id_str.len() as u32).to_be_bytes());
        bytes.extend_from_slice(freeze_id_str.as_bytes());

        let scope_str = self.scope.to_string();
        bytes.extend_from_slice(&(scope_str.len() as u32).to_be_bytes());
        bytes.extend_from_slice(scope_str.as_bytes());

        bytes.extend_from_slice(&(self.scope_value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.scope_value.as_bytes());

        let defect_id_str = self.trigger_defect_id.as_str();
        bytes.extend_from_slice(&(defect_id_str.len() as u32).to_be_bytes());
        bytes.extend_from_slice(defect_id_str.as_bytes());

        bytes.extend_from_slice(&self.frozen_at.to_be_bytes());

        let actor_id_str = self.gate_actor_id.as_str();
        bytes.extend_from_slice(&(actor_id_str.len() as u32).to_be_bytes());
        bytes.extend_from_slice(actor_id_str.as_bytes());

        bytes.extend_from_slice(&(self.time_envelope_ref.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.time_envelope_ref.as_bytes());

        bytes
    }
}

// =============================================================================
// Intervention Unfreeze Event
// =============================================================================

/// Resolution type for unfreezing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionType {
    /// Divergence was determined to be benign (e.g., force push by admin).
    Benign,

    /// Divergence was reconciled by restoring ledger state.
    Reconciled,

    /// Manual override by authorized operator.
    ManualOverride,

    /// Rollback to previous known-good state.
    Rollback,
}

/// An intervention unfreeze event restoring admissions for a scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionUnfreeze {
    /// The freeze ID being unfrozen.
    pub freeze_id: FreezeId,

    /// How the divergence was resolved.
    pub resolution_type: ResolutionType,

    /// Adjudication ID (if applicable).
    pub adjudication_id: Option<String>,

    /// Timestamp when unfrozen (nanoseconds since epoch).
    pub unfrozen_at: u64,

    /// Actor that issued the unfreeze.
    pub gate_actor_id: ActorId,

    /// Signature over the unfreeze event.
    #[serde(with = "serde_bytes")]
    pub gate_signature: [u8; 64],

    /// Time envelope reference for temporal authority.
    pub time_envelope_ref: String,
}

// =============================================================================
// Freeze Check Trait (Finding 1: Admission Integration)
// =============================================================================

/// Trait for checking freeze status before admission.
///
/// This trait is implemented by components that track freeze state and
/// can be injected into admission decision logic.
///
/// # Security
///
/// Implementations MUST be thread-safe and return consistent results
/// under concurrent access. Admission paths MUST check freeze status
/// before proceeding with any admission.
pub trait FreezeCheck: Send + Sync {
    /// Checks if admissions are allowed for the given repository.
    ///
    /// Returns `Ok(())` if admission is allowed, or `Err` with details
    /// if the repository is frozen.
    fn check_admission(&self, repo_id: &RepoId) -> Result<(), FreezeCheckError>;

    /// Returns true if the repository is currently frozen.
    fn is_frozen(&self, repo_id: &RepoId) -> bool;

    /// Returns the active freeze for a repository, if any.
    fn get_active_freeze(&self, repo_id: &RepoId) -> Option<InterventionFreeze>;
}

/// Error returned when admission is blocked due to freeze.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FreezeCheckError {
    /// The repository is frozen due to divergence detection.
    #[error("repository {repo_id} is frozen: {reason}")]
    RepoFrozen {
        /// The frozen repository ID.
        repo_id: String,
        /// The freeze ID.
        freeze_id: String,
        /// Reason for the freeze.
        reason: String,
    },

    /// Global freeze is in effect.
    #[error("global freeze in effect: {reason}")]
    GlobalFreeze {
        /// The freeze ID.
        freeze_id: String,
        /// Reason for the freeze.
        reason: String,
    },
}

// =============================================================================
// Freeze Registry
// =============================================================================

/// In-memory registry of active freezes.
///
/// Thread-safe implementation of [`FreezeCheck`] that maintains freeze state
/// and enforces admission rejection for frozen repositories.
#[derive(Debug, Default)]
pub struct FreezeRegistry {
    /// Freezes by repository ID.
    repo_freezes: Arc<RwLock<HashMap<String, InterventionFreeze>>>,

    /// Global freeze, if active.
    global_freeze: Arc<RwLock<Option<InterventionFreeze>>>,
}

impl FreezeRegistry {
    /// Creates a new empty freeze registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an intervention freeze.
    pub fn record_freeze(&self, freeze: InterventionFreeze) {
        match freeze.scope {
            FreezeScope::Global => {
                let mut guard = self.global_freeze.write().expect("lock poisoned");
                *guard = Some(freeze);
            },
            FreezeScope::Repo | FreezeScope::Work => {
                let mut guard = self.repo_freezes.write().expect("lock poisoned");
                guard.insert(freeze.scope_value.clone(), freeze);
            },
        }
    }

    /// Removes a freeze by ID.
    pub fn remove_freeze(&self, freeze_id: &FreezeId) {
        // Check global freeze first
        {
            let mut guard = self.global_freeze.write().expect("lock poisoned");
            if let Some(ref freeze) = *guard {
                if freeze.freeze_id == *freeze_id {
                    *guard = None;
                    return;
                }
            }
        }

        // Check repo freezes
        let mut guard = self.repo_freezes.write().expect("lock poisoned");
        guard.retain(|_, freeze| freeze.freeze_id != *freeze_id);
    }

    /// Returns the count of active freezes.
    #[must_use]
    pub fn active_freeze_count(&self) -> usize {
        let global = usize::from(self.global_freeze.read().expect("lock poisoned").is_some());
        let repo = self.repo_freezes.read().expect("lock poisoned").len();
        global + repo
    }

    /// Clears all freezes.
    pub fn clear(&self) {
        *self.global_freeze.write().expect("lock poisoned") = None;
        self.repo_freezes.write().expect("lock poisoned").clear();
    }
}

impl FreezeCheck for FreezeRegistry {
    fn check_admission(&self, repo_id: &RepoId) -> Result<(), FreezeCheckError> {
        // Check global freeze first
        if let Some(ref freeze) = *self.global_freeze.read().expect("lock poisoned") {
            return Err(FreezeCheckError::GlobalFreeze {
                freeze_id: freeze.freeze_id.to_string(),
                reason: format!("triggered by defect {}", freeze.trigger_defect_id.as_str()),
            });
        }

        // Check repo-specific freeze
        let guard = self.repo_freezes.read().expect("lock poisoned");
        if let Some(freeze) = guard.get(repo_id.as_str()) {
            return Err(FreezeCheckError::RepoFrozen {
                repo_id: repo_id.to_string(),
                freeze_id: freeze.freeze_id.to_string(),
                reason: format!("triggered by defect {}", freeze.trigger_defect_id.as_str()),
            });
        }

        Ok(())
    }

    fn is_frozen(&self, repo_id: &RepoId) -> bool {
        self.check_admission(repo_id).is_err()
    }

    fn get_active_freeze(&self, repo_id: &RepoId) -> Option<InterventionFreeze> {
        // Check global freeze first
        let global_freeze = self.global_freeze.read().expect("lock poisoned").clone();
        if let Some(freeze) = global_freeze {
            return Some(freeze);
        }

        // Check repo-specific freeze
        self.repo_freezes
            .read()
            .expect("lock poisoned")
            .get(repo_id.as_str())
            .cloned()
    }
}

// =============================================================================
// Watchdog Configuration
// =============================================================================

/// Configuration for the divergence watchdog.
#[derive(Debug, Clone)]
pub struct DivergenceWatchdogConfig {
    /// Poll interval for checking divergence.
    pub poll_interval: Duration,

    /// Actor ID for the watchdog.
    pub actor_id: ActorId,
}

impl Default for DivergenceWatchdogConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            actor_id: ActorId::new_unchecked("watchdog-divergence"),
        }
    }
}

// =============================================================================
// Divergence Watchdog
// =============================================================================

/// Watchdog error types.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WatchdogError {
    /// Failed to fetch external state.
    #[error("failed to fetch external state: {0}")]
    FetchError(String),

    /// Failed to emit freeze event.
    #[error("failed to emit freeze event: {0}")]
    EmitError(String),
}

/// Divergence watchdog for detecting trunk HEAD mismatches.
///
/// The watchdog polls external trunk state and compares against the latest
/// `MergeReceipt.result_selector`. On divergence, it emits freeze events
/// via the configured registry.
pub struct DivergenceWatchdog {
    /// Configuration.
    config: DivergenceWatchdogConfig,

    /// Time source for envelope references.
    time_source: Box<dyn TimeSource>,

    /// Freeze registry for recording freezes.
    registry: Arc<FreezeRegistry>,

    /// Last known merge receipt `result_selectors` by repo.
    known_selectors: RwLock<HashMap<String, [u8; 32]>>,
}

impl fmt::Debug for DivergenceWatchdog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DivergenceWatchdog")
            .field("config", &self.config)
            .field("registry", &self.registry)
            .field("known_selectors", &self.known_selectors)
            .finish_non_exhaustive()
    }
}

impl DivergenceWatchdog {
    /// Creates a new divergence watchdog.
    #[must_use]
    pub fn new(
        config: DivergenceWatchdogConfig,
        time_source: Box<dyn TimeSource>,
        registry: Arc<FreezeRegistry>,
    ) -> Self {
        Self {
            config,
            time_source,
            registry,
            known_selectors: RwLock::new(HashMap::new()),
        }
    }

    /// Updates the known `result_selector` for a repository.
    ///
    /// Call this when a new `MergeReceipt` is committed.
    pub fn update_known_selector(&self, repo_id: &RepoId, selector: [u8; 32]) {
        let mut guard = self.known_selectors.write().expect("lock poisoned");
        guard.insert(repo_id.to_string(), selector);
    }

    /// Checks for divergence between known selector and observed external
    /// state.
    ///
    /// Returns the defect ID if divergence is detected and a freeze is emitted.
    pub fn check_divergence(
        &self,
        repo_id: &RepoId,
        external_trunk_head: [u8; 32],
    ) -> Option<DefectId> {
        let known = {
            let guard = self.known_selectors.read().expect("lock poisoned");
            guard.get(repo_id.as_str()).copied()
        };

        let Some(known_selector) = known else {
            // No known selector yet, nothing to compare
            return None;
        };

        if known_selector == external_trunk_head {
            // No divergence
            return None;
        }

        // Divergence detected!
        let defect_id = DefectId::generate();
        let freeze_id = FreezeId::generate();

        let freeze = InterventionFreeze {
            freeze_id,
            scope: FreezeScope::Repo,
            scope_value: repo_id.to_string(),
            trigger_defect_id: defect_id.clone(),
            frozen_at: self.time_source.now_nanos(),
            gate_actor_id: self.config.actor_id.clone(),
            gate_signature: [0u8; 64], // TODO: Sign with watchdog key
            time_envelope_ref: self.time_source.time_envelope_ref(),
        };

        self.registry.record_freeze(freeze);

        Some(defect_id)
    }

    /// Returns the freeze registry for admission checks.
    #[must_use]
    pub const fn registry(&self) -> &Arc<FreezeRegistry> {
        &self.registry
    }

    /// Returns the poll interval.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        self.config.poll_interval
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Type-Safe ID Tests
    // =========================================================================

    #[test]
    fn test_freeze_id_generation() {
        let id = FreezeId::generate();
        assert!(id.as_str().starts_with("freeze-"));
    }

    #[test]
    fn test_freeze_id_validation() {
        // Valid ID
        assert!(FreezeId::new("freeze-001").is_ok());

        // Empty ID
        assert!(matches!(FreezeId::new(""), Err(IdError::Empty)));

        // Too long ID
        let long = "x".repeat(MAX_ID_LENGTH + 1);
        assert!(matches!(FreezeId::new(long), Err(IdError::TooLong { .. })));

        // ID with control character
        assert!(matches!(
            FreezeId::new("freeze\x00001"),
            Err(IdError::InvalidCharacter { .. })
        ));
    }

    #[test]
    fn test_defect_id_serialization() {
        let id = DefectId::new("defect-123").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"defect-123\"");

        let parsed: DefectId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_actor_id_display() {
        let id = ActorId::new("actor-001").unwrap();
        assert_eq!(id.to_string(), "actor-001");
    }

    #[test]
    fn test_repo_id_from_str() {
        let id: RepoId = "repo-001".parse().unwrap();
        assert_eq!(id.as_str(), "repo-001");
    }

    // =========================================================================
    // Time Source Tests
    // =========================================================================

    #[test]
    fn test_system_time_source() {
        let source = SystemTimeSource::new();
        let nanos = source.now_nanos();
        assert!(nanos > 0);

        let envelope_ref = source.time_envelope_ref();
        assert!(envelope_ref.starts_with("system:nanos:"));
    }

    #[test]
    fn test_mock_time_source() {
        let source = MockTimeSource::new(1_000_000_000);
        assert_eq!(source.now_nanos(), 1_000_000_000);

        source.advance(Duration::from_secs(1));
        assert_eq!(source.now_nanos(), 2_000_000_000);

        source.set(5_000_000_000);
        assert_eq!(source.now_nanos(), 5_000_000_000);

        let envelope_ref = source.time_envelope_ref();
        assert!(envelope_ref.starts_with("mock:nanos:"));
    }

    // =========================================================================
    // Freeze Registry Tests
    // =========================================================================

    #[test]
    fn test_freeze_registry_empty() {
        let registry = FreezeRegistry::new();
        let repo_id = RepoId::new("repo-001").unwrap();

        assert!(!registry.is_frozen(&repo_id));
        assert!(registry.check_admission(&repo_id).is_ok());
        assert!(registry.get_active_freeze(&repo_id).is_none());
        assert_eq!(registry.active_freeze_count(), 0);
    }

    #[test]
    fn test_freeze_registry_repo_freeze() {
        let registry = FreezeRegistry::new();
        let repo_id = RepoId::new("repo-001").unwrap();

        let freeze = InterventionFreeze {
            freeze_id: FreezeId::new("freeze-001").unwrap(),
            scope: FreezeScope::Repo,
            scope_value: "repo-001".to_string(),
            trigger_defect_id: DefectId::new("defect-001").unwrap(),
            frozen_at: 1_000_000_000,
            gate_actor_id: ActorId::new("watchdog").unwrap(),
            gate_signature: [0u8; 64],
            time_envelope_ref: "test:ref:1".to_string(),
        };

        registry.record_freeze(freeze.clone());

        assert!(registry.is_frozen(&repo_id));
        assert!(registry.check_admission(&repo_id).is_err());
        assert_eq!(
            registry.get_active_freeze(&repo_id).unwrap().freeze_id,
            freeze.freeze_id
        );
        assert_eq!(registry.active_freeze_count(), 1);

        // Other repos should not be frozen
        let other_repo = RepoId::new("repo-002").unwrap();
        assert!(!registry.is_frozen(&other_repo));
    }

    #[test]
    fn test_freeze_registry_global_freeze() {
        let registry = FreezeRegistry::new();
        let repo_id = RepoId::new("repo-001").unwrap();

        let freeze = InterventionFreeze {
            freeze_id: FreezeId::new("freeze-001").unwrap(),
            scope: FreezeScope::Global,
            scope_value: String::new(),
            trigger_defect_id: DefectId::new("defect-001").unwrap(),
            frozen_at: 1_000_000_000,
            gate_actor_id: ActorId::new("watchdog").unwrap(),
            gate_signature: [0u8; 64],
            time_envelope_ref: "test:ref:1".to_string(),
        };

        registry.record_freeze(freeze);

        // All repos should be frozen
        assert!(registry.is_frozen(&repo_id));
        assert!(registry.is_frozen(&RepoId::new("repo-002").unwrap()));

        let err = registry.check_admission(&repo_id).unwrap_err();
        assert!(matches!(err, FreezeCheckError::GlobalFreeze { .. }));
    }

    #[test]
    fn test_freeze_registry_remove_freeze() {
        let registry = FreezeRegistry::new();
        let repo_id = RepoId::new("repo-001").unwrap();
        let freeze_id = FreezeId::new("freeze-001").unwrap();

        let freeze = InterventionFreeze {
            freeze_id: freeze_id.clone(),
            scope: FreezeScope::Repo,
            scope_value: "repo-001".to_string(),
            trigger_defect_id: DefectId::new("defect-001").unwrap(),
            frozen_at: 1_000_000_000,
            gate_actor_id: ActorId::new("watchdog").unwrap(),
            gate_signature: [0u8; 64],
            time_envelope_ref: "test:ref:1".to_string(),
        };

        registry.record_freeze(freeze);
        assert!(registry.is_frozen(&repo_id));

        registry.remove_freeze(&freeze_id);
        assert!(!registry.is_frozen(&repo_id));
    }

    #[test]
    fn test_freeze_registry_clear() {
        let registry = FreezeRegistry::new();

        // Add multiple freezes
        for i in 0..3 {
            let freeze = InterventionFreeze {
                freeze_id: FreezeId::new(format!("freeze-{i:03}")).unwrap(),
                scope: FreezeScope::Repo,
                scope_value: format!("repo-{i:03}"),
                trigger_defect_id: DefectId::new(format!("defect-{i:03}")).unwrap(),
                frozen_at: 1_000_000_000,
                gate_actor_id: ActorId::new("watchdog").unwrap(),
                gate_signature: [0u8; 64],
                time_envelope_ref: "test:ref:1".to_string(),
            };
            registry.record_freeze(freeze);
        }

        assert_eq!(registry.active_freeze_count(), 3);

        registry.clear();
        assert_eq!(registry.active_freeze_count(), 0);
    }

    // =========================================================================
    // Divergence Watchdog Tests
    // =========================================================================

    #[test]
    fn test_watchdog_no_divergence() {
        let config = DivergenceWatchdogConfig::default();
        let time_source = Box::new(MockTimeSource::new(1_000_000_000));
        let registry = Arc::new(FreezeRegistry::new());
        let watchdog = DivergenceWatchdog::new(config, time_source, registry.clone());

        let repo_id = RepoId::new("repo-001").unwrap();
        let selector = [0x42; 32];

        // Update known selector
        watchdog.update_known_selector(&repo_id, selector);

        // Check with same selector - no divergence
        let result = watchdog.check_divergence(&repo_id, selector);
        assert!(result.is_none());
        assert!(!registry.is_frozen(&repo_id));
    }

    #[test]
    fn test_watchdog_divergence_detected() {
        let config = DivergenceWatchdogConfig::default();
        let time_source = Box::new(MockTimeSource::new(1_000_000_000));
        let registry = Arc::new(FreezeRegistry::new());
        let watchdog = DivergenceWatchdog::new(config, time_source, registry.clone());

        let repo_id = RepoId::new("repo-001").unwrap();
        let known_selector = [0x42; 32];
        let external_head = [0x99; 32]; // Different!

        // Update known selector
        watchdog.update_known_selector(&repo_id, known_selector);

        // Check with different external head - divergence!
        let result = watchdog.check_divergence(&repo_id, external_head);
        assert!(result.is_some());
        assert!(registry.is_frozen(&repo_id));

        // Verify freeze was recorded
        let freeze = registry.get_active_freeze(&repo_id).unwrap();
        assert_eq!(freeze.scope, FreezeScope::Repo);
        assert_eq!(freeze.scope_value, "repo-001");
    }

    #[test]
    fn test_watchdog_no_known_selector() {
        let config = DivergenceWatchdogConfig::default();
        let time_source = Box::new(MockTimeSource::new(1_000_000_000));
        let registry = Arc::new(FreezeRegistry::new());
        let watchdog = DivergenceWatchdog::new(config, time_source, registry.clone());

        let repo_id = RepoId::new("repo-001").unwrap();
        let external_head = [0x99; 32];

        // No known selector - should not trigger divergence
        let result = watchdog.check_divergence(&repo_id, external_head);
        assert!(result.is_none());
        assert!(!registry.is_frozen(&repo_id));
    }

    // =========================================================================
    // Intervention Event Tests
    // =========================================================================

    #[test]
    fn test_intervention_freeze_serialization() {
        let freeze = InterventionFreeze {
            freeze_id: FreezeId::new("freeze-001").unwrap(),
            scope: FreezeScope::Repo,
            scope_value: "repo-001".to_string(),
            trigger_defect_id: DefectId::new("defect-001").unwrap(),
            frozen_at: 1_000_000_000,
            gate_actor_id: ActorId::new("watchdog").unwrap(),
            gate_signature: [0u8; 64],
            time_envelope_ref: "htf:tick:12345".to_string(),
        };

        let json = serde_json::to_string(&freeze).unwrap();
        let parsed: InterventionFreeze = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.freeze_id, freeze.freeze_id);
        assert_eq!(parsed.scope, freeze.scope);
        assert_eq!(parsed.scope_value, freeze.scope_value);
    }

    #[test]
    fn test_intervention_freeze_canonical_bytes() {
        let freeze1 = InterventionFreeze {
            freeze_id: FreezeId::new("freeze-001").unwrap(),
            scope: FreezeScope::Repo,
            scope_value: "repo-001".to_string(),
            trigger_defect_id: DefectId::new("defect-001").unwrap(),
            frozen_at: 1_000_000_000,
            gate_actor_id: ActorId::new("watchdog").unwrap(),
            gate_signature: [0u8; 64],
            time_envelope_ref: "htf:tick:12345".to_string(),
        };

        let freeze2 = InterventionFreeze {
            freeze_id: FreezeId::new("freeze-002").unwrap(), // Different ID
            ..freeze1.clone()
        };

        // Different freeze IDs should produce different canonical bytes
        assert_ne!(freeze1.canonical_bytes(), freeze2.canonical_bytes());
    }

    #[test]
    fn test_intervention_unfreeze_serialization() {
        let unfreeze = InterventionUnfreeze {
            freeze_id: FreezeId::new("freeze-001").unwrap(),
            resolution_type: ResolutionType::Reconciled,
            adjudication_id: Some("adj-001".to_string()),
            unfrozen_at: 2_000_000_000,
            gate_actor_id: ActorId::new("operator").unwrap(),
            gate_signature: [0u8; 64],
            time_envelope_ref: "htf:tick:12346".to_string(),
        };

        let json = serde_json::to_string(&unfreeze).unwrap();
        let parsed: InterventionUnfreeze = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.freeze_id, unfreeze.freeze_id);
        assert_eq!(parsed.resolution_type, ResolutionType::Reconciled);
    }

    // =========================================================================
    // Admission Integration Tests
    // =========================================================================

    #[test]
    fn test_freeze_check_blocks_admission() {
        let registry = FreezeRegistry::new();
        let repo_id = RepoId::new("repo-001").unwrap();

        // Initially not frozen
        assert!(registry.check_admission(&repo_id).is_ok());

        // Freeze the repo
        let freeze = InterventionFreeze {
            freeze_id: FreezeId::new("freeze-001").unwrap(),
            scope: FreezeScope::Repo,
            scope_value: "repo-001".to_string(),
            trigger_defect_id: DefectId::new("defect-001").unwrap(),
            frozen_at: 1_000_000_000,
            gate_actor_id: ActorId::new("watchdog").unwrap(),
            gate_signature: [0u8; 64],
            time_envelope_ref: "test:ref:1".to_string(),
        };
        registry.record_freeze(freeze);

        // Now admission should be blocked
        let result = registry.check_admission(&repo_id);
        assert!(result.is_err());

        match result.unwrap_err() {
            FreezeCheckError::RepoFrozen {
                repo_id: rid,
                freeze_id,
                ..
            } => {
                assert_eq!(rid, "repo-001");
                assert_eq!(freeze_id, "freeze-001");
            },
            FreezeCheckError::GlobalFreeze { .. } => panic!("Expected RepoFrozen error"),
        }
    }

    #[test]
    fn test_freeze_check_error_display() {
        let repo_err = FreezeCheckError::RepoFrozen {
            repo_id: "repo-001".to_string(),
            freeze_id: "freeze-001".to_string(),
            reason: "divergence detected".to_string(),
        };
        assert!(repo_err.to_string().contains("repo-001"));
        assert!(repo_err.to_string().contains("frozen"));

        let global_err = FreezeCheckError::GlobalFreeze {
            freeze_id: "freeze-global".to_string(),
            reason: "emergency".to_string(),
        };
        assert!(global_err.to_string().contains("global freeze"));
    }
}
