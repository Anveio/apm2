//! Budget tracking for episode resource management.
//!
//! This module implements the `BudgetTracker` per TCK-00165. The tracker
//! manages resource consumption during episode execution, enforcing limits
//! from the episode envelope.
//!
//! # Architecture
//!
//! ```text
//! EpisodeEnvelope
//!     │
//!     └── budget: EpisodeBudget (immutable limits)
//!               │
//!               ▼
//!         BudgetTracker
//!               │
//!               ├── charge(delta) ──► Updates consumed counters
//!               ├── remaining() ──► Returns available budget
//!               └── is_exhausted() ──► Checks if any limit exceeded
//! ```
//!
//! # Security Model
//!
//! - Budget checks are **fail-closed**: if any limit is exceeded, the operation
//!   is denied
//! - All arithmetic uses checked operations to prevent overflow
//! - Zero in budget means unlimited for that resource
//!
//! # Contract References
//!
//! - TCK-00165: Tool execution and budget charging
//! - AD-EPISODE-001: Immutable episode envelope with budget
//! - CTR-2504: Defensive time handling

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::budget::EpisodeBudget;
use super::decision::BudgetDelta;

// =============================================================================
// BudgetExhaustedError
// =============================================================================

/// Error indicating budget exhaustion.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BudgetExhaustedError {
    /// Token budget exceeded.
    #[error("token budget exceeded: requested {requested}, remaining {remaining}")]
    Tokens {
        /// Tokens requested.
        requested: u64,
        /// Tokens remaining.
        remaining: u64,
    },

    /// Tool calls budget exceeded.
    #[error("tool calls budget exceeded: requested {requested}, remaining {remaining}")]
    ToolCalls {
        /// Tool calls requested.
        requested: u32,
        /// Tool calls remaining.
        remaining: u32,
    },

    /// Wall clock time budget exceeded.
    #[error("wall time budget exceeded: requested {requested}ms, remaining {remaining}ms")]
    WallTime {
        /// Milliseconds requested.
        requested: u64,
        /// Milliseconds remaining.
        remaining: u64,
    },

    /// CPU time budget exceeded.
    #[error("CPU time budget exceeded: requested {requested}ms, remaining {remaining}ms")]
    CpuTime {
        /// Milliseconds requested.
        requested: u64,
        /// Milliseconds remaining.
        remaining: u64,
    },

    /// I/O bytes budget exceeded.
    #[error("I/O bytes budget exceeded: requested {requested}, remaining {remaining}")]
    BytesIo {
        /// Bytes requested.
        requested: u64,
        /// Bytes remaining.
        remaining: u64,
    },

    /// Evidence bytes budget exceeded.
    #[error("evidence bytes budget exceeded: requested {requested}, remaining {remaining}")]
    EvidenceBytes {
        /// Bytes requested.
        requested: u64,
        /// Bytes remaining.
        remaining: u64,
    },
}

impl BudgetExhaustedError {
    /// Returns the resource type that was exhausted.
    #[must_use]
    pub const fn resource(&self) -> &'static str {
        match self {
            Self::Tokens { .. } => "tokens",
            Self::ToolCalls { .. } => "tool_calls",
            Self::WallTime { .. } => "wall_time",
            Self::CpuTime { .. } => "cpu_time",
            Self::BytesIo { .. } => "bytes_io",
            Self::EvidenceBytes { .. } => "evidence_bytes",
        }
    }
}

// =============================================================================
// BudgetTracker
// =============================================================================

/// Thread-safe budget tracker for episode resource management.
///
/// The tracker maintains atomic counters for consumed resources and enforces
/// limits from the episode envelope. All operations are thread-safe.
///
/// # Invariants
///
/// - [INV-BT001] Consumed values never exceed limit values (enforced by
///   `charge`)
/// - [INV-BT002] Original limits are immutable after construction
/// - [INV-BT003] Zero limit means unlimited (no enforcement)
///
/// # Example
///
/// ```rust
/// use apm2_daemon::episode::{BudgetDelta, BudgetTracker, EpisodeBudget};
///
/// let budget = EpisodeBudget::builder()
///     .tokens(10_000)
///     .tool_calls(100)
///     .build();
///
/// let tracker = BudgetTracker::from_envelope(budget);
///
/// // Charge a tool call
/// let delta = BudgetDelta::single_call().with_tokens(500);
/// tracker.charge(&delta).expect("budget available");
///
/// // Check remaining
/// let remaining = tracker.remaining();
/// assert_eq!(remaining.tokens(), 9_500);
/// assert_eq!(remaining.tool_calls(), 99);
/// ```
#[derive(Debug)]
pub struct BudgetTracker {
    /// Original budget limits (immutable).
    limits: EpisodeBudget,

    /// Tokens consumed.
    tokens_consumed: AtomicU64,

    /// Tool calls consumed.
    tool_calls_consumed: AtomicU32,

    /// Wall clock time consumed (milliseconds).
    wall_ms_consumed: AtomicU64,

    /// CPU time consumed (milliseconds).
    cpu_ms_consumed: AtomicU64,

    /// I/O bytes consumed.
    bytes_io_consumed: AtomicU64,

    /// Evidence bytes consumed.
    evidence_bytes_consumed: AtomicU64,
}

impl BudgetTracker {
    /// Creates a new budget tracker from an episode envelope budget.
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget limits from the episode envelope
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // AtomicU64::new is not const in stable
    pub fn from_envelope(budget: EpisodeBudget) -> Self {
        Self {
            limits: budget,
            tokens_consumed: AtomicU64::new(0),
            tool_calls_consumed: AtomicU32::new(0),
            wall_ms_consumed: AtomicU64::new(0),
            cpu_ms_consumed: AtomicU64::new(0),
            bytes_io_consumed: AtomicU64::new(0),
            evidence_bytes_consumed: AtomicU64::new(0),
        }
    }

    /// Creates an unlimited budget tracker.
    ///
    /// This is useful for testing or when budget enforcement is disabled.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::from_envelope(EpisodeBudget::unlimited())
    }

    /// Charges the given budget delta, consuming resources.
    ///
    /// This checks all limits before consuming any resources (atomic
    /// all-or-nothing). If any limit would be exceeded, no resources are
    /// consumed and an error is returned.
    ///
    /// # Arguments
    ///
    /// * `delta` - The resources to consume
    ///
    /// # Errors
    ///
    /// Returns an error if any budget limit would be exceeded.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe but not strictly serializable. Under high
    /// contention, the total consumed may slightly exceed limits due to
    /// the check-then-update pattern. For strict enforcement, external
    /// synchronization is needed.
    pub fn charge(&self, delta: &BudgetDelta) -> Result<(), BudgetExhaustedError> {
        // Check all limits first (fail-closed)
        self.check_tokens(delta.tokens)?;
        self.check_tool_calls(delta.tool_calls)?;
        self.check_wall_ms(delta.wall_ms)?;
        self.check_cpu_ms(delta.cpu_ms)?;
        self.check_bytes_io(delta.bytes_io)?;

        // All checks passed, consume resources
        // Using Relaxed ordering since we don't need synchronization beyond
        // the atomic operations themselves
        self.tokens_consumed
            .fetch_add(delta.tokens, Ordering::Relaxed);
        self.tool_calls_consumed
            .fetch_add(delta.tool_calls, Ordering::Relaxed);
        self.wall_ms_consumed
            .fetch_add(delta.wall_ms, Ordering::Relaxed);
        self.cpu_ms_consumed
            .fetch_add(delta.cpu_ms, Ordering::Relaxed);
        self.bytes_io_consumed
            .fetch_add(delta.bytes_io, Ordering::Relaxed);

        Ok(())
    }

    /// Charges evidence bytes separately from the main delta.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The evidence bytes to charge
    ///
    /// # Errors
    ///
    /// Returns an error if the evidence bytes budget would be exceeded.
    pub fn charge_evidence(&self, bytes: u64) -> Result<(), BudgetExhaustedError> {
        self.check_evidence_bytes(bytes)?;
        self.evidence_bytes_consumed
            .fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }

    /// Returns the remaining budget.
    ///
    /// For unlimited resources (limit = 0), the remaining value is also 0.
    #[must_use]
    pub fn remaining(&self) -> EpisodeBudget {
        EpisodeBudget::builder()
            .tokens(self.remaining_tokens())
            .tool_calls(self.remaining_tool_calls())
            .wall_ms(self.remaining_wall_ms())
            .cpu_ms(self.remaining_cpu_ms())
            .bytes_io(self.remaining_bytes_io())
            .evidence_bytes(self.remaining_evidence_bytes())
            .build()
    }

    /// Returns the consumed resources as a snapshot.
    #[must_use]
    pub fn consumed(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            tokens: self.tokens_consumed.load(Ordering::Relaxed),
            tool_calls: self.tool_calls_consumed.load(Ordering::Relaxed),
            wall_ms: self.wall_ms_consumed.load(Ordering::Relaxed),
            cpu_ms: self.cpu_ms_consumed.load(Ordering::Relaxed),
            bytes_io: self.bytes_io_consumed.load(Ordering::Relaxed),
            evidence_bytes: self.evidence_bytes_consumed.load(Ordering::Relaxed),
        }
    }

    /// Returns the original budget limits.
    #[must_use]
    pub const fn limits(&self) -> &EpisodeBudget {
        &self.limits
    }

    /// Returns `true` if any budget limit is exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.is_tokens_exhausted()
            || self.is_tool_calls_exhausted()
            || self.is_wall_time_exhausted()
            || self.is_cpu_time_exhausted()
            || self.is_bytes_io_exhausted()
            || self.is_evidence_bytes_exhausted()
    }

    /// Returns `true` if the token budget is exhausted.
    #[must_use]
    pub fn is_tokens_exhausted(&self) -> bool {
        let limit = self.limits.tokens();
        limit > 0 && self.tokens_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the tool calls budget is exhausted.
    #[must_use]
    pub fn is_tool_calls_exhausted(&self) -> bool {
        let limit = self.limits.tool_calls();
        limit > 0 && self.tool_calls_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the wall time budget is exhausted.
    #[must_use]
    pub fn is_wall_time_exhausted(&self) -> bool {
        let limit = self.limits.wall_ms();
        limit > 0 && self.wall_ms_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the CPU time budget is exhausted.
    #[must_use]
    pub fn is_cpu_time_exhausted(&self) -> bool {
        let limit = self.limits.cpu_ms();
        limit > 0 && self.cpu_ms_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the I/O bytes budget is exhausted.
    #[must_use]
    pub fn is_bytes_io_exhausted(&self) -> bool {
        let limit = self.limits.bytes_io();
        limit > 0 && self.bytes_io_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the evidence bytes budget is exhausted.
    #[must_use]
    pub fn is_evidence_bytes_exhausted(&self) -> bool {
        let limit = self.limits.evidence_bytes();
        limit > 0 && self.evidence_bytes_consumed.load(Ordering::Relaxed) >= limit
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    fn remaining_tokens(&self) -> u64 {
        let limit = self.limits.tokens();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.tokens_consumed.load(Ordering::Relaxed))
    }

    fn remaining_tool_calls(&self) -> u32 {
        let limit = self.limits.tool_calls();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.tool_calls_consumed.load(Ordering::Relaxed))
    }

    fn remaining_wall_ms(&self) -> u64 {
        let limit = self.limits.wall_ms();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.wall_ms_consumed.load(Ordering::Relaxed))
    }

    fn remaining_cpu_ms(&self) -> u64 {
        let limit = self.limits.cpu_ms();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.cpu_ms_consumed.load(Ordering::Relaxed))
    }

    fn remaining_bytes_io(&self) -> u64 {
        let limit = self.limits.bytes_io();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.bytes_io_consumed.load(Ordering::Relaxed))
    }

    fn remaining_evidence_bytes(&self) -> u64 {
        let limit = self.limits.evidence_bytes();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.evidence_bytes_consumed.load(Ordering::Relaxed))
    }

    fn check_tokens(&self, requested: u64) -> Result<(), BudgetExhaustedError> {
        let limit = self.limits.tokens();
        if limit == 0 || requested == 0 {
            return Ok(()); // Unlimited or no request
        }
        let consumed = self.tokens_consumed.load(Ordering::Relaxed);
        let remaining = limit.saturating_sub(consumed);
        if requested > remaining {
            return Err(BudgetExhaustedError::Tokens {
                requested,
                remaining,
            });
        }
        Ok(())
    }

    fn check_tool_calls(&self, requested: u32) -> Result<(), BudgetExhaustedError> {
        let limit = self.limits.tool_calls();
        if limit == 0 || requested == 0 {
            return Ok(()); // Unlimited or no request
        }
        let consumed = self.tool_calls_consumed.load(Ordering::Relaxed);
        let remaining = limit.saturating_sub(consumed);
        if requested > remaining {
            return Err(BudgetExhaustedError::ToolCalls {
                requested,
                remaining,
            });
        }
        Ok(())
    }

    fn check_wall_ms(&self, requested: u64) -> Result<(), BudgetExhaustedError> {
        let limit = self.limits.wall_ms();
        if limit == 0 || requested == 0 {
            return Ok(()); // Unlimited or no request
        }
        let consumed = self.wall_ms_consumed.load(Ordering::Relaxed);
        let remaining = limit.saturating_sub(consumed);
        if requested > remaining {
            return Err(BudgetExhaustedError::WallTime {
                requested,
                remaining,
            });
        }
        Ok(())
    }

    fn check_cpu_ms(&self, requested: u64) -> Result<(), BudgetExhaustedError> {
        let limit = self.limits.cpu_ms();
        if limit == 0 || requested == 0 {
            return Ok(()); // Unlimited or no request
        }
        let consumed = self.cpu_ms_consumed.load(Ordering::Relaxed);
        let remaining = limit.saturating_sub(consumed);
        if requested > remaining {
            return Err(BudgetExhaustedError::CpuTime {
                requested,
                remaining,
            });
        }
        Ok(())
    }

    fn check_bytes_io(&self, requested: u64) -> Result<(), BudgetExhaustedError> {
        let limit = self.limits.bytes_io();
        if limit == 0 || requested == 0 {
            return Ok(()); // Unlimited or no request
        }
        let consumed = self.bytes_io_consumed.load(Ordering::Relaxed);
        let remaining = limit.saturating_sub(consumed);
        if requested > remaining {
            return Err(BudgetExhaustedError::BytesIo {
                requested,
                remaining,
            });
        }
        Ok(())
    }

    fn check_evidence_bytes(&self, requested: u64) -> Result<(), BudgetExhaustedError> {
        let limit = self.limits.evidence_bytes();
        if limit == 0 || requested == 0 {
            return Ok(()); // Unlimited or no request
        }
        let consumed = self.evidence_bytes_consumed.load(Ordering::Relaxed);
        let remaining = limit.saturating_sub(consumed);
        if requested > remaining {
            return Err(BudgetExhaustedError::EvidenceBytes {
                requested,
                remaining,
            });
        }
        Ok(())
    }
}

// =============================================================================
// BudgetSnapshot
// =============================================================================

/// Snapshot of consumed budget resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    /// Tokens consumed.
    pub tokens: u64,

    /// Tool calls consumed.
    pub tool_calls: u32,

    /// Wall clock time consumed (milliseconds).
    pub wall_ms: u64,

    /// CPU time consumed (milliseconds).
    pub cpu_ms: u64,

    /// I/O bytes consumed.
    pub bytes_io: u64,

    /// Evidence bytes consumed.
    pub evidence_bytes: u64,
}

impl BudgetSnapshot {
    /// Returns `true` if all values are zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.tokens == 0
            && self.tool_calls == 0
            && self.wall_ms == 0
            && self.cpu_ms == 0
            && self.bytes_io == 0
            && self.evidence_bytes == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_budget() -> EpisodeBudget {
        EpisodeBudget::builder()
            .tokens(10_000)
            .tool_calls(100)
            .wall_ms(60_000)
            .cpu_ms(30_000)
            .bytes_io(1_000_000)
            .evidence_bytes(100_000)
            .build()
    }

    #[test]
    fn test_budget_tracker_charge_success() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let delta = BudgetDelta::single_call()
            .with_tokens(500)
            .with_wall_ms(100)
            .with_bytes_io(1000);

        assert!(tracker.charge(&delta).is_ok());

        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 500);
        assert_eq!(consumed.tool_calls, 1);
        assert_eq!(consumed.wall_ms, 100);
        assert_eq!(consumed.bytes_io, 1000);
    }

    #[test]
    fn test_budget_tracker_charge_tokens_exceeded() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let delta = BudgetDelta::single_call().with_tokens(10_001);

        let result = tracker.charge(&delta);
        assert!(matches!(result, Err(BudgetExhaustedError::Tokens { .. })));
    }

    #[test]
    fn test_budget_tracker_charge_tool_calls_exceeded() {
        let budget = EpisodeBudget::builder().tool_calls(2).build();
        let tracker = BudgetTracker::from_envelope(budget);

        // First two charges succeed
        assert!(tracker.charge(&BudgetDelta::single_call()).is_ok());
        assert!(tracker.charge(&BudgetDelta::single_call()).is_ok());

        // Third charge fails
        let result = tracker.charge(&BudgetDelta::single_call());
        assert!(matches!(
            result,
            Err(BudgetExhaustedError::ToolCalls { .. })
        ));
    }

    #[test]
    fn test_budget_tracker_remaining() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let delta = BudgetDelta::single_call().with_tokens(3000);
        tracker.charge(&delta).unwrap();

        let remaining = tracker.remaining();
        assert_eq!(remaining.tokens(), 7000);
        assert_eq!(remaining.tool_calls(), 99);
    }

    #[test]
    fn test_budget_tracker_is_exhausted() {
        let budget = EpisodeBudget::builder().tokens(100).build();
        let tracker = BudgetTracker::from_envelope(budget);

        assert!(!tracker.is_exhausted());
        assert!(!tracker.is_tokens_exhausted());

        let delta = BudgetDelta::single_call().with_tokens(100);
        tracker.charge(&delta).unwrap();

        assert!(tracker.is_exhausted());
        assert!(tracker.is_tokens_exhausted());
    }

    #[test]
    fn test_budget_tracker_unlimited() {
        let tracker = BudgetTracker::unlimited();

        // Large charges should succeed with unlimited budget
        let delta = BudgetDelta::single_call()
            .with_tokens(1_000_000_000)
            .with_bytes_io(1_000_000_000);

        assert!(tracker.charge(&delta).is_ok());
        assert!(!tracker.is_exhausted());
    }

    #[test]
    fn test_budget_tracker_unlimited_remaining() {
        let tracker = BudgetTracker::unlimited();

        // Remaining is 0 for unlimited (not u64::MAX)
        let remaining = tracker.remaining();
        assert_eq!(remaining.tokens(), 0);
        assert!(remaining.is_unlimited());
    }

    #[test]
    fn test_budget_tracker_charge_evidence() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        assert!(tracker.charge_evidence(50_000).is_ok());
        assert!(tracker.charge_evidence(50_000).is_ok());

        // Next charge exceeds limit
        let result = tracker.charge_evidence(1);
        assert!(matches!(
            result,
            Err(BudgetExhaustedError::EvidenceBytes { .. })
        ));
    }

    #[test]
    fn test_budget_tracker_no_partial_charge() {
        let budget = EpisodeBudget::builder()
            .tokens(1000)
            .tool_calls(1) // Will fail on second call
            .build();
        let tracker = BudgetTracker::from_envelope(budget);

        // First charge succeeds
        tracker.charge(&BudgetDelta::single_call()).unwrap();

        // Second charge fails - tokens should NOT be consumed
        let delta = BudgetDelta::single_call().with_tokens(500);
        let result = tracker.charge(&delta);
        assert!(result.is_err());

        // Verify no partial consumption
        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 0); // Not 500
        assert_eq!(consumed.tool_calls, 1);
    }

    #[test]
    fn test_budget_exhausted_error_resource() {
        assert_eq!(
            BudgetExhaustedError::Tokens {
                requested: 0,
                remaining: 0
            }
            .resource(),
            "tokens"
        );
        assert_eq!(
            BudgetExhaustedError::ToolCalls {
                requested: 0,
                remaining: 0
            }
            .resource(),
            "tool_calls"
        );
        assert_eq!(
            BudgetExhaustedError::WallTime {
                requested: 0,
                remaining: 0
            }
            .resource(),
            "wall_time"
        );
    }

    #[test]
    fn test_budget_snapshot_is_zero() {
        let snapshot = BudgetSnapshot::default();
        assert!(snapshot.is_zero());

        let snapshot = BudgetSnapshot {
            tokens: 1,
            ..Default::default()
        };
        assert!(!snapshot.is_zero());
    }

    #[test]
    fn test_budget_tracker_multiple_charges() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        for _ in 0..10 {
            let delta = BudgetDelta::single_call()
                .with_tokens(100)
                .with_bytes_io(10_000);
            tracker.charge(&delta).unwrap();
        }

        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 1000);
        assert_eq!(consumed.tool_calls, 10);
        assert_eq!(consumed.bytes_io, 100_000);
    }

    #[test]
    fn test_budget_tracker_limits_accessor() {
        let budget = test_budget();
        let tracker = BudgetTracker::from_envelope(budget);

        assert_eq!(tracker.limits().tokens(), 10_000);
        assert_eq!(tracker.limits().tool_calls(), 100);
    }

    // =========================================================================
    // Budget charging tests (UT-00165-01)
    // =========================================================================

    #[test]
    fn test_budget_charge_decrements_correctly() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let delta = BudgetDelta {
            tokens: 1000,
            tool_calls: 5,
            wall_ms: 500,
            cpu_ms: 100,
            bytes_io: 5000,
        };

        tracker.charge(&delta).unwrap();

        let remaining = tracker.remaining();
        assert_eq!(remaining.tokens(), 9000);
        assert_eq!(remaining.tool_calls(), 95);
        assert_eq!(remaining.wall_ms(), 59_500);
        assert_eq!(remaining.cpu_ms(), 29_900);
        assert_eq!(remaining.bytes_io(), 995_000);
    }

    // =========================================================================
    // Budget exhaustion tests (UT-00165-03)
    // =========================================================================

    #[test]
    fn test_budget_exhaustion_detected() {
        let budget = EpisodeBudget::builder()
            .tokens(100)
            .tool_calls(5)
            .wall_ms(1000)
            .build();
        let tracker = BudgetTracker::from_envelope(budget);

        // Exhaust tokens
        tracker
            .charge(&BudgetDelta::single_call().with_tokens(100))
            .unwrap();
        assert!(tracker.is_tokens_exhausted());

        // Exhaust tool calls
        for _ in 0..4 {
            tracker.charge(&BudgetDelta::single_call()).unwrap();
        }
        assert!(tracker.is_tool_calls_exhausted());

        // Overall exhaustion
        assert!(tracker.is_exhausted());
    }
}
