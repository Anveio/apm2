//! Raw adapter implementation.
//!
//! The [`RawAdapter`] is a baseline adapter that spawns processes and emits
//! all PTY output as raw [`HarnessEvent::Output`] events without any parsing.
//!
//! # Behavior
//!
//! - Spawns processes using PTY (pseudo-terminal) for proper terminal emulation
//! - Emits all output as `Output` events with `OutputKind::Combined`
//! - Does not parse tool calls or structured events
//! - Forwards termination status directly
//!
//! # Resource Bounds
//!
//! The adapter enforces a maximum of [`MAX_CONCURRENT_ADAPTERS`] concurrent
//! spawned processes to prevent resource exhaustion. If this limit is reached,
//! [`spawn`](RawAdapter::spawn) will return an error.
//!
//! # Holon Implementation
//!
//! Per AD-LAYER-001 and AD-ADAPT-001, `RawAdapter` implements the [`Holon`]
//! trait for holonic coordination:
//!
//! - `Input`: [`HarnessConfig`] - Configuration for spawning
//! - `Output`: [`RawAdapterOutput`] - Exit status and output count
//! - `State`: [`RawAdapterState`] - Current adapter state
//!
//! This adapter is useful for:
//! - Running arbitrary shell commands
//! - Testing and debugging harness infrastructure
//! - Processes that don't have structured output formats

use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use apm2_holon::{Artifact, EpisodeContext, EpisodeResult, Holon, HolonError, StopCondition};
use tokio::sync::Semaphore;

use super::adapter::{
    AdapterError, AdapterResult, AdapterType, HarnessAdapter, HarnessConfig, HarnessEvent,
    HarnessEventStream, HarnessHandle, HarnessHandleInner, OutputKind, TerminationClassification,
};
use super::pty::{PtyConfig, PtyRunner};

/// Counter for generating unique handle IDs.
static HANDLE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Maximum number of concurrent adapter instances allowed.
///
/// This limit prevents resource exhaustion from spawning too many processes.
/// The limit is intentionally conservative to account for system resources
/// like file descriptors, memory, and CPU time.
///
/// Each spawned process consumes:
/// - At least 3 file descriptors (stdin, stdout, stderr / PTY)
/// - Memory for the process and its buffers
/// - A tokio task for event handling
///
/// With this limit, the maximum file descriptor usage is approximately
/// 100 * 3 = 300 FDs, well within typical system limits.
pub const MAX_CONCURRENT_ADAPTERS: usize = 100;

/// Output produced by the `RawAdapter` when used as a Holon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAdapterOutput {
    /// Exit code from the process, if available.
    pub exit_code: Option<i32>,
    /// Number of output events emitted.
    pub output_event_count: u64,
    /// Whether the process terminated successfully.
    pub success: bool,
}

/// State of the `RawAdapter` when used as a Holon.
#[derive(Debug, Clone, Default)]
pub struct RawAdapterState {
    /// Current episode ID being processed.
    pub episode_id: Option<String>,
    /// Number of output events received in current episode.
    pub output_event_count: u64,
    /// Whether intake has been called.
    pub intake_called: bool,
    /// Last exit code, if process has terminated.
    pub last_exit_code: Option<i32>,
}

/// Raw adapter that emits unstructured output.
///
/// This adapter spawns processes and emits all PTY output as raw events.
/// It does not parse tool calls or structured events.
///
/// # Resource Bounds
///
/// The adapter tracks spawned tasks and enforces [`MAX_CONCURRENT_ADAPTERS`]
/// as the maximum number of concurrent processes. When this limit is reached,
/// [`spawn`](RawAdapter::spawn) returns
/// [`AdapterError::ResourceLimitExceeded`].
///
/// # Holon Implementation
///
/// Per AD-LAYER-001, `RawAdapter` implements the Holon trait:
/// - `Input = HarnessConfig`
/// - `Output = RawAdapterOutput`
/// - `State = RawAdapterState`
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::raw_adapter::RawAdapter;
/// use apm2_daemon::episode::adapter::{HarnessConfig, HarnessAdapter};
///
/// let adapter = RawAdapter::new();
/// let config = HarnessConfig::new("echo", "episode-1")
///     .with_args(vec!["hello".to_string()]);
///
/// let (handle, mut events) = adapter.spawn(config).await?;
///
/// while let Some(event) = events.recv().await {
///     println!("Event: {:?}", event);
/// }
/// ```
#[derive(Debug)]
pub struct RawAdapter {
    /// Semaphore for tracking and limiting concurrent spawned tasks.
    ///
    /// Each successful spawn acquires a permit, which is released when
    /// the spawned task completes. This bounds resource usage.
    task_semaphore: Arc<Semaphore>,

    /// State for Holon trait implementation.
    holon_state: RawAdapterState,
}

impl Default for RawAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RawAdapter {
    /// Create a new raw adapter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            task_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_ADAPTERS)),
            holon_state: RawAdapterState::default(),
        }
    }

    /// Returns the number of currently active (spawned) processes.
    ///
    /// This is useful for monitoring resource usage.
    #[must_use]
    pub fn active_count(&self) -> usize {
        MAX_CONCURRENT_ADAPTERS - self.task_semaphore.available_permits()
    }

    /// Returns the number of available slots for new processes.
    #[must_use]
    pub fn available_slots(&self) -> usize {
        self.task_semaphore.available_permits()
    }

    /// Generate a new unique handle ID.
    fn next_handle_id() -> u64 {
        HANDLE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Get current timestamp in nanoseconds.
    #[allow(clippy::cast_possible_truncation)]
    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Classify the exit status into a termination classification.
    const fn classify_exit(exit_status: super::pty::ExitStatus) -> TerminationClassification {
        match exit_status {
            super::pty::ExitStatus::Exited(0) => TerminationClassification::Success,
            super::pty::ExitStatus::Exited(_) => TerminationClassification::Failure,
            super::pty::ExitStatus::Signaled(_) => TerminationClassification::Killed,
            super::pty::ExitStatus::Running => TerminationClassification::Unknown,
        }
    }
}

impl HarnessAdapter for RawAdapter {
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Raw
    }

    fn spawn(
        &self,
        config: HarnessConfig,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = AdapterResult<(HarnessHandle, HarnessEventStream)>>
                + Send
                + '_,
        >,
    > {
        // Clone the semaphore Arc for use in the async block
        let semaphore = Arc::clone(&self.task_semaphore);

        Box::pin(async move {
            // Validate configuration before spawning
            config.validate()?;

            // Try to acquire a permit without blocking
            // This enforces the concurrent adapter limit
            let permit = semaphore.clone().try_acquire_owned().map_err(|_| {
                AdapterError::resource_limit_exceeded(format!(
                    "maximum concurrent adapters ({MAX_CONCURRENT_ADAPTERS}) reached"
                ))
            })?;

            let handle_id = Self::next_handle_id();
            let episode_id = config.episode_id.clone();

            // Create PTY configuration from harness config
            let (cols, rows) = config.pty_size;
            let pty_config = PtyConfig::default().with_window_size(cols, rows);

            // Get timestamp for spawn
            let timestamp_ns = Self::now_ns();

            // Build args slice
            let args: Vec<&str> = config.args.iter().map(String::as_str).collect();

            // Spawn the process via PtyRunner
            let mut runner = PtyRunner::spawn(&config.command, &args, pty_config, timestamp_ns)
                .map_err(|e| AdapterError::spawn_failed(format!("PTY spawn failed: {e}")))?;

            // Create the event channel
            let (tx, rx) = tokio::sync::mpsc::channel(256);

            // Spawn a task that reads from the PTY and emits events
            // The permit is moved into the task and dropped when it completes,
            // releasing the slot for a new process.
            tokio::spawn(async move {
                // Hold the permit for the duration of the task
                let _permit = permit;

                let mut seq = 0u64;

                // Read output from PTY and emit events
                while let Some(output) = runner.recv().await {
                    let event = HarnessEvent::output(
                        output.chunk.to_vec(),
                        OutputKind::Combined,
                        seq,
                        output.ts_mono,
                    );
                    seq += 1;

                    if tx.send(event).await.is_err() {
                        // Receiver dropped, stop reading
                        break;
                    }
                }

                // Wait for process to exit and get status
                let exit_status = runner.wait().unwrap_or(super::pty::ExitStatus::Running);

                let exit_code = exit_status.code();
                let classification = Self::classify_exit(exit_status);

                // Emit terminated event
                let _ = tx
                    .send(HarnessEvent::terminated(exit_code, classification))
                    .await;

                // Permit is automatically released when dropped here
            });

            let handle = HarnessHandle::new(handle_id, episode_id, HarnessHandleInner::Placeholder);

            Ok((handle, rx))
        })
    }

    fn send_input(
        &self,
        _handle: &HarnessHandle,
        _input: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<()>> + Send + '_>> {
        Box::pin(async move {
            // Note: To fully implement send_input, we would need to store the PtyRunner
            // in the HarnessHandleInner. For now, return an error indicating this
            // limitation. A future ticket can enhance this to support interactive input.
            Err(AdapterError::input_failed(
                "raw adapter send_input requires handle-based PTY storage (not yet implemented)",
            ))
        })
    }

    fn terminate(
        &self,
        _handle: &HarnessHandle,
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<ExitStatus>> + Send + '_>> {
        Box::pin(async move {
            // Note: Similar to send_input, full terminate support requires storing
            // the PtyRunner in HarnessHandleInner. The spawned task will handle
            // cleanup when dropped. For explicit termination, we would need to
            // signal the runner via the handle.
            Err(AdapterError::terminate_failed(
                "raw adapter terminate requires handle-based PTY storage (not yet implemented)",
            ))
        })
    }
}

// =============================================================================
// Holon Trait Implementation
// =============================================================================
//
// Per AD-LAYER-001 and the ticket step 5, HarnessAdapter (specifically
// RawAdapter) implements the Holon trait for holonic coordination.

impl Holon for RawAdapter {
    type Input = HarnessConfig;
    type Output = RawAdapterOutput;
    type State = RawAdapterState;

    fn intake(&mut self, input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        // Validate the input configuration
        input.validate().map_err(|e| {
            HolonError::invalid_input(format!("HarnessConfig validation failed: {e}"))
        })?;

        // Store the episode ID in state
        self.holon_state.episode_id = Some(input.episode_id);
        self.holon_state.intake_called = true;
        self.holon_state.output_event_count = 0;
        self.holon_state.last_exit_code = None;

        Ok(())
    }

    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        // In the adapter model, execution happens asynchronously via spawn().
        // The Holon trait is used for coordination/state management rather
        // than direct execution in this context.
        //
        // For RawAdapter, we return completion since the actual work is
        // done via the HarnessAdapter::spawn() method.
        if !self.holon_state.intake_called {
            return Err(HolonError::episode_failed(
                "intake() must be called before execute_episode()",
                true,
            ));
        }

        // Return completed with the current state
        let output = RawAdapterOutput {
            exit_code: self.holon_state.last_exit_code,
            output_event_count: self.holon_state.output_event_count,
            success: self.holon_state.last_exit_code.is_some_and(|c| c == 0),
        };

        Ok(EpisodeResult::completed(output))
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        // RawAdapter does not emit artifacts directly.
        // All output is streamed via HarnessEvent::Output events.
        // Artifacts would be collected by the episode runtime from the output stream.
        Ok(())
    }

    fn escalate(&mut self, reason: &str) -> Result<(), HolonError> {
        // RawAdapter doesn't have a supervisor to escalate to.
        // Log the escalation reason and return success (no-op escalation).
        tracing::warn!(reason = %reason, "RawAdapter escalation requested (no supervisor)");
        Ok(())
    }

    fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition {
        // Check standard stop conditions
        if ctx.episode_limit_reached() {
            return StopCondition::max_episodes_reached(ctx.episode_number());
        }

        if ctx.tokens_exhausted() {
            return StopCondition::budget_exhausted("tokens");
        }

        // If we have an exit code, we're done
        if self.holon_state.last_exit_code.is_some() {
            return StopCondition::GoalSatisfied;
        }

        StopCondition::Continue
    }

    fn state(&self) -> &Self::State {
        &self.holon_state
    }

    fn holon_id(&self) -> Option<&str> {
        self.holon_state.episode_id.as_deref()
    }

    fn type_name(&self) -> &'static str {
        "RawAdapter"
    }
}

/// Helper functions for testing the raw adapter.
#[cfg(test)]
pub(crate) mod test_helpers {
    use std::time::SystemTime;

    use super::super::adapter::OutputKind;
    use super::*;

    /// Get the current timestamp in nanoseconds.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Create a mock output event for testing.
    #[must_use]
    pub fn mock_output_event(data: &[u8], seq: u64) -> HarnessEvent {
        HarnessEvent::output(data.to_vec(), OutputKind::Combined, seq, now_ns())
    }
}

#[cfg(test)]
mod tests {
    use super::super::adapter::OutputKind;
    use super::*;

    #[test]
    fn test_raw_adapter_new() {
        let adapter = RawAdapter::new();
        assert_eq!(adapter.adapter_type(), AdapterType::Raw);
    }

    #[test]
    fn test_raw_adapter_default() {
        let adapter = RawAdapter::default();
        assert_eq!(adapter.adapter_type(), AdapterType::Raw);
    }

    #[test]
    fn test_raw_adapter_debug() {
        let adapter = RawAdapter::new();
        let debug_str = format!("{adapter:?}");
        assert!(debug_str.contains("RawAdapter"));
    }

    #[test]
    fn test_handle_id_generation() {
        let id1 = RawAdapter::next_handle_id();
        let id2 = RawAdapter::next_handle_id();
        let id3 = RawAdapter::next_handle_id();

        // IDs should be monotonically increasing
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[tokio::test]
    async fn test_raw_adapter_spawn_echo() {
        let adapter = RawAdapter::new();
        let config =
            HarnessConfig::new("echo", "episode-test").with_args(vec!["hello".to_string()]);

        let result = adapter.spawn(config).await;
        assert!(result.is_ok());

        let (handle, mut events) = result.unwrap();
        assert!(!handle.episode_id().is_empty());
        assert_eq!(handle.episode_id(), "episode-test");

        // Collect events until terminated
        let mut output_events = Vec::new();
        let mut terminated_event = None;

        while let Some(event) = events.recv().await {
            if event.is_terminal() {
                terminated_event = Some(event);
                break;
            }
            output_events.push(event);
        }

        // Should have received at least one output event with "hello"
        assert!(!output_events.is_empty(), "expected output events");

        // Check that we got output containing "hello"
        let has_hello = output_events.iter().any(|e| {
            if let HarnessEvent::Output { chunk, .. } = e {
                String::from_utf8_lossy(chunk).contains("hello")
            } else {
                false
            }
        });
        assert!(has_hello, "expected output to contain 'hello'");

        // Should have terminated successfully
        assert!(terminated_event.is_some(), "expected terminated event");
        if let Some(HarnessEvent::Terminated {
            exit_code,
            classification,
        }) = terminated_event
        {
            assert_eq!(exit_code, Some(0));
            assert_eq!(classification, TerminationClassification::Success);
        }
    }

    #[tokio::test]
    async fn test_raw_adapter_spawn_with_exit_code() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("sh", "episode-exit")
            .with_args(vec!["-c".to_string(), "exit 42".to_string()]);

        let (_, mut events) = adapter.spawn(config).await.unwrap();

        // Drain events until terminated
        let mut terminated_event = None;
        while let Some(event) = events.recv().await {
            if event.is_terminal() {
                terminated_event = Some(event);
                break;
            }
        }

        // Check exit code
        if let Some(HarnessEvent::Terminated {
            exit_code,
            classification,
        }) = terminated_event
        {
            assert_eq!(exit_code, Some(42));
            assert_eq!(classification, TerminationClassification::Failure);
        } else {
            panic!("expected terminated event");
        }
    }

    #[tokio::test]
    async fn test_raw_adapter_send_input_not_implemented() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("cat", "episode-test");

        let (handle, _events) = adapter.spawn(config).await.unwrap();

        let result = adapter.send_input(&handle, b"test input").await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, AdapterError::InputFailed { .. }));
    }

    #[tokio::test]
    async fn test_raw_adapter_terminate_not_implemented() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("sleep", "episode-test").with_args(vec!["1".to_string()]);

        let (handle, _events) = adapter.spawn(config).await.unwrap();

        let result = adapter.terminate(&handle).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, AdapterError::TerminateFailed { .. }));
    }

    #[test]
    fn test_mock_output_event() {
        let event = test_helpers::mock_output_event(b"test data", 1);

        match event {
            HarnessEvent::Output {
                chunk,
                kind,
                seq,
                ts,
            } => {
                assert_eq!(chunk, b"test data");
                assert_eq!(kind, OutputKind::Combined);
                assert_eq!(seq, 1);
                assert!(ts > 0);
            },
            _ => panic!("expected Output event"),
        }
    }

    #[test]
    fn test_raw_adapter_initial_capacity() {
        let adapter = RawAdapter::new();
        assert_eq!(adapter.active_count(), 0);
        assert_eq!(adapter.available_slots(), MAX_CONCURRENT_ADAPTERS);
    }

    #[tokio::test]
    async fn test_raw_adapter_tracks_active_count() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("echo", "ep-1");

        // Before spawn, no active tasks
        assert_eq!(adapter.active_count(), 0);

        // Spawn a process
        let (_handle, mut events) = adapter.spawn(config).await.unwrap();

        // Wait for the task to complete
        while events.recv().await.is_some() {}

        // After completion, the permit should be released
        // Give a small delay for the task to fully complete
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(adapter.active_count(), 0);
        assert_eq!(adapter.available_slots(), MAX_CONCURRENT_ADAPTERS);
    }

    #[tokio::test]
    async fn test_raw_adapter_validates_config_on_spawn() {
        let adapter = RawAdapter::new();

        // Empty command should fail validation
        let config = HarnessConfig::new("", "ep-1");
        let result = adapter.spawn(config).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AdapterError::ValidationFailed(_)));
    }

    #[tokio::test]
    async fn test_raw_adapter_validates_args_on_spawn() {
        let adapter = RawAdapter::new();

        // Arg with null byte should fail validation
        let config = HarnessConfig::new("echo", "ep-1").with_args(vec!["bad\0arg".to_string()]);
        let result = adapter.spawn(config).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AdapterError::ValidationFailed(_)));
    }

    // =========================================================================
    // Holon Trait Tests
    // =========================================================================

    #[test]
    fn test_holon_intake() {
        let mut adapter = RawAdapter::new();
        let config =
            HarnessConfig::new("echo", "episode-holon").with_args(vec!["test".to_string()]);

        let result = adapter.intake(config, "lease-123");
        assert!(result.is_ok());
        assert!(adapter.holon_state.intake_called);
        assert_eq!(
            adapter.holon_state.episode_id,
            Some("episode-holon".to_string())
        );
    }

    #[test]
    fn test_holon_intake_validation_error() {
        let mut adapter = RawAdapter::new();
        let config = HarnessConfig::new("", "episode-invalid"); // Empty command

        let result = adapter.intake(config, "lease-123");
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_execute_without_intake() {
        let mut adapter = RawAdapter::new();
        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        let result = adapter.execute_episode(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_execute_after_intake() {
        let mut adapter = RawAdapter::new();
        let config = HarnessConfig::new("echo", "episode-exec");

        adapter.intake(config, "lease-123").unwrap();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        let result = adapter.execute_episode(&ctx);
        assert!(result.is_ok());
        assert!(result.unwrap().is_completed());
    }

    #[test]
    fn test_holon_should_stop() {
        let adapter = RawAdapter::new();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // Without exit code, should continue
        let condition = adapter.should_stop(&ctx);
        assert_eq!(condition, StopCondition::Continue);
    }

    #[test]
    fn test_holon_should_stop_budget_exhausted() {
        let adapter = RawAdapter::new();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .remaining_tokens(0)
            .build();

        let condition = adapter.should_stop(&ctx);
        assert!(matches!(condition, StopCondition::BudgetExhausted { .. }));
    }

    #[test]
    fn test_holon_should_stop_max_episodes() {
        let adapter = RawAdapter::new();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .episode_number(10)
            .max_episodes(10)
            .build();

        let condition = adapter.should_stop(&ctx);
        assert!(matches!(
            condition,
            StopCondition::MaxEpisodesReached { .. }
        ));
    }

    #[test]
    fn test_holon_state() {
        let adapter = RawAdapter::new();
        let state = adapter.state();
        assert!(!state.intake_called);
        assert!(state.episode_id.is_none());
    }

    #[test]
    fn test_holon_type_name() {
        let adapter = RawAdapter::new();
        assert_eq!(adapter.type_name(), "RawAdapter");
    }

    #[test]
    fn test_holon_emit_artifact() {
        let adapter = RawAdapter::new();
        let artifact = Artifact::builder()
            .kind("test")
            .work_id("work-1")
            .content("test content")
            .build();

        let result = adapter.emit_artifact(artifact);
        assert!(result.is_ok());
    }

    #[test]
    fn test_holon_escalate() {
        let mut adapter = RawAdapter::new();
        let result = adapter.escalate("test escalation");
        assert!(result.is_ok());
    }

    #[test]
    fn test_raw_adapter_output() {
        let output = RawAdapterOutput {
            exit_code: Some(0),
            output_event_count: 10,
            success: true,
        };

        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.output_event_count, 10);
        assert!(output.success);
    }
}
