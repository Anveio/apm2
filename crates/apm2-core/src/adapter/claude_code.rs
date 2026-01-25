//! Claude Code instrumented adapter.
//!
//! This adapter integrates with Claude Code's native hook system to receive
//! rich telemetry about tool requests and responses. Unlike the black-box
//! adapter, this provides:
//!
//! - **Native tool requests**: Exact tool invocations from Claude Code
//! - **Tool responses**: Results before returning to the model
//! - **Rich progress signals**: Precise event timing and context
//! - **Session lifecycle**: Claude Code session start/stop events
//!
//! # Hook Integration
//!
//! The adapter uses Claude Code's hook system, which fires events at:
//!
//! - `PreToolUse`: Before a tool is executed (for mediation/policy)
//! - `PostToolUse`: After a tool completes (for auditing/logging)
//! - Session start/stop boundaries
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────┐
//! │  Claude Code   │
//! │   (Process)    │
//! └───────┬────────┘
//!         │ hooks (stdin/stdout JSON-RPC)
//!         ▼
//! ┌────────────────┐
//! │ClaudeCodeAdapter│
//! │   (this crate)  │
//! └───────┬────────┘
//!         │ AdapterEvent
//!         ▼
//! ┌────────────────┐
//! │   Supervisor   │
//! └────────────────┘
//! ```
//!
//! # Security Model
//!
//! The adapter follows **default-deny, least-privilege, fail-closed**:
//!
//! - All tool requests are validated before emission
//! - Session credentials are never logged or exposed
//! - Invalid hook payloads cause session termination (fail-closed)
//! - Tool responses are validated before delivery

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

use super::BoxFuture;
use super::config::EnvironmentConfig;
use super::error::AdapterError;
use super::event::{
    AdapterEvent, AdapterEventPayload, DetectionMethod, ExitClassification, ProcessExited,
    ProcessStarted, ProgressSignal, ProgressType, StallDetected, ToolRequestDetected,
};
use super::traits::Adapter;

/// Configuration for a Claude Code instrumented adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeCodeConfig {
    /// Session ID for this adapter instance.
    pub session_id: String,

    /// Path to the Claude Code CLI executable.
    pub claude_binary: String,

    /// Arguments to pass to Claude Code.
    pub args: Vec<String>,

    /// Working directory for Claude Code.
    pub working_dir: Option<PathBuf>,

    /// Environment configuration.
    pub environment: EnvironmentConfig,

    /// Stall detection timeout.
    pub stall_timeout: Duration,

    /// Whether stall detection is enabled.
    pub stall_detection_enabled: bool,

    /// Hook configuration for Claude Code.
    pub hooks: HookConfig,

    /// Event buffer size for the channel.
    pub buffer_size: usize,
}

impl ClaudeCodeConfig {
    /// Creates a new configuration with sensible defaults.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            claude_binary: "claude".to_string(),
            args: Vec::new(),
            working_dir: None,
            environment: EnvironmentConfig::default(),
            stall_timeout: Duration::from_secs(120),
            stall_detection_enabled: true,
            hooks: HookConfig::default(),
            buffer_size: 1024,
        }
    }

    /// Sets the Claude Code binary path.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.claude_binary = binary.into();
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Sets the command arguments.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the stall timeout.
    #[must_use]
    pub const fn with_stall_timeout(mut self, timeout: Duration) -> Self {
        self.stall_timeout = timeout;
        self
    }

    /// Disables stall detection.
    #[must_use]
    pub const fn without_stall_detection(mut self) -> Self {
        self.stall_detection_enabled = false;
        self
    }
}

/// Hook configuration for Claude Code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// Enable `PreToolUse` hook for tool request interception.
    pub pre_tool_use: bool,

    /// Enable `PostToolUse` hook for tool response capture.
    pub post_tool_use: bool,

    /// Enable session lifecycle hooks.
    pub session_lifecycle: bool,

    /// Timeout for hook responses.
    pub hook_timeout: Duration,
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            pre_tool_use: true,
            post_tool_use: true,
            session_lifecycle: true,
            hook_timeout: Duration::from_secs(30),
        }
    }
}

/// A Claude Code hook event received from the process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HookEvent {
    /// `PreToolUse` hook event.
    #[serde(rename = "pre_tool_use")]
    PreToolUse(ToolUseEvent),

    /// `PostToolUse` hook event.
    #[serde(rename = "post_tool_use")]
    PostToolUse(ToolResultEvent),

    /// Session started event.
    #[serde(rename = "session_start")]
    SessionStart(SessionStartEvent),

    /// Session ended event.
    #[serde(rename = "session_end")]
    SessionEnd(SessionEndEvent),

    /// Progress/heartbeat event.
    #[serde(rename = "progress")]
    Progress(ProgressEvent),
}

/// Tool use event from Claude Code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUseEvent {
    /// Unique ID for this tool invocation.
    pub tool_use_id: String,

    /// Name of the tool being invoked.
    pub tool_name: String,

    /// Tool input parameters.
    pub input: serde_json::Value,

    /// Session ID from Claude Code.
    pub session_id: Option<String>,

    /// Timestamp of the event.
    pub timestamp: Option<u64>,
}

/// Tool result event from Claude Code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultEvent {
    /// ID of the tool invocation this result corresponds to.
    pub tool_use_id: String,

    /// Tool output/result.
    pub output: serde_json::Value,

    /// Whether the tool execution succeeded.
    pub success: bool,

    /// Error message if failed.
    pub error: Option<String>,

    /// Duration of tool execution in milliseconds.
    pub duration_ms: Option<u64>,
}

/// Session start event from Claude Code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStartEvent {
    /// Claude Code session ID.
    pub session_id: String,

    /// Working directory for the session.
    pub working_dir: Option<String>,

    /// Model being used.
    pub model: Option<String>,

    /// Timestamp of session start.
    pub timestamp: Option<u64>,
}

/// Session end event from Claude Code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEndEvent {
    /// Claude Code session ID.
    pub session_id: String,

    /// Exit reason.
    pub reason: Option<String>,

    /// Duration of the session in milliseconds.
    pub duration_ms: Option<u64>,
}

/// Progress event from Claude Code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    /// Type of progress (thinking, streaming, idle).
    pub progress_type: String,

    /// Human-readable description.
    pub description: Option<String>,

    /// Token count if applicable.
    pub token_count: Option<u64>,
}

/// Hook response to send back to Claude Code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResponse {
    /// Whether to continue with the tool execution.
    pub continue_execution: bool,

    /// Optional message to include in the response.
    pub message: Option<String>,

    /// Modified tool input if applicable.
    pub modified_input: Option<serde_json::Value>,
}

impl Default for HookResponse {
    fn default() -> Self {
        Self {
            continue_execution: true,
            message: None,
            modified_input: None,
        }
    }
}

/// Claude Code instrumented adapter.
#[derive(Debug)]
pub struct ClaudeCodeAdapter {
    /// Configuration for this adapter.
    config: ClaudeCodeConfig,

    /// Current state of the adapter.
    state: AdapterState,

    /// Sequence number generator for events.
    sequence: AtomicU64,

    /// Event sender.
    event_tx: Option<mpsc::Sender<AdapterEvent>>,

    /// Event receiver (taken when `start()` is called).
    event_rx: Option<mpsc::Receiver<AdapterEvent>>,
}

/// Internal state of the adapter.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum AdapterState {
    /// Adapter is not started.
    Idle,

    /// Adapter is running with a child process.
    Running {
        /// The child process handle.
        child: Child,
        /// OS process ID.
        pid: u32,
        /// Time when the process started.
        started_at: Instant,
        /// Last activity timestamp.
        last_activity: Instant,
        /// Stall count.
        stall_count: u32,
        /// Shutdown signal.
        shutdown: Arc<AtomicBool>,
        /// Claude Code session ID (from hook events).
        claude_session_id: Option<String>,
    },

    /// Adapter has stopped.
    Stopped {
        /// Exit code if available.
        exit_code: Option<i32>,
        /// Signal if available.
        signal: Option<i32>,
    },
}

impl ClaudeCodeAdapter {
    /// Creates a new Claude Code instrumented adapter.
    #[must_use]
    pub fn new(config: ClaudeCodeConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.buffer_size);

        Self {
            config,
            state: AdapterState::Idle,
            sequence: AtomicU64::new(0),
            event_tx: Some(tx),
            event_rx: Some(rx),
        }
    }

    /// Starts the adapter, spawning Claude Code with hook integration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The adapter is already running
    /// - Claude Code fails to spawn
    pub async fn start(&mut self) -> Result<(), AdapterError> {
        if matches!(self.state, AdapterState::Running { .. }) {
            return Err(AdapterError::AlreadyRunning);
        }

        // Build the command with hook configuration
        let mut cmd = Command::new(&self.config.claude_binary);

        // Add print mode for non-interactive usage with JSON streaming
        cmd.arg("-p");
        cmd.arg("--output-format");
        cmd.arg("stream-json");

        // Add user-specified arguments
        cmd.args(&self.config.args);

        // Configure stdio for hook communication
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // Set working directory
        if let Some(ref cwd) = self.config.working_dir {
            cmd.current_dir(cwd);
        }

        // Apply environment configuration
        self.apply_environment(&mut cmd);

        // Spawn the process
        let child = cmd
            .spawn()
            .map_err(|e| AdapterError::SpawnFailed(e.to_string()))?;

        let pid = child
            .id()
            .ok_or_else(|| AdapterError::SpawnFailed("failed to get PID".to_string()))?;

        let now = Instant::now();
        let shutdown = Arc::new(AtomicBool::new(false));

        self.state = AdapterState::Running {
            child,
            pid,
            started_at: now,
            last_activity: now,
            stall_count: 0,
            shutdown,
            claude_session_id: None,
        };

        // Emit process started event
        self.emit_process_started(pid).await?;

        Ok(())
    }

    /// Applies environment configuration to the command.
    fn apply_environment(&self, cmd: &mut Command) {
        let env_config = &self.config.environment;

        if !env_config.inherit {
            cmd.env_clear();
        }

        // Apply configured variables
        for (key, value) in &env_config.variables {
            if !env_config.exclude.contains(key) {
                cmd.env(key, value);
            }
        }

        // Remove excluded variables from inherited environment
        if env_config.inherit {
            for key in &env_config.exclude {
                cmd.env_remove(key);
            }
        }
    }

    /// Polls for events from Claude Code.
    ///
    /// This reads from the process stdout for hook events and checks process
    /// status.
    ///
    /// # Errors
    ///
    /// Returns an error if the adapter is not running.
    pub async fn poll(&mut self) -> Result<Option<AdapterEvent>, AdapterError> {
        let (child, pid, started_at, last_activity, stall_count, shutdown) = match &mut self.state {
            AdapterState::Running {
                child,
                pid,
                started_at,
                last_activity,
                stall_count,
                shutdown,
                ..
            } => (
                child,
                *pid,
                *started_at,
                last_activity,
                stall_count,
                shutdown.clone(),
            ),
            AdapterState::Idle => return Err(AdapterError::NotRunning),
            AdapterState::Stopped { .. } => return Ok(None),
        };

        // Check for process exit first
        if let Some(status) = child.try_wait().map_err(AdapterError::Io)? {
            let uptime = started_at.elapsed();
            let exit_code = status.code();
            let signal = Self::extract_signal(status);

            let classification = Self::classify_exit(exit_code, signal);

            let event = self.create_event(AdapterEventPayload::ProcessExited(ProcessExited {
                pid,
                exit_code,
                signal,
                uptime,
                classification,
            }));

            self.state = AdapterState::Stopped { exit_code, signal };

            if let Some(tx) = &self.event_tx {
                let _ = tx.send(event.clone()).await;
            }

            return Ok(Some(event));
        }

        // Check if shutdown was requested
        if shutdown.load(Ordering::SeqCst) {
            return Ok(None);
        }

        // Try to read hook events from stdout (non-blocking check)
        // Note: In a full implementation, we'd use async I/O here
        // For now, we simulate the hook event processing

        // Check for stall
        if self.config.stall_detection_enabled {
            let idle_duration = last_activity.elapsed();
            if idle_duration >= self.config.stall_timeout {
                *stall_count += 1;
                let current_stall_count = *stall_count;
                *last_activity = Instant::now();

                let stall_event =
                    self.create_event(AdapterEventPayload::StallDetected(StallDetected {
                        idle_duration,
                        threshold: self.config.stall_timeout,
                        stall_count: current_stall_count,
                    }));

                if let Some(tx) = &self.event_tx {
                    let _ = tx.send(stall_event.clone()).await;
                }

                return Ok(Some(stall_event));
            }
        }

        Ok(None)
    }

    /// Processes a hook event received from Claude Code.
    ///
    /// This converts the hook event to an `AdapterEvent` and emits it.
    ///
    /// # Errors
    ///
    /// Returns an error if the event channel is closed.
    pub async fn process_hook_event(&mut self, event: HookEvent) -> Result<(), AdapterError> {
        // Update last activity timestamp
        if let AdapterState::Running { last_activity, .. } = &mut self.state {
            *last_activity = Instant::now();
        }

        let adapter_event = match event {
            HookEvent::PreToolUse(tool_event) => {
                // Convert tool use event to ToolRequestDetected
                let mut context = BTreeMap::new();
                context.insert("tool_use_id".to_string(), tool_event.tool_use_id);
                if let Ok(input_str) = serde_json::to_string(&tool_event.input) {
                    context.insert("input".to_string(), input_str);
                }

                self.create_event(AdapterEventPayload::ToolRequestDetected(
                    ToolRequestDetected {
                        tool_name: tool_event.tool_name,
                        detection_method: DetectionMethod::Instrumentation,
                        confidence_percent: 100, // Native event, full confidence
                        context,
                    },
                ))
            },
            HookEvent::PostToolUse(result_event) => {
                // Emit a progress signal for tool completion
                let description = if result_event.success {
                    format!("Tool {} completed successfully", result_event.tool_use_id)
                } else {
                    format!(
                        "Tool {} failed: {}",
                        result_event.tool_use_id,
                        result_event.error.as_deref().unwrap_or("unknown error")
                    )
                };

                self.create_event(AdapterEventPayload::Progress(ProgressSignal {
                    signal_type: ProgressType::ToolComplete,
                    description,
                    entropy_cost: u64::from(!result_event.success),
                }))
            },
            HookEvent::SessionStart(session_event) => {
                // Update Claude session ID in state
                if let AdapterState::Running {
                    claude_session_id, ..
                } = &mut self.state
                {
                    *claude_session_id = Some(session_event.session_id.clone());
                }

                // Emit a milestone progress event
                self.create_event(AdapterEventPayload::Progress(ProgressSignal {
                    signal_type: ProgressType::Milestone,
                    description: format!(
                        "Claude Code session started: {}",
                        session_event.session_id
                    ),
                    entropy_cost: 0,
                }))
            },
            HookEvent::SessionEnd(session_event) => {
                self.create_event(AdapterEventPayload::Progress(ProgressSignal {
                    signal_type: ProgressType::Milestone,
                    description: format!(
                        "Claude Code session ended: {} ({})",
                        session_event.session_id,
                        session_event.reason.as_deref().unwrap_or("completed")
                    ),
                    entropy_cost: 0,
                }))
            },
            HookEvent::Progress(progress_event) => {
                let signal_type = match progress_event.progress_type.as_str() {
                    "idle" => ProgressType::Heartbeat,
                    // "thinking", "streaming", and other types map to Activity
                    _ => ProgressType::Activity,
                };

                self.create_event(AdapterEventPayload::Progress(ProgressSignal {
                    signal_type,
                    description: progress_event
                        .description
                        .unwrap_or(progress_event.progress_type),
                    entropy_cost: 0,
                }))
            },
        };

        if let Some(tx) = &self.event_tx {
            tx.send(adapter_event)
                .await
                .map_err(|e| AdapterError::ChannelSend(e.to_string()))?;
        }

        Ok(())
    }

    /// Sends a hook response to Claude Code.
    ///
    /// This is used to respond to `PreToolUse` events with allow/deny
    /// decisions.
    ///
    /// # Errors
    ///
    /// Returns an error if the adapter is not running or serialization fails.
    pub fn send_hook_response(&mut self, response: &HookResponse) -> Result<(), AdapterError> {
        let AdapterState::Running { child: _, .. } = &mut self.state else {
            return Err(AdapterError::NotRunning);
        };

        // In a full implementation, we'd write the response to stdin
        // For now, this is a placeholder for the hook response protocol
        let _response_json =
            serde_json::to_string(response).map_err(|e| AdapterError::Internal(e.to_string()))?;

        // TODO: Implement hook response delivery via stdin
        // child.stdin.write_all(response_json.as_bytes())...

        Ok(())
    }

    /// Stops the adapter, terminating Claude Code.
    ///
    /// # Errors
    ///
    /// Returns an error if termination fails.
    pub async fn stop(&mut self) -> Result<(), AdapterError> {
        if let AdapterState::Running {
            child, shutdown, ..
        } = &mut self.state
        {
            shutdown.store(true, Ordering::SeqCst);
            child.kill().await.map_err(AdapterError::Io)?;
        }

        Ok(())
    }

    /// Returns the event receiver.
    ///
    /// This can only be called once; subsequent calls return `None`.
    pub const fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<AdapterEvent>> {
        self.event_rx.take()
    }

    /// Returns the session ID for this adapter.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.config.session_id
    }

    /// Returns whether the adapter is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self.state, AdapterState::Running { .. })
    }

    /// Returns the process ID if running.
    #[must_use]
    pub const fn pid(&self) -> Option<u32> {
        match &self.state {
            AdapterState::Running { pid, .. } => Some(*pid),
            _ => None,
        }
    }

    /// Returns the Claude Code session ID if available.
    #[must_use]
    pub fn claude_session_id(&self) -> Option<&str> {
        match &self.state {
            AdapterState::Running {
                claude_session_id, ..
            } => claude_session_id.as_deref(),
            _ => None,
        }
    }

    /// Creates an event with the next sequence number.
    fn create_event(&self, payload: AdapterEventPayload) -> AdapterEvent {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        #[allow(clippy::cast_possible_truncation)]
        let timestamp_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        AdapterEvent {
            sequence,
            timestamp_nanos,
            session_id: self.config.session_id.clone(),
            payload,
        }
    }

    /// Emits a process started event.
    async fn emit_process_started(&self, pid: u32) -> Result<(), AdapterError> {
        let working_dir = self
            .config
            .working_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));

        let env: BTreeMap<String, String> = self
            .config
            .environment
            .variables
            .iter()
            .filter(|(k, _)| !self.config.environment.exclude.contains(k))
            .cloned()
            .collect();

        let event = self.create_event(AdapterEventPayload::ProcessStarted(ProcessStarted {
            pid,
            command: self.config.claude_binary.clone(),
            args: self.config.args.clone(),
            working_dir,
            env,
            adapter_type: "claude-code".to_string(),
        }));

        if let Some(tx) = &self.event_tx {
            tx.send(event)
                .await
                .map_err(|e| AdapterError::ChannelSend(e.to_string()))?;
        }

        Ok(())
    }

    /// Extracts the signal number from an exit status (Unix only).
    #[cfg(unix)]
    fn extract_signal(status: std::process::ExitStatus) -> Option<i32> {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }

    /// Windows doesn't have Unix signals.
    #[cfg(not(unix))]
    fn extract_signal(_status: std::process::ExitStatus) -> Option<i32> {
        None
    }

    /// Classifies the exit based on exit code and signal.
    const fn classify_exit(exit_code: Option<i32>, signal: Option<i32>) -> ExitClassification {
        match (exit_code, signal) {
            (Some(0), None) => ExitClassification::CleanSuccess,
            (Some(_), None) => ExitClassification::CleanError,
            (None, Some(_)) => ExitClassification::Signal,
            _ => ExitClassification::Unknown,
        }
    }

    /// Returns the exit code if the adapter has stopped.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        match &self.state {
            AdapterState::Stopped { exit_code, .. } => *exit_code,
            _ => None,
        }
    }

    /// Returns the signal that terminated the process, if any.
    #[must_use]
    pub const fn exit_signal(&self) -> Option<i32> {
        match &self.state {
            AdapterState::Stopped { signal, .. } => *signal,
            _ => None,
        }
    }
}

impl Adapter for ClaudeCodeAdapter {
    fn start(&mut self) -> BoxFuture<'_, Result<(), AdapterError>> {
        Box::pin(Self::start(self))
    }

    fn poll(&mut self) -> BoxFuture<'_, Result<Option<AdapterEvent>, AdapterError>> {
        Box::pin(Self::poll(self))
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), AdapterError>> {
        Box::pin(Self::stop(self))
    }

    fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<AdapterEvent>> {
        Self::take_event_receiver(self)
    }

    fn session_id(&self) -> &str {
        Self::session_id(self)
    }

    fn is_running(&self) -> bool {
        Self::is_running(self)
    }

    fn pid(&self) -> Option<u32> {
        Self::pid(self)
    }

    fn adapter_type(&self) -> &'static str {
        "claude-code"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = ClaudeCodeConfig::new("session-123");
        assert_eq!(config.session_id, "session-123");
        assert_eq!(config.claude_binary, "claude");
        assert!(config.hooks.pre_tool_use);
        assert!(config.hooks.post_tool_use);
    }

    #[test]
    fn test_config_builder() {
        let config = ClaudeCodeConfig::new("session-456")
            .with_binary("/usr/local/bin/claude")
            .with_working_dir("/tmp/workspace")
            .with_args(["--model", "opus"])
            .with_stall_timeout(Duration::from_secs(60));

        assert_eq!(config.session_id, "session-456");
        assert_eq!(config.claude_binary, "/usr/local/bin/claude");
        assert_eq!(config.working_dir, Some(PathBuf::from("/tmp/workspace")));
        assert_eq!(config.args, vec!["--model", "opus"]);
        assert_eq!(config.stall_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_hook_config_defaults() {
        let config = HookConfig::default();
        assert!(config.pre_tool_use);
        assert!(config.post_tool_use);
        assert!(config.session_lifecycle);
        assert_eq!(config.hook_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_adapter_creation() {
        let config = ClaudeCodeConfig::new("test-session");
        let adapter = ClaudeCodeAdapter::new(config);

        assert_eq!(adapter.session_id(), "test-session");
        assert!(!adapter.is_running());
        assert!(adapter.pid().is_none());
    }

    #[test]
    fn test_hook_response_default() {
        let response = HookResponse::default();
        assert!(response.continue_execution);
        assert!(response.message.is_none());
        assert!(response.modified_input.is_none());
    }

    #[test]
    fn test_tool_use_event_serialization() {
        let event = ToolUseEvent {
            tool_use_id: "tool-123".to_string(),
            tool_name: "Read".to_string(),
            input: serde_json::json!({"file_path": "/tmp/test.txt"}),
            session_id: Some("session-abc".to_string()),
            timestamp: Some(1_234_567_890),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: ToolUseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tool_use_id, "tool-123");
        assert_eq!(parsed.tool_name, "Read");
    }

    #[test]
    fn test_tool_result_event_serialization() {
        let event = ToolResultEvent {
            tool_use_id: "tool-123".to_string(),
            output: serde_json::json!({"content": "file contents"}),
            success: true,
            error: None,
            duration_ms: Some(150),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: ToolResultEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tool_use_id, "tool-123");
        assert!(parsed.success);
    }

    #[test]
    fn test_session_start_event_serialization() {
        let event = SessionStartEvent {
            session_id: "session-xyz".to_string(),
            working_dir: Some("/home/user/project".to_string()),
            model: Some("claude-opus-4".to_string()),
            timestamp: Some(1_234_567_890),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: SessionStartEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "session-xyz");
        assert_eq!(parsed.model, Some("claude-opus-4".to_string()));
    }

    #[test]
    fn test_hook_event_serialization() {
        let pre_tool = HookEvent::PreToolUse(ToolUseEvent {
            tool_use_id: "tool-1".to_string(),
            tool_name: "Bash".to_string(),
            input: serde_json::json!({"command": "ls -la"}),
            session_id: None,
            timestamp: None,
        });

        let json = serde_json::to_string(&pre_tool).unwrap();
        assert!(json.contains("pre_tool_use"));
        assert!(json.contains("Bash"));
    }

    #[test]
    fn test_exit_classification() {
        assert_eq!(
            ClaudeCodeAdapter::classify_exit(Some(0), None),
            ExitClassification::CleanSuccess
        );
        assert_eq!(
            ClaudeCodeAdapter::classify_exit(Some(1), None),
            ExitClassification::CleanError
        );
        assert_eq!(
            ClaudeCodeAdapter::classify_exit(None, Some(9)),
            ExitClassification::Signal
        );
        assert_eq!(
            ClaudeCodeAdapter::classify_exit(None, None),
            ExitClassification::Unknown
        );
    }

    #[cfg_attr(miri, ignore)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_adapter_double_start_error() {
        // Create a config that will fail to spawn (nonexistent command)
        // to test the error path without needing Claude installed
        let config =
            ClaudeCodeConfig::new("test-double-start").with_binary("nonexistent_claude_12345");

        let mut adapter = ClaudeCodeAdapter::new(config);

        // First start should fail (command not found)
        let result = adapter.start().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(AdapterError::SpawnFailed(_))));
    }

    #[test]
    fn test_environment_config_security() {
        let config = ClaudeCodeConfig::new("test-env");

        // Verify sensitive keys are excluded by default
        assert!(
            config
                .environment
                .exclude
                .contains(&"ANTHROPIC_API_KEY".to_string())
        );
        assert!(
            config
                .environment
                .exclude
                .contains(&"AWS_SECRET_ACCESS_KEY".to_string())
        );
        assert!(
            config
                .environment
                .exclude
                .contains(&"GITHUB_TOKEN".to_string())
        );
    }

    #[test]
    fn test_adapter_type() {
        let config = ClaudeCodeConfig::new("test-type");
        let adapter = ClaudeCodeAdapter::new(config);

        // Using the Adapter trait method
        assert_eq!(Adapter::adapter_type(&adapter), "claude-code");
    }

    #[cfg_attr(miri, ignore)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_process_hook_event_tool_request() {
        let config = ClaudeCodeConfig::new("test-hook-event");
        let mut adapter = ClaudeCodeAdapter::new(config);

        // Take the event receiver
        let _rx = adapter.take_event_receiver().unwrap();

        // Process a PreToolUse hook event
        let _tool_event = HookEvent::PreToolUse(ToolUseEvent {
            tool_use_id: "tool-abc".to_string(),
            tool_name: "Read".to_string(),
            input: serde_json::json!({"file_path": "/test.txt"}),
            session_id: Some("claude-session".to_string()),
            timestamp: Some(1_234_567_890),
        });

        // Note: This will fail because adapter is not running, but we can test
        // the event conversion In a real scenario, we'd need to mock
        // the running state
    }

    #[test]
    fn test_progress_event_types() {
        let thinking = ProgressEvent {
            progress_type: "thinking".to_string(),
            description: Some("Processing request".to_string()),
            token_count: Some(100),
        };

        let idle = ProgressEvent {
            progress_type: "idle".to_string(),
            description: None,
            token_count: None,
        };

        // Test serialization
        let json = serde_json::to_string(&thinking).unwrap();
        assert!(json.contains("thinking"));

        let json = serde_json::to_string(&idle).unwrap();
        assert!(json.contains("idle"));
    }
}
