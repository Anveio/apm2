//! Claude CLI worker adapter.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use apm2_core::ledger::{FileLedger, Ledger};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{error, info, warn};

/// Configuration for the Claude worker.
#[derive(Debug)]
pub struct ClaudeWorkerConfig {
    /// Claude CLI command path.
    pub command: String,
    /// CLI arguments.
    pub args: Vec<String>,
    /// Optional working directory.
    pub workdir: Option<PathBuf>,
    /// Optional prompt to send to stdin on startup.
    pub prompt: Option<String>,
    /// Ledger for event persistence.
    pub ledger: Arc<RwLock<FileLedger>>,
}

/// Claude worker adapter.
#[derive(Debug)]
pub struct ClaudeWorker {
    config: ClaudeWorkerConfig,
}

impl ClaudeWorker {
    /// Create a new Claude worker.
    #[must_use]
    pub const fn new(config: ClaudeWorkerConfig) -> Self {
        Self { config }
    }

    /// Run the Claude worker until it exits.
    pub async fn run(self) -> Result<()> {
        let command_label = sanitize_command_label(&self.config.command);
        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(workdir) = &self.config.workdir {
            cmd.current_dir(workdir);
        }

        info!(command = %command_label, "starting Claude worker");

        let mut child = cmd.spawn().context("failed to spawn claude worker")?;
        let pid = child.id();

        let started_event = json!({
            "type": "WorkerStarted",
            "worker": "claude",
            "command": command_label,
            "args_count": self.config.args.len(),
            "pid": pid,
            "started_at": now_epoch_secs(),
        });
        let result = self.config.ledger.write().await.append(started_event);
        if let Err(err) = result {
            error!(error = %err, "failed to append worker started event");
        }

        if let Some(prompt) = &self.config.prompt {
            if let Some(mut stdin) = child.stdin.take() {
                let prompt_len = prompt.len();
                if let Err(err) = stdin.write_all(prompt.as_bytes()).await {
                    warn!(error = %err, "failed to write prompt to Claude stdin");
                } else if let Err(err) = stdin.write_all(b"\n").await {
                    warn!(error = %err, "failed to terminate Claude prompt");
                }

                let event = json!({
                    "type": "WorkerPromptSent",
                    "worker": "claude",
                    "pid": pid,
                    "bytes": prompt_len,
                    "sent_at": now_epoch_secs(),
                });
                let result = self.config.ledger.write().await.append(event);
                if let Err(err) = result {
                    error!(error = %err, "failed to append prompt event");
                }
            }
        }

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let ledger = Arc::clone(&self.config.ledger);

        if let Some(stdout) = stdout {
            let ledger = Arc::clone(&ledger);
            tokio::spawn(async move {
                if let Err(err) = stream_output(stdout, ledger, "stdout", pid).await {
                    error!(error = %err, "failed to read Claude stdout");
                }
            });
        }

        if let Some(stderr) = stderr {
            let ledger = Arc::clone(&ledger);
            tokio::spawn(async move {
                if let Err(err) = stream_output(stderr, ledger, "stderr", pid).await {
                    error!(error = %err, "failed to read Claude stderr");
                }
            });
        }

        let status = child
            .wait()
            .await
            .context("failed to wait for Claude worker")?;
        let exit_event = json!({
            "type": "WorkerExited",
            "worker": "claude",
            "pid": pid,
            "code": status.code(),
            "success": status.success(),
            "exited_at": now_epoch_secs(),
        });
        let result = self.config.ledger.write().await.append(exit_event);
        if let Err(err) = result {
            error!(error = %err, "failed to append worker exit event");
        }

        if !status.success() {
            warn!(status = %status, "Claude worker exited with error");
        }

        sleep(Duration::from_millis(100)).await;
        Ok(())
    }
}

async fn stream_output<R>(
    reader: R,
    ledger: Arc<RwLock<FileLedger>>,
    stream: &str,
    pid: Option<u32>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }

        let event = json!({
            "type": "WorkerOutput",
            "worker": "claude",
            "pid": pid,
            "stream": stream,
            "bytes": line.len(),
            "received_at": now_epoch_secs(),
        });

        let result = ledger.write().await.append(event);
        if let Err(err) = result {
            error!(error = %err, "failed to append worker output event");
        }
    }
    Ok(())
}

fn sanitize_command_label(command: &str) -> String {
    Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
        .to_string()
}

fn now_epoch_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
