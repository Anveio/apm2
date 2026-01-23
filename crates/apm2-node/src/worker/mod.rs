//! Worker adapters for holonic nodes.

mod claude;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use apm2_core::ledger::FileLedger;
pub use claude::ClaudeWorker;
use tokio::sync::RwLock;

/// Available worker adapter kinds.
#[derive(Debug, Clone, Copy)]
pub enum WorkerKind {
    /// Anthropic Claude CLI adapter.
    Claude,
}

impl WorkerKind {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "claude" => Some(Self::Claude),
            _ => None,
        }
    }
}

/// Worker configuration loaded from environment.
#[derive(Debug)]
pub enum WorkerAdapter {
    /// Claude CLI worker.
    Claude(ClaudeWorker),
}

impl WorkerAdapter {
    /// Build a worker adapter from environment variables.
    ///
    /// Returns `Ok(None)` when no worker adapter is configured.
    pub fn from_env(ledger: Arc<RwLock<FileLedger>>) -> Result<Option<Self>> {
        let kind = match std::env::var("APM2_WORKER") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => return Ok(None),
        };

        let kind = WorkerKind::parse(&kind)
            .with_context(|| format!("unsupported APM2_WORKER '{kind}'"))?;

        match kind {
            WorkerKind::Claude => {
                let command =
                    std::env::var("CLAUDE_COMMAND").unwrap_or_else(|_| "claude".to_string());
                let args = std::env::var("CLAUDE_ARGS")
                    .unwrap_or_default()
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                let workdir = std::env::var("CLAUDE_WORKDIR").ok().map(PathBuf::from);
                let prompt = std::env::var("CLAUDE_PROMPT")
                    .ok()
                    .filter(|s| !s.trim().is_empty());

                let worker = ClaudeWorker::new(claude::ClaudeWorkerConfig {
                    command,
                    args,
                    workdir,
                    prompt,
                    ledger,
                });
                Ok(Some(Self::Claude(worker)))
            },
        }
    }

    /// Run the configured worker adapter.
    pub async fn run(self) -> Result<()> {
        match self {
            Self::Claude(worker) => worker.run().await,
        }
    }
}
