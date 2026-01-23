//! Tamper-evident event ledger.
//!
//! Provides an append-only JSONL ledger with hash chaining.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Genesis marker for the first event in the chain.
pub const GENESIS_HASH: &str = "GENESIS";

/// Ledger event entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic sequence number (starts at 0).
    pub seq: u64,
    /// Hash of the previous event (or `GENESIS_HASH` for the first event).
    pub prev_hash: String,
    /// Arbitrary JSON payload.
    pub payload: serde_json::Value,
}

/// Ledger interface for appending and inspecting events.
pub trait Ledger {
    /// Append a new event to the ledger.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be written.
    fn append(&mut self, payload: serde_json::Value) -> Result<Event, LedgerError>;

    /// Return all known events.
    #[must_use]
    fn events(&self) -> &[Event];

    /// Return the last sequence number, if any.
    #[must_use]
    fn last_seq(&self) -> Option<u64>;
}

/// File-backed ledger stored in JSONL format.
#[derive(Debug)]
pub struct FileLedger {
    path: PathBuf,
    events: Vec<Event>,
}

impl FileLedger {
    /// Open an existing ledger or create a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or read.
    ///
    /// # Panics
    ///
    /// Panics if the ledger chain integrity is broken.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = resolve_ledger_path(path.as_ref());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(LedgerError::Io)?;
        }

        let events = if path.exists() {
            let events = read_events(&path)?;
            verify_chain_or_panic(&events);
            events
        } else {
            Vec::new()
        };

        Ok(Self { path, events })
    }

    /// Verify the chain integrity without panicking.
    ///
    /// # Errors
    ///
    /// Returns an error if the chain is invalid.
    pub fn verify(&self) -> Result<(), LedgerError> {
        verify_chain(&self.events)
    }

    /// Return the path to the ledger file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Ledger for FileLedger {
    fn append(&mut self, payload: serde_json::Value) -> Result<Event, LedgerError> {
        let (seq, prev_hash) = self.events.last().map_or_else(
            || (0, GENESIS_HASH.to_string()),
            |event| (event.seq + 1, hash_event(event)),
        );

        let event = Event {
            seq,
            prev_hash,
            payload,
        };

        let serialized = serde_json::to_string(&event).map_err(LedgerError::Serialize)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(LedgerError::Io)?;
        file.write_all(serialized.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(LedgerError::Io)?;
        file.flush().map_err(LedgerError::Io)?;

        self.events.push(event.clone());
        Ok(event)
    }

    fn events(&self) -> &[Event] {
        &self.events
    }

    fn last_seq(&self) -> Option<u64> {
        self.events.last().map(|event| event.seq)
    }
}

/// Ledger errors.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse error.
    #[error("failed to parse event: {0}")]
    Parse(#[from] serde_json::Error),

    /// JSON serialize error.
    #[error("failed to serialize event: {0}")]
    Serialize(serde_json::Error),

    /// Chain integrity error.
    #[error("ledger integrity error: {0}")]
    Integrity(String),
}

fn resolve_ledger_path(path: &Path) -> PathBuf {
    if path.exists() {
        if path.is_dir() {
            return path.join("events.jsonl");
        }
        return path.to_path_buf();
    }

    if path.file_name().and_then(|name| name.to_str()) == Some("events.jsonl") {
        return path.to_path_buf();
    }

    if path.extension().is_some() {
        return path.to_path_buf();
    }

    path.join("events.jsonl")
}

fn read_events(path: &Path) -> Result<Vec<Event>, LedgerError> {
    let file = std::fs::File::open(path).map_err(LedgerError::Io)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line_result in reader.lines() {
        let line = line_result.map_err(LedgerError::Io)?;
        if line.trim().is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(&line).map_err(LedgerError::Parse)?;
        events.push(event);
    }

    Ok(events)
}

fn verify_chain_or_panic(events: &[Event]) {
    if let Err(error) = verify_chain(events) {
        panic!("ledger chain integrity check failed: {error}");
    }
}

fn verify_chain(events: &[Event]) -> Result<(), LedgerError> {
    if events.is_empty() {
        return Ok(());
    }

    let first = &events[0];
    if first.seq != 0 {
        return Err(LedgerError::Integrity(format!(
            "expected first seq 0, got {}",
            first.seq
        )));
    }
    if first.prev_hash != GENESIS_HASH {
        return Err(LedgerError::Integrity(format!(
            "expected genesis prev_hash {}, got {}",
            GENESIS_HASH, first.prev_hash
        )));
    }

    for window in events.windows(2) {
        let prev = &window[0];
        let current = &window[1];
        if current.seq != prev.seq + 1 {
            return Err(LedgerError::Integrity(format!(
                "non-monotonic seq: {} followed by {}",
                prev.seq, current.seq
            )));
        }
        let expected = hash_event(prev);
        if current.prev_hash != expected {
            return Err(LedgerError::Integrity(format!(
                "hash mismatch at seq {}",
                current.seq
            )));
        }
    }

    Ok(())
}

fn hash_event(event: &Event) -> String {
    let payload = serde_json::to_vec(event).unwrap_or_default();
    let digest = Sha256::digest(payload);
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn test_append_and_reload() {
        let temp_dir = std::env::temp_dir().join(format!("apm2-ledger-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mut ledger = FileLedger::open(&temp_dir).unwrap();
        let first = ledger
            .append(json!({"type": "ChildConnected", "id": 1}))
            .unwrap();
        let second = ledger
            .append(json!({"type": "Heartbeat", "seq": 1}))
            .unwrap();

        assert_eq!(first.seq, 0);
        assert_eq!(second.seq, 1);
        assert_eq!(ledger.events().len(), 2);

        let reloaded = FileLedger::open(&temp_dir).unwrap();
        assert_eq!(reloaded.events().len(), 2);
        assert_eq!(reloaded.last_seq(), Some(1));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_tamper_detection_panics() {
        let temp_dir = std::env::temp_dir().join(format!("apm2-ledger-tamper-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mut ledger = FileLedger::open(&temp_dir).unwrap();
        ledger.append(json!({"type": "Alpha"})).unwrap();
        ledger.append(json!({"type": "Beta"})).unwrap();

        let ledger_path = resolve_ledger_path(&temp_dir);
        let mut lines: Vec<String> = std::fs::read_to_string(&ledger_path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        let mut tampered: Event = serde_json::from_str(&lines[0]).unwrap();
        tampered.payload = json!({"type": "Gamma"});
        lines[0] = serde_json::to_string(&tampered).unwrap();
        std::fs::write(&ledger_path, lines.join("\n") + "\n").unwrap();

        let result = std::panic::catch_unwind(|| {
            let _ = FileLedger::open(&temp_dir);
        });
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
