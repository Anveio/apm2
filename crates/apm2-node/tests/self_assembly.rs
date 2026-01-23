//! Self-assembly integration test for holonic nodes.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use apm2_core::identity::NodeIdentity;
use serde_json::Value;
use uuid::Uuid;

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    const fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn kill_and_wait(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

#[test]
#[allow(clippy::similar_names)]
fn self_assembly_roundtrip() -> Result<()> {
    let node_bin = env!("CARGO_BIN_EXE_apm2-node");

    let base_dir = std::env::temp_dir().join(format!("apm2-self-assembly-{}", Uuid::new_v4()));
    let node_a_dir = base_dir.join("node-a");
    let node_b_dir = base_dir.join("node-b");
    std::fs::create_dir_all(&node_a_dir).context("create node A dir")?;
    std::fs::create_dir_all(&node_b_dir).context("create node B dir")?;

    let mut node_a = spawn_node(
        node_bin,
        "127.0.0.1:3000",
        "http://127.0.0.1:3000",
        &node_a_dir,
        None,
    )?;
    thread::sleep(Duration::from_secs(1));

    let mut node_b = spawn_node(
        node_bin,
        "127.0.0.1:3001",
        "http://127.0.0.1:3001",
        &node_b_dir,
        Some("http://127.0.0.1:3000"),
    )?;

    thread::sleep(Duration::from_secs(10));

    let node_b_identity_before = load_identity(&node_b_dir)?;
    let node_b_events_before = read_events(&node_b_dir)?;

    node_b.kill_and_wait();
    thread::sleep(Duration::from_secs(1));

    let mut node_b = spawn_node(
        node_bin,
        "127.0.0.1:3001",
        "http://127.0.0.1:3001",
        &node_b_dir,
        Some("http://127.0.0.1:3000"),
    )?;

    thread::sleep(Duration::from_secs(8));

    let node_a_events = read_events(&node_a_dir)?;
    let node_b_identity_after = load_identity(&node_b_dir)?;
    let node_b_events_after = read_events(&node_b_dir)?;

    assert!(
        node_a_events.iter().any(|event| {
            event
                .get("payload")
                .and_then(Value::as_object)
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
                == Some("ChildConnected")
        }),
        "Node A ledger did not record ChildConnected"
    );

    assert_eq!(
        node_b_identity_before.id, node_b_identity_after.id,
        "Node B ActorId changed after restart"
    );

    assert!(
        node_b_events_after.len() > node_b_events_before.len(),
        "Node B did not append heartbeat events after restart"
    );

    assert_contiguous_sequences(&node_b_events_after)?;

    node_b.kill_and_wait();
    node_a.kill_and_wait();
    let _ = std::fs::remove_dir_all(&base_dir);

    Ok(())
}

fn spawn_node(
    node_bin: &str,
    addr: &str,
    public_url: &str,
    data_dir: &Path,
    parent_url: Option<&str>,
) -> Result<ChildGuard> {
    let mut command = Command::new(node_bin);
    command
        .env("NODE_ADDR", addr)
        .env("NODE_URL", public_url)
        .env("NODE_DATA_DIR", data_dir)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(parent_url) = parent_url {
        command.env("PARENT_URL", parent_url);
    }

    let child = command.spawn().context("failed to spawn apm2-node")?;
    Ok(ChildGuard::new(child))
}

fn load_identity(dir: &Path) -> Result<NodeIdentity> {
    let path = dir.join("identity.json");
    let content = std::fs::read_to_string(&path).context("read identity.json")?;
    let identity: NodeIdentity = serde_json::from_str(&content).context("parse identity.json")?;
    Ok(identity)
}

fn read_events(dir: &Path) -> Result<Vec<Value>> {
    let path = dir.join("events.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&path).context("read events.jsonl")?;
    let mut events = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(line).context("parse event json")?;
        events.push(event);
    }
    Ok(events)
}

fn assert_contiguous_sequences(events: &[Value]) -> Result<()> {
    for (index, event) in events.iter().enumerate() {
        let seq = event
            .get("seq")
            .and_then(Value::as_u64)
            .context("event missing seq")?;
        let expected = index as u64;
        if seq != expected {
            anyhow::bail!("non-contiguous ledger seq: expected {expected}, got {seq}");
        }
    }
    Ok(())
}
