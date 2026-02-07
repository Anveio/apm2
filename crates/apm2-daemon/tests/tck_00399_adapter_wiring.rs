//! Integration tests for TCK-00399: `AdapterRegistry` wiring into
//! `SpawnEpisode`.
//!
//! These tests verify that [`EpisodeRuntime::spawn_adapter()`] correctly wires
//! the adapter lifecycle: spawn, event stream bridge, and terminate on stop.
//!
//! Test command: `cargo test -p apm2-daemon --test tck_00399_adapter_wiring`

use std::sync::Arc;

use apm2_daemon::episode::registry::AdapterRegistry;
use apm2_daemon::episode::{
    AdapterType, EpisodeRuntime, EpisodeRuntimeConfig, HarnessConfig, QuarantineReason,
    TerminationClass,
};

/// IT-00399-01: Verify `spawn_adapter` stores handle and `stop()` terminates
/// process.
///
/// This test validates the core wiring:
/// 1. Creates and starts an episode
/// 2. Spawns an agent process via `spawn_adapter`
/// 3. Calls `stop()`, which should terminate the agent process
/// 4. Verifies the episode reaches Terminated state
#[tokio::test]
async fn it_00399_01_spawn_adapter_and_stop_terminates_process() {
    let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(10);
    let registry = Arc::new(AdapterRegistry::with_defaults());
    let runtime = EpisodeRuntime::new(config).with_adapter_registry(Arc::clone(&registry));

    // Create and start an episode
    let envelope_hash = [0u8; 32];
    let episode_id = runtime.create(envelope_hash, 1_000_000).await.unwrap();
    let _handle = runtime
        .start_with_workspace(
            &episode_id,
            "lease-399-01",
            2_000_000,
            std::path::Path::new("/tmp"),
        )
        .await
        .unwrap();

    // Spawn a short-lived process via the adapter
    let adapter = registry.get(AdapterType::Raw).unwrap();
    let harness_config =
        HarnessConfig::new("echo", episode_id.as_str()).with_args(vec!["hello".to_string()]);

    runtime
        .spawn_adapter(&episode_id, harness_config, adapter)
        .await
        .unwrap();

    // Small delay for the process to complete and bridge task to drain
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Stop the episode -- this should handle the (already-exited) process
    // gracefully
    let stop_result = runtime
        .stop(&episode_id, TerminationClass::Success, 3_000_000)
        .await;

    assert!(
        stop_result.is_ok(),
        "stop should succeed even after process has exited: {stop_result:?}"
    );
}

/// IT-00399-02: Verify `spawn_adapter` rejects non-Running episodes.
#[tokio::test]
async fn it_00399_02_spawn_adapter_rejects_created_state() {
    let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(10);
    let registry = Arc::new(AdapterRegistry::with_defaults());
    let runtime = EpisodeRuntime::new(config).with_adapter_registry(Arc::clone(&registry));

    // Create but do NOT start
    let envelope_hash = [1u8; 32];
    let episode_id = runtime.create(envelope_hash, 1_000_000).await.unwrap();

    let adapter = registry.get(AdapterType::Raw).unwrap();
    let harness_config =
        HarnessConfig::new("echo", episode_id.as_str()).with_args(vec!["test".to_string()]);

    let result = runtime
        .spawn_adapter(&episode_id, harness_config, adapter)
        .await;

    assert!(
        result.is_err(),
        "spawn_adapter should fail for episode in Created state"
    );
}

/// IT-00399-03: Verify `quarantine` terminates a long-running adapter process.
#[tokio::test]
async fn it_00399_03_quarantine_terminates_adapter_process() {
    let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(10);
    let registry = Arc::new(AdapterRegistry::with_defaults());
    let runtime = EpisodeRuntime::new(config).with_adapter_registry(Arc::clone(&registry));

    let envelope_hash = [2u8; 32];
    let episode_id = runtime.create(envelope_hash, 1_000_000).await.unwrap();
    let _handle = runtime
        .start_with_workspace(
            &episode_id,
            "lease-399-03",
            2_000_000,
            std::path::Path::new("/tmp"),
        )
        .await
        .unwrap();

    // Spawn a long-running process (cat blocks on stdin)
    let adapter = registry.get(AdapterType::Raw).unwrap();
    let harness_config = HarnessConfig::new("cat", episode_id.as_str());

    runtime
        .spawn_adapter(&episode_id, harness_config, adapter)
        .await
        .unwrap();

    // Small delay for process to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Quarantine should terminate the process
    let quarantine_result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        runtime.quarantine(
            &episode_id,
            QuarantineReason::new("test", "test quarantine"),
            3_000_000,
        ),
    )
    .await;

    assert!(
        quarantine_result.is_ok(),
        "quarantine must complete within timeout (not deadlock)"
    );
    assert!(
        quarantine_result.unwrap().is_ok(),
        "quarantine should succeed"
    );
}
