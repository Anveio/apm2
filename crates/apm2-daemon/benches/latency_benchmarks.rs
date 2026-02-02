//! Latency benchmarks for daemon control plane operations.
//!
//! This module implements the benchmark harness for RFC-0017 latency
//! requirements:
//!
//! - **BENCH-001**: Spawn acknowledgment latency <100ms p99 (REQ-DCP-0009)
//! - **BENCH-002**: Session ready latency <2s p99 (REQ-DCP-0010)
//! - **BENCH-003**: Tool mediation overhead <5ms p50 (REQ-DCP-0011)
//!
//! # Methodology
//!
//! Per `07_test_and_evidence.yaml`:
//!
//! - BENCH-001: Warm daemon, local Unix socket, 1000 iterations, measure time
//!   from `SpawnEpisode` call to `session_id` return.
//! - BENCH-002: Warm daemon, local Unix socket, 100 iterations, measure time
//!   from `SpawnEpisode` call to `sandbox_ready` signal.
//! - BENCH-003: Warm daemon, 10000 tool requests with no-op tool, measure time
//!   from `RequestTool` to validation complete.
//!
//! # Contract References
//!
//! - REQ-DCP-0009: Spawn Acknowledgment Latency
//! - REQ-DCP-0010: Session Ready Latency
//! - REQ-DCP-0011: Tool Mediation Overhead
//! - CTR-1303: Bounded collections with MAX_* constants

#![allow(missing_docs)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use apm2_daemon::episode::capability::StubManifestLoader;
use apm2_daemon::episode::envelope::RiskTier;
use apm2_daemon::episode::{
    BrokerToolRequest, CapabilityManifest, CapabilityManifestBuilder, DedupeKey, EpisodeId,
    EpisodeRuntime, EpisodeRuntimeConfig, ToolBroker, ToolBrokerConfig, ToolClass,
};
use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, black_box, criterion_group, criterion_main,
};

// =============================================================================
// Test Fixtures
// =============================================================================

/// Creates a minimal capability manifest for benchmarking.
fn create_test_manifest() -> CapabilityManifest {
    CapabilityManifestBuilder::new("bench-manifest")
        .build()
        .expect("failed to build test manifest")
}

/// Creates a minimal tool request for benchmarking tool mediation.
fn create_tool_request(request_id: &str, episode_id: &EpisodeId) -> BrokerToolRequest {
    BrokerToolRequest {
        request_id: request_id.to_string(),
        episode_id: episode_id.clone(),
        tool_class: ToolClass::Read,
        dedupe_key: DedupeKey::new(format!("dedupe-{request_id}")),
        args_hash: [0u8; 32],
        inline_args: None,
        path: Some(PathBuf::from("/tmp/bench-file.txt")),
        size: None,
        network: None,
        shell_command: None,
        risk_tier: RiskTier::Tier2,
    }
}

/// Creates an envelope hash for benchmarking.
fn create_envelope_hash(seed: u64) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let seed_bytes = seed.to_le_bytes();
    hash[..8].copy_from_slice(&seed_bytes);
    hash
}

/// Creates a test episode ID for tool mediation benchmarks.
fn create_test_episode_id(seed: u64) -> EpisodeId {
    EpisodeId::new(format!("ep-bench-{seed:016x}-0-1")).expect("failed to create episode ID")
}

/// Returns current timestamp in nanoseconds.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

// =============================================================================
// BENCH-001: Spawn Acknowledgment Latency
// =============================================================================

/// Benchmark spawn acknowledgment latency (`session_id` returned).
///
/// Per REQ-DCP-0009, `SpawnEpisode` MUST acknowledge with `session_id` within
/// <100ms p99 on a local Unix socket (warm daemon).
///
/// This benchmark measures the time to:
/// 1. Create an episode from an envelope
/// 2. Start the episode (obtain session handle with `session_id`)
///
/// # Methodology (BENCH-001)
///
/// - Warm daemon (runtime pre-created)
/// - 1000 iterations per sample
/// - Measure time from `create()` to `start()` completion
fn bench_spawn_ack_latency(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let mut group = c.benchmark_group("latency/spawn_ack");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));

    // Pre-create runtime (warm daemon simulation)
    let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(100_000);
    let runtime = Arc::new(rt.block_on(async { EpisodeRuntime::new(config) }));

    group.bench_function("create_and_start", |b| {
        let runtime = Arc::clone(&runtime);
        let mut counter = 0u64;

        b.iter(|| {
            counter += 1;
            let runtime = Arc::clone(&runtime);
            let envelope_hash = create_envelope_hash(counter);

            rt.block_on(async move {
                let timestamp_ns = now_ns();

                // Create episode (envelope registration)
                let episode_id = runtime
                    .create(black_box(envelope_hash), timestamp_ns)
                    .await
                    .expect("failed to create episode");

                // Start episode (session_id generation)
                let handle = runtime
                    .start(&episode_id, "lease-bench", timestamp_ns)
                    .await
                    .expect("failed to start episode");

                black_box(handle)
            })
        });
    });

    // Measure `create()` alone
    group.bench_function("create_only", |b| {
        let runtime = Arc::clone(&runtime);
        let mut counter = 0u64;

        b.iter(|| {
            counter += 1;
            let runtime = Arc::clone(&runtime);
            let envelope_hash = create_envelope_hash(counter);

            rt.block_on(async move {
                let timestamp_ns = now_ns();

                let episode_id = runtime
                    .create(black_box(envelope_hash), timestamp_ns)
                    .await
                    .expect("failed to create episode");

                black_box(episode_id)
            })
        });
    });

    // Measure `start()` alone (requires pre-created episode)
    group.bench_function("start_only", |b| {
        let runtime = Arc::clone(&runtime);

        b.iter_batched(
            || {
                // Setup: create an episode
                let runtime = Arc::clone(&runtime);
                rt.block_on(async move {
                    let envelope_hash = create_envelope_hash(rand::random());
                    let timestamp_ns = now_ns();

                    let episode_id = runtime
                        .create(envelope_hash, timestamp_ns)
                        .await
                        .expect("failed to create episode");

                    (runtime, episode_id, timestamp_ns)
                })
            },
            |(runtime, episode_id, timestamp_ns)| {
                rt.block_on(async move {
                    let handle = runtime
                        .start(&episode_id, "lease-bench", timestamp_ns)
                        .await
                        .expect("failed to start episode");

                    black_box(handle)
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// =============================================================================
// BENCH-002: Session Ready Latency
// =============================================================================

/// Benchmark session ready latency (pack sealed, policy checked, sandbox
/// ready).
///
/// Per REQ-DCP-0010, `SpawnEpisode` MUST complete session readiness within
/// <2s p99 on a local Unix socket (warm daemon).
///
/// This benchmark measures the complete session initialization flow:
/// 1. Create episode
/// 2. Start episode
/// 3. Initialize broker with capability manifest
///
/// # Methodology (BENCH-002)
///
/// - Warm daemon (runtime pre-created)
/// - 100 iterations per sample (longer operation)
/// - Measure time from `create()` to broker initialized (sandbox ready proxy)
fn bench_session_ready_latency(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let mut group = c.benchmark_group("latency/session_ready");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));

    // Pre-create runtime (warm daemon simulation)
    let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(100_000);

    group.bench_function("full_session_init", |b| {
        let mut counter = 0u64;

        b.iter(|| {
            counter += 1;
            let envelope_hash = create_envelope_hash(counter);
            let manifest = create_test_manifest();

            rt.block_on(async {
                let runtime = EpisodeRuntime::new(config.clone());
                let timestamp_ns = now_ns();

                // Step 1: Create episode
                let episode_id = runtime
                    .create(black_box(envelope_hash), timestamp_ns)
                    .await
                    .expect("failed to create episode");

                // Step 2: Start episode
                let handle = runtime
                    .start(&episode_id, "lease-bench", timestamp_ns)
                    .await
                    .expect("failed to start episode");

                // Step 3: Initialize broker (capability sealing proxy for sandbox ready)
                let broker: ToolBroker<StubManifestLoader> =
                    ToolBroker::new(ToolBrokerConfig::default());
                broker
                    .initialize_with_manifest(manifest)
                    .await
                    .expect("failed to initialize broker");

                black_box((handle, broker))
            })
        });
    });

    // Benchmark broker initialization alone
    group.bench_function("broker_init_only", |b| {
        b.iter(|| {
            let manifest = create_test_manifest();

            rt.block_on(async {
                let broker: ToolBroker<StubManifestLoader> =
                    ToolBroker::new(ToolBrokerConfig::default());
                broker
                    .initialize_with_manifest(black_box(manifest))
                    .await
                    .expect("failed to initialize broker");

                black_box(broker)
            })
        });
    });

    group.finish();
}

// =============================================================================
// BENCH-003: Tool Mediation Overhead
// =============================================================================

/// Benchmark tool mediation overhead (excluding tool execution time).
///
/// Per REQ-DCP-0011, tool mediation overhead MUST be <5ms p50.
///
/// This benchmark measures the broker request path:
/// 1. Request validation
/// 2. Capability check
/// 3. Policy evaluation
/// 4. Dedupe cache lookup
///
/// # Methodology (BENCH-003)
///
/// - Warm daemon (broker pre-initialized)
/// - 10000 tool requests with no-op validation
/// - Measure time from `request()` call to decision return
fn bench_tool_mediation_overhead(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let mut group = c.benchmark_group("latency/tool_mediation");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(1000);
    group.throughput(Throughput::Elements(1));
    group.measurement_time(Duration::from_secs(10));

    // Pre-initialize broker (warm daemon simulation)
    let broker = rt.block_on(async {
        let manifest = create_test_manifest();
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(ToolBrokerConfig::default().without_dedupe_cache());
        broker
            .initialize_with_manifest(manifest)
            .await
            .expect("failed to initialize broker");
        Arc::new(broker)
    });

    // Create a test episode ID for requests
    let test_episode_id = create_test_episode_id(12345);

    group.bench_function("request_validation", |b| {
        let broker = Arc::clone(&broker);
        let episode_id = test_episode_id.clone();
        let mut counter = 0u64;

        b.iter(|| {
            counter += 1;
            let broker = Arc::clone(&broker);
            let request = create_tool_request(&format!("req-{counter}"), &episode_id);

            rt.block_on(async move {
                let timestamp_ns = now_ns();

                let decision = broker
                    .request(black_box(&request), timestamp_ns, None)
                    .await;

                black_box(decision)
            })
        });
    });

    // Benchmark with dedupe cache enabled
    let broker_with_cache = rt.block_on(async {
        let manifest = create_test_manifest();
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());
        broker
            .initialize_with_manifest(manifest)
            .await
            .expect("failed to initialize broker");
        Arc::new(broker)
    });

    group.bench_function("request_with_dedupe_cache", |b| {
        let broker = Arc::clone(&broker_with_cache);
        let episode_id = test_episode_id.clone();
        let mut counter = 0u64;

        b.iter(|| {
            counter += 1;
            let broker = Arc::clone(&broker);
            let request = create_tool_request(&format!("req-cache-{counter}"), &episode_id);

            rt.block_on(async move {
                let timestamp_ns = now_ns();

                let decision = broker
                    .request(black_box(&request), timestamp_ns, None)
                    .await;

                black_box(decision)
            })
        });
    });

    // Benchmark dedupe cache hit path (same request twice)
    group.bench_function("dedupe_cache_hit", |b| {
        let broker = Arc::clone(&broker_with_cache);
        let episode_id = test_episode_id.clone();

        b.iter_batched(
            || {
                // Setup: Make first request to populate cache
                let broker = Arc::clone(&broker);
                let request_id = format!("dedupe-{}", rand::random::<u64>());
                let request = create_tool_request(&request_id, &episode_id);

                rt.block_on(async {
                    let timestamp_ns = now_ns();

                    // First request - should be allowed/denied (not cached)
                    let _ = broker.request(&request, timestamp_ns, None).await;

                    (broker, request, timestamp_ns)
                })
            },
            |(broker, request, timestamp_ns)| {
                rt.block_on(async move {
                    // Second request - should hit dedupe cache
                    let decision = broker
                        .request(black_box(&request), timestamp_ns + 1, None)
                        .await;

                    black_box(decision)
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// =============================================================================
// Scaling Benchmarks
// =============================================================================

/// Benchmark spawn latency scaling with concurrent episodes.
///
/// This measures how spawn latency degrades as the number of concurrent
/// episodes increases. Per CTR-1303, the runtime must handle up to
/// `MAX_CONCURRENT_EPISODES` (10,000) episodes.
fn bench_spawn_scaling(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let mut group = c.benchmark_group("latency/spawn_scaling");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(50);

    for episode_count in [10, 100, 1000, 5000] {
        let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(100_000);
        let runtime = Arc::new(rt.block_on(async { EpisodeRuntime::new(config) }));

        // Pre-populate with episodes
        rt.block_on(async {
            for i in 0..episode_count {
                let envelope_hash = create_envelope_hash(u64::try_from(i).unwrap_or(0));
                let timestamp_ns = now_ns();

                let episode_id = runtime
                    .create(envelope_hash, timestamp_ns)
                    .await
                    .expect("failed to create episode");

                runtime
                    .start(&episode_id, format!("lease-{i}"), timestamp_ns)
                    .await
                    .expect("failed to start episode");
            }
        });

        group.bench_with_input(
            BenchmarkId::from_parameter(episode_count),
            &episode_count,
            |b, _| {
                let runtime = Arc::clone(&runtime);
                let mut counter = u64::try_from(episode_count).unwrap_or(0);

                b.iter(|| {
                    counter += 1;
                    let runtime = Arc::clone(&runtime);
                    let envelope_hash = create_envelope_hash(counter);

                    rt.block_on(async move {
                        let timestamp_ns = now_ns();

                        let episode_id = runtime
                            .create(black_box(envelope_hash), timestamp_ns)
                            .await
                            .expect("failed to create episode");

                        let handle = runtime
                            .start(&episode_id, "lease-scale", timestamp_ns)
                            .await
                            .expect("failed to start episode");

                        black_box(handle)
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark tool mediation throughput under load.
///
/// This measures how many tool mediation requests can be processed per second
/// with varying batch sizes.
fn bench_mediation_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let mut group = c.benchmark_group("latency/mediation_throughput");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(50);

    // Pre-initialize broker
    let broker = rt.block_on(async {
        let manifest = create_test_manifest();
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(ToolBrokerConfig::default().without_dedupe_cache());
        broker
            .initialize_with_manifest(manifest)
            .await
            .expect("failed to initialize broker");
        Arc::new(broker)
    });

    // Create a test episode ID for requests
    let test_episode_id = create_test_episode_id(67890);

    for batch_size in [10, 50, 100, 500] {
        group.throughput(Throughput::Elements(u64::try_from(batch_size).unwrap_or(0)));

        let episode_id = test_episode_id.clone();
        group.bench_with_input(
            BenchmarkId::new("batch", batch_size),
            &batch_size,
            |b, &size| {
                let broker = Arc::clone(&broker);
                let episode_id = episode_id.clone();
                let mut batch_counter = 0u64;

                b.iter(|| {
                    batch_counter += 1;
                    let broker = Arc::clone(&broker);
                    let episode_id = episode_id.clone();

                    rt.block_on(async move {
                        let timestamp_ns = now_ns();

                        let mut results = Vec::with_capacity(size);
                        for i in 0..size {
                            let request = create_tool_request(
                                &format!("batch-{batch_counter}-{i}"),
                                &episode_id,
                            );
                            let decision = broker
                                .request(black_box(&request), timestamp_ns, None)
                                .await;
                            results.push(decision);
                        }

                        black_box(results)
                    })
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Criterion Groups
// =============================================================================

criterion_group!(
    name = spawn_benchmarks;
    config = Criterion::default()
        .with_output_color(true)
        .significance_level(0.05)
        .noise_threshold(0.02);
    targets = bench_spawn_ack_latency, bench_session_ready_latency, bench_spawn_scaling
);

criterion_group!(
    name = mediation_benchmarks;
    config = Criterion::default()
        .with_output_color(true)
        .significance_level(0.05)
        .noise_threshold(0.02);
    targets = bench_tool_mediation_overhead, bench_mediation_throughput
);

criterion_main!(spawn_benchmarks, mediation_benchmarks);
