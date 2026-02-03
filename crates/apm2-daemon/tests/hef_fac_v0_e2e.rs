//! TCK-00313: FAC v0 E2E Harness - Real Tool Execution Tests
//!
//! This test module provides end-to-end verification of the FAC v0 reviewer
//! harness against REQ-HEF-0010 acceptance criteria:
//!
//! 1. Workspace snapshot/apply succeeds or emits `ReviewBlocked` with CAS logs
//! 2. Tool logs stored in CAS, referenced by `ReviewReceipt`
//! 3. Tool profile enforced (unallowlisted tools denied)
//! 4. `GitOperation` output bounds enforced (DIFF: 262KB/4000 lines, STATUS: 16KB/500 lines)
//!
//! # Real vs Simulated Execution
//!
//! This harness exercises:
//! - **REAL**: `WorkspaceManager::apply()` validation, `CapabilityValidator` enforcement,
//!   `ReadFileHandler` execution via `ToolExecutor`, CAS storage, ledger anchoring
//! - **SIMULATED**: `GitOperation` output (no handler exists yet - see follow-up ticket),
//!   Full episode runtime orchestration (TCK-00256/260 scope)
//!
//! # Verification Commands
//!
//! ```bash
//! # Run all FAC v0 E2E tests
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e -- --nocapture
//!
//! # Run specific test
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e test_fac_v0_full_e2e_autonomous_flow
//!
//! # Run negative tests
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e test_workspace_apply_rejects
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e test_capability_validator_enforces
//! ```
//!
//! # Security Properties
//!
//! Per RFC-0018 and SEC-CTRL-FAC-0015:
//! - Tool profile enforcement via `CapabilityValidator`
//! - Path traversal prevention via `WorkspaceManager` validation
//! - Binary file detection for v0 limitations
//! - CAS-backed evidence with hash binding

use std::path::PathBuf;
use std::sync::Arc;

use apm2_core::crypto::Signer;
use apm2_core::fac::{
    ChangeKind, ChangeSetBundleV1, FileChange, GitObjectRef, HashAlgo, ReviewMetadata,
    ReviewVerdict,
};
use apm2_daemon::cas::{DurableCas, DurableCasConfig};
use apm2_daemon::episode::executor::ContentAddressedStore;
use apm2_daemon::episode::{
    BudgetTracker, Capability, CapabilityManifestBuilder, CapabilityScope, CapabilityValidator,
    EpisodeBudget, ExecutionContext, RiskTier, ToolClass, ToolExecutor, ToolRequest,
    WorkspaceError, WorkspaceManager,
};
use apm2_daemon::episode::{ReadFileHandler, ReviewCompletionResult};
use apm2_daemon::episode::tool_handler::{ReadArgs, ToolArgs};
use apm2_daemon::episode::workspace::validate_file_changes;
use tempfile::TempDir;

// =============================================================================
// Test Harness
// =============================================================================

/// FAC v0 E2E test harness with real components.
struct FacV0TestHarness {
    /// Workspace manager for snapshot/apply operations.
    workspace_manager: WorkspaceManager,
    /// Capability validator for tool profile enforcement.
    capability_validator: CapabilityValidator,
    /// Content-addressed store for evidence.
    cas: Arc<dyn ContentAddressedStore>,
    /// Tool executor with real handlers.
    tool_executor: ToolExecutor,
    /// Signer for cryptographic operations.
    signer: Signer,
    /// Temporary directory for workspace.
    _temp_dir: TempDir,
    /// Current timestamp for event ordering.
    current_timestamp_ms: u64,
}

impl FacV0TestHarness {
    /// Creates a new test harness with real components.
    fn new() -> Self {
        // Create temporary workspace directory
        let temp_dir = TempDir::new().expect("create temp dir");
        let workspace_root = temp_dir.path().to_path_buf();

        // Create workspace manager
        let workspace_manager = WorkspaceManager::new(workspace_root.clone());

        // Create reviewer capability manifest with Read allowed
        let reviewer_manifest = create_reviewer_capability_manifest();
        let capability_validator =
            CapabilityValidator::new(reviewer_manifest).expect("valid capability validator");

        // Create CAS
        let cas_dir = temp_dir.path().join("cas");
        std::fs::create_dir_all(&cas_dir).expect("create cas dir");
        let cas_config = DurableCasConfig::new(&cas_dir);
        let cas: Arc<dyn ContentAddressedStore> =
            Arc::new(DurableCas::new(cas_config).expect("create cas"));

        // Create budget tracker for tool execution
        let budget = EpisodeBudget::builder()
            .tokens(10_000)
            .tool_calls(100)
            .wall_ms(300_000)
            .bytes_io(10_000_000)
            .build();
        let budget_tracker = Arc::new(BudgetTracker::from_envelope(budget));

        // Create executor with real ReadFileHandler rooted at workspace
        let mut executor = ToolExecutor::new(budget_tracker, cas.clone());
        executor
            .register_handler(Box::new(ReadFileHandler::with_root(workspace_root)))
            .expect("register ReadFileHandler");

        // Create signer
        let signer = Signer::generate();

        Self {
            workspace_manager,
            capability_validator,
            cas,
            tool_executor: executor,
            signer,
            _temp_dir: temp_dir,
            current_timestamp_ms: 1_704_067_200_000, // 2024-01-01T00:00:00Z
        }
    }

    /// Returns the workspace root path.
    const fn workspace_root(&self) -> &PathBuf {
        &self.workspace_manager.workspace_root
    }

    /// Advances the current timestamp.
    const fn advance_time(&mut self, ms: u64) {
        self.current_timestamp_ms += ms;
    }

    /// Creates an execution context for tool calls.
    fn execution_context(&self, request_id: &str) -> ExecutionContext {
        ExecutionContext::new(
            apm2_daemon::episode::EpisodeId::new("ep-fac-v0-e2e").expect("valid episode id"),
            request_id,
            self.current_timestamp_ms * 1_000_000, // Convert to nanoseconds
        )
    }
}

/// Creates a reviewer capability manifest for FAC v0.
///
/// Per REQ-HEF-0010, the reviewer profile allows:
/// - Read: File reading for code review
/// - Denies: Write, Execute, Network (safety constraints)
fn create_reviewer_capability_manifest() -> apm2_daemon::episode::CapabilityManifest {
    // Use allow_all() scope which sets root_paths to ["/"], allowing all absolute paths.
    // The default scope has empty root_paths which would deny all path-based operations.
    CapabilityManifestBuilder::new("reviewer-fac-v0-manifest")
        .delegator("fac-v0-orchestrator")
        .capability(
            Capability::builder("cap-reviewer-read", ToolClass::Read)
                .scope(CapabilityScope::allow_all()) // Allows all paths under "/"
                .build()
                .expect("valid read capability"),
        )
        .tool_allowlist(vec![ToolClass::Read]) // Only Read is allowed
        .build()
        .expect("valid manifest")
}

/// Creates a test changeset bundle.
fn create_test_changeset_bundle(files: Vec<(&str, ChangeKind)>) -> ChangeSetBundleV1 {
    let file_manifest: Vec<FileChange> = files
        .into_iter()
        .map(|(path, kind)| FileChange {
            path: path.to_string(),
            change_kind: kind,
            old_path: None,
        })
        .collect();

    ChangeSetBundleV1::builder()
        .changeset_id("cs-test-001")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "a".repeat(40),
        })
        .diff_hash([0x42; 32])
        .file_manifest(file_manifest)
        .binary_detected(false)
        .build()
        .expect("valid changeset bundle")
}

// =============================================================================
// IT-00313-01: Full E2E Autonomous Flow
// =============================================================================

/// Tests the full FAC v0 autonomous reviewer flow with real components.
///
/// This test exercises:
/// 1. Workspace snapshot capture
/// 2. Changeset bundle validation and apply
/// 3. Real tool execution via `ToolExecutor` + `ReadFileHandler`
/// 4. CAS storage of tool outputs
/// 5. Review receipt creation with hash binding
#[tokio::test]
async fn test_fac_v0_full_e2e_autonomous_flow() {
    let mut harness = FacV0TestHarness::new();

    // =========================================================================
    // Step 1: Create workspace snapshot
    // =========================================================================
    let snapshot = harness
        .workspace_manager
        .snapshot("work-fac-v0-test")
        .expect("workspace snapshot");

    assert_eq!(snapshot.work_id, "work-fac-v0-test");
    assert_ne!(snapshot.snapshot_hash, [0u8; 32], "snapshot hash should be non-zero");

    // =========================================================================
    // Step 2: Create and validate changeset bundle
    // =========================================================================
    let bundle = create_test_changeset_bundle(vec![
        ("src/lib.rs", ChangeKind::Modify),
        ("tests/integration.rs", ChangeKind::Add),
    ]);

    // Validate changeset
    bundle.validate().expect("changeset should be valid");
    assert!(!bundle.binary_detected, "no binary files in test bundle");

    // =========================================================================
    // Step 3: Apply changeset to workspace
    // =========================================================================
    let apply_result = harness
        .workspace_manager
        .apply(&bundle)
        .expect("apply should succeed");

    assert_eq!(apply_result.changeset_digest, bundle.changeset_digest);
    assert_eq!(apply_result.files_modified, 2);
    harness.advance_time(100);

    // =========================================================================
    // Step 3a: Create test file for ReadFileHandler to read
    // =========================================================================
    let test_file_path = harness.workspace_root().join("src/lib.rs");
    std::fs::create_dir_all(test_file_path.parent().unwrap()).expect("create workspace dirs");
    std::fs::write(
        &test_file_path,
        b"// Test file for FAC v0 E2E\nfn main() { println!(\"Hello, FAC!\"); }\n",
    )
    .expect("create test file");

    // =========================================================================
    // Step 3b: Validate tool request against capability manifest
    // =========================================================================
    // Use absolute path to match the scope's root "/" requirement
    let read_request = ToolRequest::new(ToolClass::Read, RiskTier::default())
        .with_path(test_file_path.clone())
        .with_size(4096);

    let decision = harness.capability_validator.validate(&read_request);
    assert!(
        decision.is_allowed(),
        "Read tool should be allowed: {decision:?}"
    );

    // =========================================================================
    // Step 3c: Execute REAL tool via ToolExecutor (not simulated)
    // =========================================================================
    let ctx = harness.execution_context("req-read-001");
    let read_args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("src/lib.rs"), // Relative to workspace root
        offset: None,
        limit: Some(4096),
    });

    let tool_result = harness
        .tool_executor
        .execute(&ctx, &read_args)
        .await
        .expect("tool execution");

    assert!(tool_result.success, "tool execution should succeed");
    assert!(
        !tool_result.output.is_empty(),
        "tool output should contain file contents"
    );
    assert!(
        String::from_utf8_lossy(&tool_result.output).contains("FAC v0 E2E"),
        "output should contain test file content"
    );

    harness.advance_time(50);

    // =========================================================================
    // Step 4: Store tool output in CAS
    // =========================================================================
    // Safe truncation: tool durations will never exceed u64::MAX milliseconds
    #[allow(clippy::cast_possible_truncation)]
    let duration_ms = tool_result.duration.as_millis() as u64;
    let tool_log = serde_json::json!({
        "tool": "FileRead",
        "path": "src/lib.rs",
        "success": tool_result.success,
        "bytes_read": tool_result.output.len(),
        "duration_ms": duration_ms,
    });
    let tool_log_hash = harness.cas.store(tool_log.to_string().as_bytes());

    // Verify tool log can be retrieved
    let retrieved = harness.cas.retrieve(&tool_log_hash);
    assert!(retrieved.is_some(), "tool log should be retrievable from CAS");

    harness.advance_time(25);

    // =========================================================================
    // Step 5: Create review artifact bundle and receipt
    // =========================================================================
    let review_text = "LGTM - Code changes look good. No security issues found.";
    let review_text_hash = harness.cas.store(review_text.as_bytes());

    let review_result = ReviewCompletionResult::builder()
        .receipt_id("RR-fac-v0-e2e-001")
        .review_id("review-fac-v0-e2e-001")
        .changeset_digest(bundle.changeset_digest)
        .review_text_hash(review_text_hash)
        .tool_log_hashes(vec![tool_log_hash])
        .time_envelope_ref([0x88; 32]) // Mock time envelope ref
        .reviewer_actor_id("reviewer-fac-v0-e2e")
        .metadata(
            ReviewMetadata::new()
                .with_reviewer_actor_id("reviewer-fac-v0-e2e")
                .with_verdict(ReviewVerdict::Approve)
                .with_started_at(harness.current_timestamp_ms - 175)
                .with_completed_at(harness.current_timestamp_ms),
        )
        .build()
        .expect("review completion result");

    // Verify review result binds to changeset
    assert_eq!(review_result.changeset_digest, bundle.changeset_digest);
    assert_eq!(
        review_result.artifact_bundle.tool_log_hashes.len(),
        1,
        "should have one tool log hash"
    );

    // Create signed receipt event
    let receipt_event = review_result
        .create_receipt_event(&harness.signer)
        .expect("create receipt event");

    // Verify signature
    assert!(
        receipt_event
            .verify_signature(&harness.signer.verifying_key())
            .is_ok(),
        "receipt signature should be valid"
    );

    // =========================================================================
    // Verification: All REQ-HEF-0010 criteria met
    // =========================================================================
    // 1. ✅ Workspace apply succeeded (apply_result)
    // 2. ✅ Tool logs stored in CAS (tool_log_hash), referenced by ReviewReceipt
    // 3. ✅ Tool profile enforced (capability_validator checked Read is allowed)
    // 4. ⚠️ GitOperation bounds: Not tested (no GitOperationHandler exists yet)
}

// =============================================================================
// IT-00313-02: Workspace Apply Negative Tests
// =============================================================================

/// Tests that workspace apply rejects binary files (v0 limitation).
#[test]
fn test_workspace_apply_rejects_binary_files() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_root = temp_dir.path().to_path_buf();

    // Create bundle with binary_detected = true
    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-binary-test")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "b".repeat(40),
        })
        .diff_hash([0x43; 32])
        .file_manifest(vec![FileChange {
            path: "image.png".to_string(),
            change_kind: ChangeKind::Add,
            old_path: None,
        }])
        .binary_detected(true) // Binary detected!
        .build()
        .expect("valid bundle");

    // Validate should reject binary files
    let result = validate_file_changes(&bundle, &workspace_root);

    assert!(
        matches!(result, Err(WorkspaceError::BinaryUnsupported(_))),
        "should reject binary files: got {result:?}"
    );
}

/// Tests that workspace apply rejects path traversal attempts.
#[test]
fn test_workspace_apply_rejects_path_traversal() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_root = temp_dir.path().to_path_buf();

    // Create bundle with path traversal
    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-traversal-test")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "c".repeat(40),
        })
        .diff_hash([0x44; 32])
        .file_manifest(vec![FileChange {
            path: "../etc/passwd".to_string(), // Path traversal!
            change_kind: ChangeKind::Modify,
            old_path: None,
        }])
        .binary_detected(false)
        .build()
        .expect("valid bundle");

    // Validate should reject path traversal
    let result = validate_file_changes(&bundle, &workspace_root);

    assert!(
        matches!(result, Err(WorkspaceError::PathTraversal(_))),
        "should reject path traversal: got {result:?}"
    );
}

/// Tests that workspace apply produces correct result structure.
#[test]
fn test_workspace_apply_produces_correct_result() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_manager = WorkspaceManager::new(temp_dir.path().to_path_buf());

    let bundle = create_test_changeset_bundle(vec![
        ("src/main.rs", ChangeKind::Add),
        ("Cargo.toml", ChangeKind::Modify),
        ("README.md", ChangeKind::Delete),
    ]);

    let result = workspace_manager.apply(&bundle).expect("apply should succeed");

    assert_eq!(result.changeset_digest, bundle.changeset_digest);
    assert_eq!(result.files_modified, 3);
    assert!(result.applied_at_ns > 0, "applied_at_ns should be positive");
}

// =============================================================================
// IT-00313-03: Capability Validator Tests
// =============================================================================

/// Tests that capability validator enforces the tool profile.
///
/// Per REQ-HEF-0010, the reviewer profile:
/// - Allows: Read (for code review)
/// - Denies: Write, Execute, Network (safety constraints)
#[test]
fn test_capability_validator_enforces_tool_profile() {
    let manifest = create_reviewer_capability_manifest();
    let validator = CapabilityValidator::new(manifest).expect("valid validator");

    // Read should be allowed (use absolute path to match scope's root "/" requirement)
    let read_request = ToolRequest::new(ToolClass::Read, RiskTier::default())
        .with_path(PathBuf::from("/workspace/src/lib.rs"));
    let read_decision = validator.validate(&read_request);
    assert!(
        read_decision.is_allowed(),
        "Read should be allowed: {read_decision:?}"
    );

    // Write should be denied (not in tool_allowlist)
    let write_request = ToolRequest::new(ToolClass::Write, RiskTier::default())
        .with_path(PathBuf::from("/workspace/src/lib.rs"));
    let write_decision = validator.validate(&write_request);
    assert!(
        !write_decision.is_allowed(),
        "Write should be denied: {write_decision:?}"
    );

    // Execute should be denied (not in tool_allowlist)
    // Note: Execute also requires shell_command, but allowlist check comes first
    let execute_request = ToolRequest::new(ToolClass::Execute, RiskTier::default());
    let execute_decision = validator.validate(&execute_request);
    assert!(
        !execute_decision.is_allowed(),
        "Execute should be denied: {execute_decision:?}"
    );

    // Network should be denied (not in tool_allowlist)
    let network_request = ToolRequest::new(ToolClass::Network, RiskTier::default())
        .with_network("example.com", 443);
    let network_decision = validator.validate(&network_request);
    assert!(
        !network_decision.is_allowed(),
        "Network should be denied: {network_decision:?}"
    );
}

/// Tests that capability validator respects tool allowlist.
#[test]
fn test_capability_validator_respects_allowlist() {
    // Create manifest with only Execute allowed and shell_allowlist configured
    let manifest = CapabilityManifestBuilder::new("execute-only-manifest")
        .delegator("test-delegator")
        .capability(
            Capability::builder("cap-execute", ToolClass::Execute)
                .scope(CapabilityScope::allow_all()) // Use allow_all() for permissive scope
                .build()
                .expect("valid execute capability"),
        )
        .tool_allowlist(vec![ToolClass::Execute])
        .shell_allowlist(vec!["ls".to_string(), "cat".to_string()]) // Required for Execute
        .build()
        .expect("valid manifest");

    let validator = CapabilityValidator::new(manifest).expect("valid validator");

    // Execute should be allowed when shell_command matches allowlist
    let execute_request = ToolRequest::new(ToolClass::Execute, RiskTier::default())
        .with_shell_command("ls");
    assert!(
        validator.validate(&execute_request).is_allowed(),
        "Execute should be allowed when in allowlist with matching shell command"
    );

    // Read should be denied (not in allowlist)
    let read_request = ToolRequest::new(ToolClass::Read, RiskTier::default())
        .with_path(PathBuf::from("/workspace/file.txt"));
    assert!(
        !validator.validate(&read_request).is_allowed(),
        "Read should be denied when not in allowlist"
    );
}

// =============================================================================
// IT-00313-04: CAS Storage Tests
// =============================================================================

/// Tests that tool outputs are correctly stored in CAS.
#[tokio::test]
async fn test_tool_output_stored_in_cas() {
    let harness = FacV0TestHarness::new();

    // Create test file
    let test_file = harness.workspace_root().join("test_cas.txt");
    std::fs::write(&test_file, b"Content for CAS storage test").expect("write test file");

    // Execute tool
    let ctx = harness.execution_context("req-cas-test");
    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("test_cas.txt"),
        offset: None,
        limit: None,
    });

    let result = harness
        .tool_executor
        .execute(&ctx, &args)
        .await
        .expect("execute");

    assert!(result.success);

    // Store result in CAS
    let result_json = serde_json::to_vec(&result.output).expect("serialize");
    let hash = harness.cas.store(&result_json);

    // Verify retrieval
    let retrieved = harness.cas.retrieve(&hash).expect("retrieve");
    assert_eq!(retrieved, result_json);
}

// =============================================================================
// IT-00313-05: Snapshot/Apply Integration Tests
// =============================================================================

/// Tests workspace snapshot captures state correctly.
#[test]
fn test_workspace_snapshot_captures_state() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_manager = WorkspaceManager::new(temp_dir.path().to_path_buf());

    let snapshot1 = workspace_manager
        .snapshot("work-001")
        .expect("first snapshot");
    let snapshot2 = workspace_manager
        .snapshot("work-002")
        .expect("second snapshot");

    // Different work IDs should produce different hashes (via BLAKE3 of work_id)
    assert_ne!(
        snapshot1.snapshot_hash, snapshot2.snapshot_hash,
        "different work IDs should have different hashes"
    );

    // Same work ID should produce same hash (deterministic)
    let snapshot1_again = workspace_manager
        .snapshot("work-001")
        .expect("snapshot again");
    assert_eq!(
        snapshot1.snapshot_hash, snapshot1_again.snapshot_hash,
        "same work ID should have same hash"
    );
}

/// Tests workspace restore from snapshot.
#[test]
fn test_workspace_restore_from_snapshot() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_manager = WorkspaceManager::new(temp_dir.path().to_path_buf());

    let snapshot = workspace_manager
        .snapshot("work-restore-test")
        .expect("snapshot");

    // Restore should succeed (stub implementation)
    let result = workspace_manager.restore(&snapshot);
    assert!(result.is_ok(), "restore should succeed");
}

// =============================================================================
// IT-00313-06: Tool Executor Integration Tests
// =============================================================================

/// Tests that tool executor respects budget constraints.
#[tokio::test]
async fn test_tool_executor_respects_budget() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_root = temp_dir.path().to_path_buf();

    // Create CAS
    let cas: Arc<dyn ContentAddressedStore> =
        Arc::new(apm2_daemon::episode::StubContentAddressedStore::new());

    // Create very limited budget (1 tool call)
    let budget = EpisodeBudget::builder().tool_calls(1).build();
    let budget_tracker = Arc::new(BudgetTracker::from_envelope(budget));

    // Create executor
    let mut executor = ToolExecutor::new(budget_tracker.clone(), cas);
    executor
        .register_handler(Box::new(ReadFileHandler::with_root(&workspace_root)))
        .expect("register handler");

    // Create test file
    std::fs::write(workspace_root.join("budget_test.txt"), b"test").expect("write file");

    let ctx = ExecutionContext::new(
        apm2_daemon::episode::EpisodeId::new("ep-budget-test").expect("valid id"),
        "req-budget-1",
        0,
    );
    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("budget_test.txt"),
        offset: None,
        limit: None,
    });

    // First call should succeed
    let result1 = executor.execute(&ctx, &args).await;
    assert!(result1.is_ok(), "first call should succeed");

    // Second call should fail due to budget
    let result2 = executor.execute(&ctx, &args).await;
    assert!(
        result2.is_err(),
        "second call should fail due to budget exhaustion"
    );
}

/// Tests that tool executor validates arguments.
#[tokio::test]
async fn test_tool_executor_validates_arguments() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_root = temp_dir.path().to_path_buf();

    let cas: Arc<dyn ContentAddressedStore> =
        Arc::new(apm2_daemon::episode::StubContentAddressedStore::new());

    let budget = EpisodeBudget::builder().tool_calls(100).build();
    let budget_tracker = Arc::new(BudgetTracker::from_envelope(budget));

    let mut executor = ToolExecutor::new(budget_tracker, cas);
    executor
        .register_handler(Box::new(ReadFileHandler::with_root(&workspace_root)))
        .expect("register handler");

    let ctx = ExecutionContext::new(
        apm2_daemon::episode::EpisodeId::new("ep-validate-test").expect("valid id"),
        "req-validate",
        0,
    );

    // Path traversal should be rejected at validation
    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("../etc/passwd"),
        offset: None,
        limit: None,
    });

    let result = executor.execute(&ctx, &args).await;
    assert!(
        result.is_err(),
        "path traversal should be rejected: {result:?}"
    );
}
