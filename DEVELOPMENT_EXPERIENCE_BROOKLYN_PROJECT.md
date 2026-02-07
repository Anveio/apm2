# RFC: Forge Admission Cycle Throughput Architecture (FAC-TA-0001)

Status: `Draft for Technical Steering Committee Review`  
Scope: `Mainline delivery throughput, admission control, review scaling, and build orchestration`  
Distribution: `Internal`  
Authority Model: `Containment/Security > Verification/Correctness > Liveness/Progress`

## 1. Abstract

This RFC defines a first-principles redesign of delivery throughput for APM2 by replacing ticket-serial `xtask`-centric workflow control with a Forge Admission Cycle (FAC) architecture that is:

1. FAC-authoritative at admission, with build, test, lint, and review as first-class FAC gate executions producing cryptographic `GateReceipt` artifacts,
2. receipt-driven at coordination boundaries, with the FAC state machine in the daemon as sole admission authority,
3. parallel by default for independent gate execution and review work across `32` hardware threads,
4. evidence-bound for all gate decisions, with GitHub serving as a projection surface for receipt state rather than as a governance layer.

The central claim is that current throughput is constrained primarily by serialization topology, not compute scarcity. CI is a proper subset of FAC: every build check, every lint pass, every AI review is a gate execution that produces a `GateReceipt` stored in the ledger and CAS. GitHub status checks, branch protection rules, and the merge queue are projection-surface optimizations for human visibility and fast-forward merge batching. They are derived views of FAC state, never the admission authority.

This document contains no human-time rollout estimates. Progress is specified by HTF-aligned boundary predicates and evidence conditions.

## 2. Motivation and Problem Statement

Current delivery behavior enforces a near-total order over work that is only partially ordered by true dependency. The result is avoidable queueing, repeated revalidation, and underutilization of available compute.

Observed workflow shape:

`ticket claim -> worktree -> implement -> sequential local checks -> push -> 2 reviews -> CI -> rebase churn -> merge -> finish -> next ticket`

This shape blocks scale to:

1. `5-10` review dimensions,
2. `3` concurrent implementor agents,
3. continuous merge admission without serial rebase loops.

## 3. Current-State Evidence Snapshot

All values below are observed measurements from this repository state on `main`.

### 3.1 Local Pre-Commit Cost Surface

Measured command wall times:

1. `cargo fmt --check`: `1.98s`
2. `cargo clippy --all-targets -- -D warnings -D clippy::doc_markdown -D clippy::match_same_arms -W clippy::missing_const_for_fn`: `33.61s`
3. `cargo test -p xtask -- --test-threads=1`: `16.56s`
4. `cargo semver-checks check-release`: `1.37s` (fails open for unpublished crates)
5. `cargo xtask lint --include-docs`: `11.58s`

Aggregate local check path is approximately `65s` including doc lint.

### 3.2 CI Runtime Distribution

Recent pull_request CI run durations (`workflow: CI`):

1. count: `42`
2. p50: `289s`
3. p90: `306s`
4. min: `130s`
5. max: `331s`
6. avg: `277.57s`

### 3.3 PR Lead-Time Distribution

Recent merged PRs:

1. count: `40`
2. p50 lead time (PR create -> merged): `36.12m`
3. p90 lead time: `151.12m`
4. avg lead time: `58.47m`

Interpretation: CI runtime is materially smaller than end-to-end PR lead time. Therefore, non-CI waiting and coordination are dominant.

### 3.4 Re-run and Waste Signals

Recent PR CI outcomes:

1. total PR runs sampled: `83`
2. success: `44`
3. failure: `23`
4. cancelled: `16`

Cancellation plus failure volume indicates avoidable reruns and queue churn.

### 3.5 Code/Policy Surfaces Causing Serialization

1. Sequential pre-commit checks: `xtask/src/tasks/commit.rs:100`
2. Mandatory pre-push rebase on `origin/main`: `xtask/src/tasks/push.rs:61`
3. Auto-merge model used, merge queue not explicitly modeled: `xtask/src/tasks/push.rs:148`
4. Hardcoded review dimensions (`security`, `code-quality`, `uat`): `xtask/src/tasks/review.rs:24`
5. Watch timeout shorter than CI median (`180s`): `xtask/src/tasks/check.rs:34`
6. Strict required status checks on default branch: `.github/rulesets/protect-main.json:36`
7. CI workflow lacks `merge_group` trigger: `.github/workflows/ci.yml:6`

### 3.6 Existing Useful Substrate

Event-driven CI handoff primitives already exist:

1. `crates/apm2-core/src/webhook/AGENTS.md:14`
2. `crates/apm2-core/src/events/ci.rs:183`

These components are compatible with replacing polling loops and serial post-push waiting.

## 4. First-Principles Model

### 4.1 CI as FAC Subset

CI is not a separate system. Build, test, lint, and review are FAC gate executions. Each gate execution produces a `GateReceipt` stored in CAS with a BLAKE3 digest. GitHub status checks are projections of those receipts onto the projection surface. The admission decision is: "all required `GateReceipt` artifacts present and passing for the target commit SHA." Not: "all GitHub status checks are green."

### 4.2 Throughput Equation

Define:

1. `A`: admission lane concurrency (effective FAC admissions per gate cycle),
2. `P`: parallel implementation slots,
3. `R`: review parallelism (gate executors for review-class gates),
4. `C`: conflict penalty factor (`0 < C <= 1`),
5. `F`: rerun penalty factor (`0 < F <= 1`),
6. `G`: gate pass ratio (`0 < G <= 1`).

Effective throughput scales as:

`T ~= A * P * R * C * F * G`

Current system behavior clamps `A ~= 1` (GitHub auto-merge, no queue), underutilizes `P` (serial ticket execution), and constrains `R` to a hardcoded small set (3 review types), forcing low `T` despite high machine compute. Since `A` is FAC-controlled (not GitHub-controlled), the FAC daemon can increase `A` directly by batching gate execution and projecting results.

### 4.3 Serialization Theorem (Operational)

If merge admission requires each PR branch to be individually rebased and revalidated against moving `main`, then global throughput converges to the slowest serial promotion path regardless of local parallel implementation.

Therefore, elimination of promotion serialization has higher leverage than incremental local command optimization.

### 4.4 Dominance-Order Implication

Any throughput gain that weakens containment or verification is inadmissible. Architecture must:

1. fail closed on missing/ambiguous gate evidence,
2. preserve required status semantics,
3. preserve exact-commit verification at promotion boundary.

## 5. Design Goals

1. Preserve strict merge correctness against actual promoted commit.
2. Increase merge admission concurrency without reducing gate strictness.
3. Scale independent AI review dimensions to `5-10` contexts.
4. Support `3` implementor agent slots with conflict-aware scheduling.
5. Eliminate polling-based coordination and short watch timeout fragility.
6. Remove strategic dependency on `xtask` for admission orchestration.
7. Bind decisions to replayable evidence artifacts.

## 6. Non-Goals

1. No consumer-platform expansion.
2. No weakening of required CI/review checks.
3. No fail-open behavior for stale/partial gate state.
4. No dependence on manual rebasing as the primary freshness mechanism.

## 7. Option Space Evaluated

## 7.1 Option A: Local Optimization Only

Mechanisms:

1. parallel local checks,
2. linker/cache tuning,
3. runner-level command acceleration.

Outcome:

Improves local latency but does not remove admission serialization. Insufficient as primary strategy.

## 7.2 Option B: Compute Offload Only

Mechanisms:

1. remote builders,
2. larger build hosts,
3. shared caches.

Outcome:

Improves compile economics but not merge queueing topology. Incomplete.

## 7.3 Option C: FAC (Queue + Event + Review Mesh + Build Fabric)

Mechanisms:

1. merge-queue-native admission,
2. event-driven control plane,
3. manifest-driven review mesh,
4. conflict-aware multi-agent scheduler,
5. shared compilation cache across workers.

Outcome:

Addresses the dominant bottleneck classes simultaneously while preserving governance constraints.

Selected: `Option C`.

## 8. Proposed FAC Architecture

## 8.1 Architectural Planes

### 8.1.1 Admission Plane

1. FAC state machine in daemon is sole admission authority. Admission decisions are functions of `GateReceipt` presence and verdict, not GitHub status check state.
2. GitHub merge queue is a projection-surface optimization: it batches fast-forward merges and runs speculative combinations. It does not make admission decisions.
3. No per-PR manual rebase requirement as primary freshness control.

### 8.1.2 Verification Plane

1. All verification (build, test, lint, review) executes as FAC gate executions producing `GateReceipt` artifacts stored in CAS.
2. Review gates become manifest-driven (not hardcoded). Each gate is process-isolated and prompt-isolated.
3. Each gate emits a `GateReceipt` with verdict, evidence digest, commit SHA binding, executor identity, and wall time. Receipts are projected to GitHub as status checks.

### 8.1.3 Control Plane

1. FAC state machine drives work item transitions. Transition events include FAC-internal events (`gate_completed`, `review_completed`, `all_gates_passing`) as the primary drivers.
2. GitHub webhook events (`workflow_run.completed`, `merge_group.*`) are secondary input signals, not the authority. The state machine does not depend on GitHub for transitions.
3. Explicit state machine with deterministic, receipt-driven transitions.

### 8.1.4 Compute Plane

1. Gate executors (cargo processes, AI review processes) run on OVH compute pool, managed by daemon.
2. Build/test/review workers use shared `sccache` backend for cross-worktree compilation dedup.
3. Keep linker acceleration (`mold` on Linux targets).
4. Avoid shared `CARGO_TARGET_DIR` across concurrent mutable worktrees due to lock/contention and feature-matrix hazards.

## 8.2 FAC State Machine

States:

1. `Queued`
2. `Claimed`
3. `Implementing`
4. `Pushed`
5. `Reviewing`
6. `QueueEligible`
7. `InMergeQueue`
8. `Promoted`
9. `Blocked`
10. `Ejected`
11. `Abandoned`

Transition rule form:

`(state, event, predicates) -> next_state`

Transitions are driven by receipt publication and FAC-internal events, not by GitHub webhook events. Webhook events are one input signal among several.

Examples:

`(Pushed, all_build_gates_passing, required_receipts_present=true) -> Reviewing`

`(Reviewing, all_review_gates_passing, required_receipts_present=true) -> QueueEligible`

`(QueueEligible, projection.merge_queue_enqueued, _) -> InMergeQueue`

`(InMergeQueue, projection.merge_group_failed, offender_identified=true) -> Ejected`

## 8.3 Typed Protocol Objects

### 8.3.1 Work Item

```json
{
  "work_id": "WID-<stable>",
  "ticket_id": "TCK-xxxxx",
  "branch": "ticket/RFC-xxxx/TCK-xxxxx",
  "base_ref": "main",
  "head_sha": "<40-hex>",
  "impact_prediction": {
    "crates": ["apm2-core", "apm2-daemon"],
    "paths": ["crates/apm2-core/src/webhook/**"],
    "confidence": 0.0
  }
}
```

### 8.3.2 Review Manifest

```json
{
  "manifest_id": "RVM-<stable>",
  "contexts": [
    "ai-review/security",
    "ai-review/correctness",
    "ai-review/architecture",
    "ai-review/performance",
    "ai-review/aep-compliance",
    "ai-review/api-contract",
    "ai-review/test-adequacy",
    "ai-review/defect-taxonomy"
  ],
  "required": true,
  "independence_policy": "isolated-process-per-context",
  "commit_binding": "<40-hex>"
}
```

### 8.3.3 Admission Verdict

```json
{
  "admission_id": "ADM-<stable>",
  "head_sha": "<40-hex>",
  "required_gate_receipts": {
    "GATE-FMT": "cas://<blake3-digest>",
    "GATE-CLIPPY": "cas://<blake3-digest>",
    "GATE-TEST": "cas://<blake3-digest>",
    "GATE-SEMVER": "cas://<blake3-digest>",
    "GATE-DOC-LINT": "cas://<blake3-digest>",
    "GATE-REVIEW-SECURITY": "cas://<blake3-digest>",
    "GATE-REVIEW-CORRECTNESS": "cas://<blake3-digest>"
  },
  "all_receipts_passing": true,
  "decision": "promote|deny",
  "projection_target": "github-merge-queue"
}
```

The admission decision is: "all required `GateReceipt` CAS digests present and their verdicts passing for the bound commit SHA." GitHub status checks are projections of this verdict, not inputs to it.

## 8.4 Review Mesh

Each review dimension is a FAC gate execution that:

1. runs in a process-isolated executor,
2. receives a prompt-isolated context (no shared transient state between reviewers),
3. produces a `GateReceipt` with verdict, evidence digest, commit SHA binding, executor identity, and wall time,
4. stores the receipt in CAS (BLAKE3 digest) and emits a ledger event,
5. projects the receipt verdict to GitHub as a status check (derived view, not authority).

Suggested initial dimensions (each maps to a `GATE-REVIEW-*` gate):

1. `GATE-REVIEW-SECURITY` → projected as `ai-review/security`
2. `GATE-REVIEW-CORRECTNESS` → projected as `ai-review/correctness`
3. `GATE-REVIEW-ARCHITECTURE` → projected as `ai-review/architecture`
4. `GATE-REVIEW-PERFORMANCE` → projected as `ai-review/performance`

Expansion set:

1. `GATE-REVIEW-API-CONTRACT` → projected as `ai-review/api-contract`
2. `GATE-REVIEW-TEST-ADEQUACY` → projected as `ai-review/test-adequacy`
3. `GATE-REVIEW-DEFECT-TAXONOMY` → projected as `ai-review/defect-taxonomy`
4. `GATE-REVIEW-AEP-COMPLIANCE` → projected as `ai-review/aep-compliance`

## 8.5 Conflict-Aware Multi-Agent Scheduling

Scheduler objective:

`maximize(sum(priority) - overlap_penalty - rerun_risk_penalty)`

Where overlap is predicted from:

1. ticket metadata,
2. crate/module tags,
3. historical touch sets,
4. current active branch changed-files.

Policies:

1. Priority dominance over overlap optimization.
2. Hard exclusion only for known non-mergeable shared surfaces.
3. Early conflict alert when active slots converge on same hot file set.

## 8.6 Build Fabric

1. Keep Linux linker optimization in `.cargo/config.toml`.
2. Use `sccache` backend for cross-worktree and cross-worker compilation reuse.
3. Place review workers on OVH compute pool.
4. Keep implementation agents where interactive development is needed.

## 8.7 CI as FAC Gate Execution

CI is not an external system that FAC depends on. CI is a proper subset of FAC. Every build check, lint pass, test suite, and AI review is a gate execution within the FAC. This section specifies the gate taxonomy, execution model, and evidence chain.

### 8.7.1 Gate Taxonomy

Build verification gates (run by daemon on OVH compute):

1. `GATE-FMT`: `cargo fmt --check` → `FmtGateReceipt`
2. `GATE-CLIPPY`: `cargo clippy --all-targets -- -D warnings ...` → `ClippyGateReceipt`
3. `GATE-TEST`: `cargo test` / `cargo nextest run` → `TestGateReceipt`
4. `GATE-SEMVER`: `cargo semver-checks check-release` → `SemverGateReceipt`
5. `GATE-DOC-LINT`: doc example lint → `DocLintGateReceipt`

Review gates (run by daemon-spawned AI review executors):

1. `GATE-REVIEW-SECURITY`: AI security review → `ReviewGateReceipt`
2. `GATE-REVIEW-CORRECTNESS`: AI correctness review → `ReviewGateReceipt`
3. `GATE-REVIEW-ARCHITECTURE`: AI architecture review → `ReviewGateReceipt`
4. `GATE-REVIEW-PERFORMANCE`: AI performance review → `ReviewGateReceipt`
5. `GATE-REVIEW-AEP-COMPLIANCE`: AEP conformance review → `ReviewGateReceipt`
6. `GATE-REVIEW-API-CONTRACT`: API contract review → `ReviewGateReceipt`
7. `GATE-REVIEW-TEST-ADEQUACY`: test coverage review → `ReviewGateReceipt`
8. `GATE-REVIEW-DEFECT-TAXONOMY`: defect classification review → `ReviewGateReceipt`

All gates are registered in the gate manifest. The required gate set for admission is configurable per-work-item or globally. Adding a new gate requires only a manifest entry and an executor, not code changes to the admission logic.

### 8.7.2 Gate Execution Model

1. Daemon receives trigger (work item pushed, `apm2 fac check` invoked, or state machine transition fires).
2. Daemon reads the gate manifest for the required gate set.
3. Daemon spawns gate executors as isolated child processes on OVH compute:
   - Build gates: `cargo` invocations with controlled environment and `sccache`.
   - Review gates: AI review processes (Codex CLI, Claude Code, or local inference) with prompt-isolated context.
4. Each executor produces a `GateReceipt` containing:
   - `gate_id`: stable identifier (e.g., `GATE-FMT`)
   - `verdict`: `pass | fail | error`
   - `evidence_digest`: BLAKE3 hash of full executor output (stdout, stderr, exit code, timing)
   - `commit_sha`: the exact commit the gate was executed against
   - `executor_identity`: which process/model produced the verdict
   - `wall_time_ms`: execution duration
   - `timestamp`: ISO 8601
5. Receipt is stored in CAS (content-addressable by BLAKE3 digest).
6. Ledger event emitted: `gate_completed { gate_id, receipt_cas_digest, verdict, commit_sha }`.
7. Receipt verdict is projected to GitHub as a status check (success/failure/pending) on the bound commit SHA.

### 8.7.3 Parallel Gate Execution

All gates are independent by construction (AEP: they read the same source tree and produce independent verdicts). Therefore:

1. Daemon spawns all gate executors in parallel on the OVH compute pool.
2. Wall-clock gate cycle = `max(individual_gate_times)`, not `sum(individual_gate_times)`.
3. On the AMD RYZEN 9 9950X3D (16c/32t): 5 build gates + 8 review gates fit comfortably within the thread budget, with headroom for 3 concurrent implementation agents.
4. `sccache` on local NVMe eliminates redundant compilation across worktrees and gate re-executions.

Current sequential local check path: ~65s. With parallel execution, wall-clock reduces to ~max(clippy, test) ≈ 34s for build gates, with review gates executing concurrently.

### 8.7.4 GitHub Actions Relationship

Two operating modes, phased:

**Phase 1 (defense-in-depth):** FAC gates run locally on OVH AND GitHub Actions CI runs remotely. Both must pass. GitHub Actions serves as an independent verification layer. FAC receipts are authoritative; GitHub CI is a cross-check.

**Phase 2 (target state):** Eliminate GitHub Actions CI. FAC gates on OVH are the sole authority. GitHub receives projected status checks from FAC gate receipts. No redundant remote execution.

In either phase: FAC is authoritative. GitHub Actions is a secondary signal, never the admission authority.

### 8.7.5 Evidence Chain

The evidence chain for every gate decision:

`gate execution → GateReceipt (CAS, BLAKE3 digest) → ledger event → GitHub status projection`

Audit path: `receipt CAS digest → CAS artifact → full gate output (exit code, stdout, stderr, timing) → executor identity → commit SHA binding`

This satisfies Section 9.2 (Evidence Rules) natively. No separate evidence layer is needed for CI — the FAC gate receipt IS the evidence artifact.

## 9. Governance and Fail-Closed Rules

## 9.1 Admission Deny Conditions

Automatic deny on:

1. missing required `GateReceipt` for any gate in the required gate set,
2. `GateReceipt` bound to non-matching commit SHA (stale receipt),
3. parse/schema failure in receipt payload,
4. BLAKE3 digest mismatch between receipt and CAS artifact (tampered evidence),
5. receipt verdict is `fail` or `error` for any required gate,
6. unknown merge-group status on projection surface.

The FAC state machine evaluates these conditions against CAS-stored receipts, not against GitHub status check API state.

## 9.2 Evidence Rules

For every promotion:

1. commit SHA binding required on every `GateReceipt`,
2. CAS-addressed receipt with BLAKE3 digest required for every required gate,
3. provenance chain required: executor identity, execution timestamp, wall time,
4. full executor output (stdout, stderr, exit code) stored as CAS artifact referenced by receipt evidence digest,
5. replay path required for audit: `receipt_digest → CAS → full output → executor identity → commit SHA`.

## 9.3 Anti-Goodhart Triples

Primary KPI must pair with:

1. independent countermetric,
2. independent oversight channel.

Examples:

1. KPI: merged work items per HTF boundary.
2. Countermetric: post-merge defect escape rate by severity.
3. Oversight: independent correctness/security review contexts.

## 10. Security and Threat Model

## 10.1 Threats

1. spoofed status contexts on GitHub projection surface,
2. review process collusion/shared hidden state between gate executors,
3. stale-success reuse: replaying a passing `GateReceipt` from a prior commit SHA after branch mutation,
4. queue poisoning via malformed event payload,
5. admission race conditions across parallel updates,
6. receipt forgery: constructing a `GateReceipt` with a passing verdict without actually executing the gate. Gaming a status check on GitHub is trivial (API call). Forging a receipt requires producing a CAS artifact whose BLAKE3 digest matches the receipt, with valid executor identity and wall time — a materially harder attack.

## 10.2 Controls

1. required gate set defined in gate manifest, not in GitHub branch protection (source of truth is FAC, projection is derived),
2. per-gate isolated executor processes with no shared transient state,
3. strict commit SHA binding on every `GateReceipt` — receipt is invalid if SHA does not match current head,
4. webhook signature verification (HMAC-SHA256, constant-time comparison) and delivery ID idempotency,
5. monotonic admission decision lock keyed by merge-group SHA,
6. CAS integrity: receipt references evidence digest, evidence is stored in CAS, BLAKE3 provides tamper detection. Forging a receipt requires the daemon signing key.

## 11. Projection-Surface Configuration (GitHub)

GitHub is a projection surface for FAC state (per RFC-0019). The governance is in the FAC gate manifest and admission logic, not in GitHub branch protection rules. The changes below configure the projection surface to reflect FAC authority.

Required projection-surface changes:

1. Enable merge queue on default branch — this is a projection optimization for batching fast-forward merges, not admission control.
2. Keep strict required status check policy — these checks are projections of `GateReceipt` verdicts. Their names must match the gate projection mapping (e.g., `GATE-FMT` projects as `fac/fmt`, `GATE-REVIEW-SECURITY` projects as `ai-review/security`).
3. Expand required status checks from current `{CI Success, ai-review/security, ai-review/code-quality}` to the full set projected from the gate manifest.
4. Add `merge_group` trigger to CI workflow (Phase 1 defense-in-depth only; removed in Phase 2).
5. Ensure CI workflow emits required contexts on both `pull_request` and `merge_group` events (Phase 1 only).

Note: In Phase 2 (target state), GitHub Actions CI is eliminated. All status checks are projected directly from FAC gate receipts via the GitHub Status API. Branch protection rules still require the projected status checks, but the source is FAC, not GitHub Actions.

## 12. FAC Implementation Boundaries (HTF-Aligned, No Human-Time Estimates)

Each boundary is entered and exited by predicates, not elapsed wall time.

## 12.1 Boundary FAC-B0: Baseline Authority

Entry:

1. instrumentation collector available,
2. metric schemas agreed by TSC.

Exit:

1. baseline evidence artifact committed with:
   - local check distribution,
   - CI distribution,
   - PR lead-time distribution,
   - rerun/cancel rates.

Rollback:

1. none required; read-only baseline.

## 12.2 Boundary FAC-B1: FAC Gate Execution + Merge Queue Projection

Entry:

1. daemon can spawn gate executors for all build gates (`GATE-FMT`, `GATE-CLIPPY`, `GATE-TEST`, `GATE-SEMVER`, `GATE-DOC-LINT`),
2. gate executors produce `GateReceipt` artifacts stored in CAS,
3. branch protection supports merge queue on projection surface.

Exit:

1. all build gates execute in parallel on daemon, producing CAS-stored receipts,
2. receipt verdicts projected to GitHub as status checks,
3. successful merge queue admission run with projected status checks on merge-group SHA,
4. no direct-main merge bypass except explicit admin override policy.

Rollback:

1. disable queue requirement and restore prior required status check set on projection surface.

## 12.3 Boundary FAC-B2: FAC State Machine Authority

Entry:

1. webhook signature+idempotency path healthy,
2. event consumer can map `gate_completed` ledger events to work item state transitions.

Exit:

1. work item state transitions driven by `GateReceipt` publication (ledger events), not GitHub webhook events,
2. polling watchdog path disabled for primary flow,
3. GitHub webhook events are secondary input signals processed by the state machine but not required for transitions.

Rollback:

1. revert to polling fallback channel.

## 12.4 Boundary FAC-B3: Review Gate Manifest v1

Entry:

1. gate manifest includes `GATE-REVIEW-*` entries with prompt, schema, and executor configuration,
2. each review gate has an isolated executor that produces `ReviewGateReceipt` artifacts.

Exit:

1. at least 5 review gates running in parallel as FAC gate executions,
2. each review gate produces a CAS-stored `GateReceipt` with evidence digest,
3. receipt verdicts projected to GitHub as status checks.

Rollback:

1. reduce required gate set to safe minimum with explicit waiver receipts.

## 12.5 Boundary FAC-B4: Multi-Agent Slot Scheduler

Entry:

1. slot manager supports `P=3`,
2. conflict predictor available.

Exit:

1. 3 concurrent implementation slots with bounded overlap penalty,
2. no admission deadlock under queue pressure.

Rollback:

1. reduce slot count while preserving queue semantics.

## 12.6 Boundary FAC-B5: XTASK Decommission

Entry:

1. FAC command surface in daemon/cli replaces admission orchestration,
2. legacy `xtask` paths marked deprecated.

Exit:

1. no critical-path admission dependence on `xtask`,
2. xtask retained only for non-critical utility functions or removed.

Rollback:

1. restore minimal shim wrapper to FAC APIs if needed.

## 13. Migration Off `xtask`

Directive:

1. stop adding net-new admission/control logic to `xtask`,
2. move orchestration endpoints to FAC-native control path (daemon + typed CLI commands),
3. xtask pre-commit checks (`fmt`, `clippy`, `test`, `semver`, `lint`) become FAC gate executions — the commit flow becomes: `apm2 fac check` → daemon runs all gates in parallel → gate receipts produced → agent can commit,
4. xtask push/review logic becomes daemon-mediated gate dispatch and receipt projection,
5. maintain compatibility wrappers only if required for transition safety.

Proposed replacement command surface:

1. `apm2 fac claim` — claim work item (replaces `xtask start-ticket`)
2. `apm2 fac check` — run all build gates in parallel, produce receipts (replaces `xtask commit` pre-checks)
3. `apm2 fac submit` — push and dispatch review gates (replaces `xtask push`)
4. `apm2 fac review-dispatch` — trigger review gate execution (replaces `xtask review`)
5. `apm2 fac admission-status` — show gate receipt state and admission readiness
6. `apm2 fac slot-manager` — manage concurrent implementation slots

## 14. Metrics, Countermetrics, and Evidence

## 14.1 Primary Metrics

1. merged work items per HTF boundary,
2. queue admission success ratio,
3. review context completion ratio,
4. merge-group rerun ratio.

## 14.2 Countermetrics

1. post-merge escaped defects by severity,
2. rollback incidence,
3. flaky-context incidence,
4. false-positive review block rate.

## 14.3 Evidence Artifacts

Target artifacts:

1. `evidence/fac/baseline/*.json`
2. `evidence/fac/admission/*.json`
3. `evidence/fac/review_contexts/*.json`
4. `evidence/fac/conflict_scheduler/*.json`
5. `evidence/fac/governance/*.json`

All artifacts must include:

1. schema version,
2. commit binding,
3. producer identity,
4. creation HTF boundary ID,
5. cryptographic digest.

## 15. Open Risks and Mitigations

## 15.1 Merge Queue Misconfiguration

Risk:

required contexts not emitted for merge-group commits.

Mitigation:

CI contract tests validating context emission for both `pull_request` and `merge_group`.

## 15.2 Review Mesh Latency Inflation

Risk:

more contexts increase wall-clock review completion.

Mitigation:

parallel dispatch, per-context SLAs measured as boundary predicates, and fail-fast on hard denials.

## 15.3 Conflict Predictor Misclassification

Risk:

false low-overlap predictions create rework.

Mitigation:

online learning from actual conflict outcomes and conservative penalties for historically hot files.

## 15.4 Status Spoofing or Drift

Risk:

status contexts reported without trusted provenance.

Mitigation:

allowlisted producers, provenance receipts, SHA-locked verification.

## 16. Acceptance Criteria for TSC Approval

This RFC is acceptable for implementation authorization when TSC confirms:

1. governance dominance order preserved (containment > verification > liveness),
2. FAC is sole admission authority — GitHub is projection surface only,
3. CI is modeled as FAC gate executions producing CAS-stored `GateReceipt` artifacts,
4. merge queue + `merge_group` contract is explicitly represented as projection-surface optimization,
5. receipt-driven state machine transitions replace polling for primary flow,
6. review gate manifest architecture supports `5-10` isolated review gates,
7. `P=3` slot scheduling with conflict-aware policy is specified,
8. `xtask` decommission path is explicit and non-ambiguous,
9. evidence contract is receipt-native: every gate decision backed by CAS-addressed receipts,
10. fail-closed behavior is explicit for missing, stale, or failing receipts,
11. OVH compute platform specification included with concurrency envelope.

## 17. Immediate Next Authoring Actions

1. ratify this RFC as `Accepted with Amendments` or `Needs Revision`,
2. split approved sections into implementation tickets under FAC namespace,
3. define gate manifest schema and register initial gate set (B1 prerequisite),
4. configure projection-surface (GitHub branch protection, merge queue, status check mapping),
5. freeze new `xtask` admission-control feature work — all new gate logic goes through FAC.

## 18. OVH Build Platform Specification

All FAC gate execution, implementation agent work, and daemon operation occurs on the OVH compute node.

### 18.1 Hardware

1. CPU: AMD RYZEN 9 9950X3D — 16 cores / 32 threads — 4.3 GHz base / 5.7 GHz boost
2. RAM: 64 GB DDR5 5600 MHz
3. Storage: 2 × 960 GB SSD NVMe (soft RAID)

### 18.2 Concurrency Envelope

The 32-thread budget supports the following concurrent workloads:

1. **3 implementation agents**: each gets a dedicated worktree, ~4-6 threads for cargo operations.
2. **5 build gate executors**: `GATE-FMT`, `GATE-CLIPPY`, `GATE-TEST`, `GATE-SEMVER`, `GATE-DOC-LINT` — lightweight except clippy/test, which are CPU-bound.
3. **5-8 review gate executors**: AI review processes (Codex CLI, Claude Code, or local inference) — primarily I/O-bound (API calls) with minimal CPU, except local inference which is GPU/CPU-bound.
4. **1 daemon process**: FAC state machine, gate dispatch, receipt storage, projection — lightweight.
5. **sccache**: compilation cache on local NVMe for cross-worktree dedup. Eliminates redundant rustc invocations across concurrent agents and gate re-executions.

Conservative estimate: 3 agents + 10 gate executors (5 build + 5 review) fits comfortably within the 16c/32t budget. The 3D V-Cache on the 9950X3D benefits compilation workloads (large instruction caches).

### 18.3 Storage Strategy

1. Worktrees: each implementation agent gets a dedicated `git worktree` on NVMe.
2. CAS: gate receipts and evidence artifacts stored on NVMe (fast random read for audit).
3. `sccache`: local NVMe backend (no network round-trip).
4. Separate `CARGO_TARGET_DIR` per worktree to avoid lock contention and feature-matrix hazards across concurrent builds.

## Appendix A: Why This Is 10x-Capable

The projected multiplicative effect comes from unlocking independent axes:

1. admission concurrency (`A`) via FAC-controlled gate batching and merge queue projection,
2. implementation concurrency (`P`) via slot scheduler on OVH 32-thread compute,
3. review coverage and parallelism (`R`) via manifest-driven review gate mesh with parallel execution,
4. reduced reruns (`F`) via speculative merge validation and receipt-driven state transitions,
5. conflict reduction (`C`) via overlap-aware scheduling.

CI absorption into FAC eliminates the external-system serialization bottleneck entirely. Gate execution on local OVH compute (not remote GitHub Actions runners) removes network round-trip and queue wait from the critical path. Local command acceleration remains valuable but is second-order relative to topology-level serialization removal.

## Appendix B: Normative Constraint Mapping (AEP-Oriented)

1. **Physics-first admissibility**: throughput plan attacks ordering constraints (serialization topology) before compute upgrades. CI absorption into FAC removes the external-system serialization bottleneck.
2. **Conventional-feasibility objections are non-blocking**: architecture retains strict gating while scaling. "But we need GitHub CI" is a projection-surface concern, not a governance concern.
3. **Novel engineering requirement**: FAC-native gate execution + receipt-driven admission + review mesh synthesis, not single-knob optimization.
4. **Compounding closure**: failures feed scheduler and reviewer quality models. Gate receipts accumulate evidence that improves future scheduling and conflict prediction.
5. **Bounded search**: explicit FAC boundaries (B0-B5) and exit predicates.
6. **Digest-first interfaces**: all gate decisions backed by CAS-addressed `GateReceipt` artifacts with BLAKE3 digests, not ephemeral GitHub API status responses. Typed protocol objects with SHA/evidence binding.
7. **Evidence-first**: gate receipts ARE the evidence. GitHub status checks are views of that evidence. The audit path runs through CAS, not through GitHub API.
8. **Anti-Goodhart**: KPI + countermetric + oversight triplets. Gate receipts include full executor output (stdout, stderr, exit code, timing), not just pass/fail. Gaming a status check requires forging a receipt, which requires the daemon signing key — a materially harder attack than calling the GitHub Status API.
9. **Recursive semantic stability**: same admission semantics for single or multiple concurrent work items. The gate manifest and receipt-driven admission logic are invariant to concurrency level.

