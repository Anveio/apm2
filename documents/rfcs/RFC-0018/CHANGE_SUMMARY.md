# RFC-0018 Change Summary (TSC readiness edits)

## Files changed/created and why
- `documents/rfcs/RFC-0018/01_problem_and_imports.yaml` — added evidence-backed gaps for capability allowlists and FAC v0 preconditions.
- `documents/rfcs/RFC-0018/02_design_decisions.yaml` — removed non-pulse rows from HEF truth-plane table, added layering note, tightened DD-HEF-0004/0011/0012.
- `documents/rfcs/RFC-0018/03_trust_boundaries.yaml` — marked topic/CAS allowlists as NEW WORK REQUIRED (TCK-00314) and clarified enforcement boundary.
- `documents/rfcs/RFC-0018/04_contracts_and_versioning.yaml` — specified BLAKE3-256 changeset_digest rules, canonicalization, binary handling, and expanded artifact schemas.
- `documents/rfcs/RFC-0018/05_rollout_and_ops.yaml` — added explicit RFC-0017 prerequisites to rollout guardrails.
- `documents/rfcs/RFC-0018/06_ticket_decomposition.yaml` — added TCK-00314 and cross-RFC dependencies; strengthened canonicalization acceptance criteria.
- `documents/rfcs/RFC-0018/07_test_and_evidence.yaml` — added ChangeSetBundle determinism unit test and clarified no-GitHub reads in FAC v0 scope.
- `documents/rfcs/RFC-0018/08_risks_and_open_questions.yaml` — added ReviewReceipt event vs GateReceipt open question; added RFC-0017 prerequisite risk note.
- `documents/rfcs/RFC-0018/09_governance_and_gates.yaml` — aligned GATE-HEF-FAC-V0 evidence categories with security evidence IDs.
- `documents/rfcs/RFC-0018/EVIDENCE_APPENDIX.md` — added evidence for BLAKE3 hashing and missing capability allowlists.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0003.yaml` — enforced exact-topic allowlists and wildcard rejection for session.sock.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0005.yaml` — required explicit CAS hash allowlists for FAC artifacts.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0010.yaml` — enumerated minimal reviewer tool profile and allowlist enforcement.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0011.yaml` — added BINARY_UNSUPPORTED to ReviewBlocked semantics.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0002.yaml` — expanded red-team scope to include CAS allowlist denials.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0009.yaml` — added no-GitHub constraints.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0010.yaml` — added no-GitHub constraints.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0011.yaml` — added no-GitHub constraints.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0012.yaml` — added no-GitHub constraints.
- `schemas/apm2/changeset_bundle_v1.yaml` — new schema stub for ChangeSetBundleV1.
- `schemas/apm2/review_artifact_bundle_v1.yaml` — new schema stub for ReviewArtifactBundleV1.
- `schemas/apm2/review_blocked_v1.yaml` — new schema stub for ReviewBlockedV1.
- `documents/rfcs/RFC-0018/CHANGE_SUMMARY.md` — this summary.

## NEW WORK REQUIRED gaps (evidence-backed)
- KernelEvent payload list lacks ChangeSetPublished/ReviewReceiptRecorded/ReviewBlockedRecorded events: `proto/kernel_events.proto:73-93`. Tickets: `TCK-00310`, `TCK-00311`, `TCK-00312`.
- EvidenceEvent only includes EvidencePublished and GateReceiptGenerated: `proto/kernel_events.proto:436-466`. Ticket: `TCK-00312`.
- PolicyResolvedForChangeSet includes changeset_digest but no CAS diff/bundle reference: `proto/kernel_events.proto:726-744`. Ticket: `TCK-00310`.
- ChangeSet risk-tier input tracks file paths/counts only (no file contents/diff): `crates/apm2-core/src/fac/risk_tier.rs:292-313`. Ticket: `TCK-00310`.
- Episode PinnedSnapshot provides repo/lockfile/policy hashes (not a diff bundle): `crates/apm2-daemon/src/episode/snapshot.rs:88-104`. Ticket: `TCK-00311`.
- CapabilityManifest lacks pulse topic allowlists and CAS hash allowlists: `crates/apm2-daemon/src/episode/capability.rs:511-526`. Ticket: `TCK-00314`.

## FAC v0 autonomy: required vs optional
Required for autonomous FAC v0:
- ChangeSetBundleV1 in CAS with ledger-anchored changeset_digest and ChangeSetPublished event.
- Workspace snapshot/apply semantics with ReviewBlocked on failure (reason codes + CAS logs).
- ReviewReceiptRecorded ledger event referencing ReviewArtifactBundleV1 (review text + tool logs in CAS).
- End-to-end FAC v0 harness producing evidence for GATE-HEF-FAC-V0 (no GitHub reads for truth).

Optional / Phase-2 or projection-only:
- ProjectionReceipt remains projection-only (not a truth source) and is not required to gate v0 autonomy.
- Semantic graph packs, review scoring, durable broker, and multi-host HEF remain future work.
