# RFC-0018 Change Summary (FAC v0 autonomy edits)

## Files changed/created and why
- `documents/rfcs/RFC-0018/01_problem_and_imports.yaml` — added evidence-backed FAC v0 autonomy gaps and registered new requirements.
- `documents/rfcs/RFC-0018/02_design_decisions.yaml` — added FAC v0 preconditions table, truth-plane references for changeset/review triggers, and DD-HEF-0010..0013.
- `documents/rfcs/RFC-0018/03_trust_boundaries.yaml` — added ChangeSetBundle and review-output trust boundaries with CAS allowlist rules.
- `documents/rfcs/RFC-0018/04_contracts_and_versioning.yaml` — specified ChangeSetBundleV1/ReviewArtifactBundleV1/ReviewBlockedV1 artifact contracts and canonicalization notes.
- `documents/rfcs/RFC-0018/05_rollout_and_ops.yaml` — blocked enable-by-default on GATE-HEF-FAC-V0 alongside projection-only gate.
- `documents/rfcs/RFC-0018/06_ticket_decomposition.yaml` — added FAC v0 precondition tickets (TCK-00310..00313) and updated ordering.
- `documents/rfcs/RFC-0018/07_test_and_evidence.yaml` — added FAC v0 integration tests and evidence registry entries.
- `documents/rfcs/RFC-0018/08_risks_and_open_questions.yaml` — added FAC v0 precondition risk and mitigations.
- `documents/rfcs/RFC-0018/09_governance_and_gates.yaml` — added GATE-HEF-FAC-V0 gate and evidence bindings.
- `documents/rfcs/RFC-0018/EVIDENCE_APPENDIX.md` — added evidence for missing diff observability and review receipts.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0009.yaml` — new requirement for ChangeSetBundle diff observability.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0010.yaml` — new requirement for reviewer viability (workspace snapshot/apply + minimal tools).
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0011.yaml` — new requirement for ReviewBlocked liveness semantics.
- `documents/rfcs/RFC-0018/requirements/README.yaml` — indexed REQ-HEF-0001..0011 for discoverability.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0009.yaml` — evidence artifact for ChangeSetBundle diff observability test.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0010.yaml` — evidence artifact for workspace snapshot/apply + ReviewBlocked test.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0011.yaml` — evidence artifact for reviewer tools + CAS logs test.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0012.yaml` — evidence artifact for FAC v0 end-to-end autonomy test.
- `documents/rfcs/RFC-0018/CHANGE_SUMMARY.md` — this summary.

## NEW WORK REQUIRED gaps (evidence-backed)
- KernelEvent payload list lacks ChangeSetPublished/ReviewReceiptRecorded/ReviewBlockedRecorded events: `proto/kernel_events.proto:73-93`. Tickets: `TCK-00310`, `TCK-00311`, `TCK-00312`.
- EvidenceEvent only includes EvidencePublished and GateReceiptGenerated: `proto/kernel_events.proto:436-466`. Ticket: `TCK-00312`.
- PolicyResolvedForChangeSet includes changeset_digest but no CAS diff/bundle reference: `proto/kernel_events.proto:726-744`. Ticket: `TCK-00310`.
- ChangeSet risk-tier input tracks file paths/counts only (no file contents/diff): `crates/apm2-core/src/fac/risk_tier.rs:292-313`. Ticket: `TCK-00310`.
- Episode PinnedSnapshot provides repo/lockfile/policy hashes (not a diff bundle): `crates/apm2-daemon/src/episode/snapshot.rs:88-104`. Ticket: `TCK-00311`.

## FAC v0 autonomy: required vs optional
Required for autonomous FAC v0:
- ChangeSetBundleV1 in CAS with ledger-anchored changeset_digest and ChangeSetPublished event.
- Workspace snapshot/apply semantics with ReviewBlocked on failure (reason codes + CAS logs).
- ReviewReceiptRecorded ledger event referencing ReviewArtifactBundleV1 (review text + tool logs in CAS).
- End-to-end FAC v0 harness producing evidence for GATE-HEF-FAC-V0 (no GitHub reads for truth).

Optional / Phase-2 or projection-only:
- ProjectionReceipt remains projection-only (not a truth source) and is not required to gate v0 autonomy.
