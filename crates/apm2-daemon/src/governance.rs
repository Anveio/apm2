//! Governance integration for policy resolution.
//!
//! This module provides the `GovernancePolicyResolver` which delegates policy
//! decisions to the Governance Holon (or local policy configuration in Phase
//! 1).
//!
//! # TCK-00289
//!
//! Implements real policy resolution wiring. Currently uses local deterministic
//! resolution until the Governance Holon is fully integrated.

use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

use crate::protocol::dispatch::{PolicyResolution, PolicyResolutionError, PolicyResolver};
use crate::protocol::messages::WorkRole;

/// Resolves policy via governance integration.
#[derive(Debug, Clone, Default)]
pub struct GovernancePolicyResolver;

impl GovernancePolicyResolver {
    /// Creates a new policy resolver.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl PolicyResolver for GovernancePolicyResolver {
    fn resolve_for_claim(
        &self,
        work_id: &str,
        role: WorkRole,
        actor_id: &str,
    ) -> Result<PolicyResolution, PolicyResolutionError> {
        // TCK-00289: In Phase 1, we use deterministic local resolution.
        // In Phase 2, this will make an IPC call to the Governance Holon.

        // Generate deterministic hashes for policy and capability manifest
        let policy_hash = blake3::hash(format!("policy:{work_id}:{actor_id}").as_bytes());
        let manifest_hash = blake3::hash(format!("manifest:{work_id}:{actor_id}").as_bytes());

        // Create and seal a context pack manifest
        let content_hash = blake3::hash(format!("content:{work_id}:{actor_id}").as_bytes());
        let context_pack = ContextPackManifestBuilder::new(
            format!("manifest:{work_id}"),
            format!("profile:{actor_id}"),
        )
        .add_entry(
            ManifestEntryBuilder::new(
                format!("/work/{work_id}/context.yaml"),
                *content_hash.as_bytes(),
            )
            .stable_id("work-context")
            .access_level(AccessLevel::Read)
            .build(),
        )
        .build();

        let context_pack_hash =
            context_pack
                .seal()
                .map_err(|e| PolicyResolutionError::GovernanceFailed {
                    message: format!("context pack sealing failed: {e}"),
                })?;

        // TODO(RFC-0019): Resolve from real governance policy evaluation.
        //
        // Transitional risk tier mapping (TCK-00340 quality fix):
        //
        // The previous hardcoded Tier4 value was fail-closed by design, but
        // it broke low-tier throughput because ALL governance-resolved claims
        // required ThresholdSigned attestation (which the IngestReviewReceipt
        // endpoint cannot provide — it only offers SelfSigned).
        //
        // This transitional mapping uses role-based heuristics until real
        // governance policy evaluation is implemented:
        //
        // - All roles: Tier1 (SelfSigned required per the attestation ratchet table).
        //   This is more restrictive than Tier0 (which requires no attestation) but
        //   still permits the SelfSigned attestation that the IPC endpoints provide.
        //
        // SECURITY: Fail-closed semantics are preserved at higher tiers
        // via the attestation ratchet table in AttestationRequirements:
        //   - Tier0: None required
        //   - Tier1: SelfSigned required
        //   - Tier2+: CounterSigned/ThresholdSigned (will be rejected by SelfSigned
        //     endpoints, enforcing fail-closed)
        //
        // When real governance resolution is wired (RFC-0019), the actual
        // risk tier from the changeset metadata will be used instead of
        // this role-based heuristic.
        let resolved_risk_tier = transitional_risk_tier(role);

        Ok(PolicyResolution {
            policy_resolved_ref: format!("PolicyResolvedForChangeSet:{work_id}"),
            resolved_policy_hash: *policy_hash.as_bytes(),
            capability_manifest_hash: *manifest_hash.as_bytes(),
            context_pack_hash,
            resolved_risk_tier,
        })
    }
}

/// Transitional risk tier mapping based on work role.
///
/// Returns Tier1 (risk tier value `1`) as the safe transitional default for
/// all roles. Tier1 requires `SelfSigned` attestation per the attestation
/// ratchet table, which is the level the daemon's IPC endpoints can produce.
///
/// This is more restrictive than Tier0 (no attestation required) but avoids
/// the Tier4 deadlock where all claims are rejected because the endpoint
/// cannot produce `ThresholdSigned` attestation.
///
/// # TODO(RFC-0019)
///
/// Replace with real governance policy evaluation that resolves the actual
/// risk tier from changeset metadata (file paths, module criticality,
/// dependency fanout, etc.).
const fn transitional_risk_tier(_role: WorkRole) -> u8 {
    // All roles: Tier1 — SelfSigned attestation required but sufficient.
    // When real governance resolution is wired (RFC-0019), this will
    // be replaced with role-specific and changeset-specific resolution.
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies the governance resolver returns Tier1 for Phase 1 transitional
    /// operation. This ensures production claims can flow through
    /// `IngestReviewReceipt` which only provides `SelfSigned` attestation.
    /// Tier1 requires `SelfSigned` attestation, which the endpoint can provide.
    #[test]
    fn test_governance_resolver_returns_tier1_for_reviewer() {
        let resolver = GovernancePolicyResolver::new();
        let result = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .expect("resolve_for_claim should succeed");

        assert_eq!(
            result.resolved_risk_tier, 1,
            "Governance resolver must return Tier1 for Reviewer role \
             — Tier4 blocks all production SelfSigned attestation"
        );
    }

    /// Verifies that all work roles get Tier1 in the transitional mapping.
    #[test]
    fn test_governance_resolver_all_roles_return_tier1() {
        let resolver = GovernancePolicyResolver::new();

        for (role, name) in [
            (WorkRole::Reviewer, "Reviewer"),
            (WorkRole::GateExecutor, "GateExecutor"),
            (WorkRole::Implementer, "Implementer"),
            (WorkRole::Coordinator, "Coordinator"),
        ] {
            let result = resolver
                .resolve_for_claim("work-001", role, "actor-001")
                .expect("resolve_for_claim should succeed");
            assert_eq!(
                result.resolved_risk_tier, 1,
                "Role {name} must get Tier1 in transitional mapping, got {}",
                result.resolved_risk_tier
            );
        }
    }

    /// Verifies that policy resolution is deterministic: same inputs produce
    /// the same outputs (policy hash, manifest hash, context pack hash).
    #[test]
    fn test_governance_resolver_deterministic() {
        let resolver = GovernancePolicyResolver::new();
        let r1 = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .unwrap();
        let r2 = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .unwrap();

        assert_eq!(r1.resolved_policy_hash, r2.resolved_policy_hash);
        assert_eq!(r1.capability_manifest_hash, r2.capability_manifest_hash);
        assert_eq!(r1.context_pack_hash, r2.context_pack_hash);
        assert_eq!(r1.resolved_risk_tier, r2.resolved_risk_tier);
    }

    /// Verifies that different work IDs produce different policy hashes,
    /// ensuring proper domain separation.
    #[test]
    fn test_governance_resolver_different_work_ids_differ() {
        let resolver = GovernancePolicyResolver::new();
        let r1 = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .unwrap();
        let r2 = resolver
            .resolve_for_claim("work-002", WorkRole::Reviewer, "actor-001")
            .unwrap();

        assert_ne!(
            r1.resolved_policy_hash, r2.resolved_policy_hash,
            "Different work_ids must produce different policy hashes"
        );
    }

    /// Integration test: verifies that a claim produced by the governance
    /// resolver has a risk tier that allows `SelfSigned` attestation through
    /// the attestation ratchet. This exercises the production
    /// `ClaimWork -> IngestReviewReceipt` path.
    #[test]
    fn test_governance_resolver_tier_allows_self_signed_attestation() {
        use apm2_core::fac::{AttestationLevel, AttestationRequirements, ReceiptKind, RiskTier};

        let resolver = GovernancePolicyResolver::new();
        let resolution = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .unwrap();

        // The resolved tier must be convertible to a valid RiskTier
        let tier = RiskTier::try_from(resolution.resolved_risk_tier)
            .expect("resolved_risk_tier must be a valid RiskTier value (0-4)");

        // Tier must be Tier1 — which accepts SelfSigned attestation
        assert_eq!(
            tier,
            RiskTier::Tier1,
            "Governance resolver must return Tier1 for transitional operation"
        );

        // Verify SelfSigned actually satisfies the attestation requirement
        // for this tier. This is the critical end-to-end assertion.
        let requirements = AttestationRequirements::new();
        let required_level = requirements.required_level(ReceiptKind::Review, tier);
        assert!(
            AttestationLevel::SelfSigned.satisfies(required_level),
            "SelfSigned must satisfy {required_level} for Review at {tier:?}"
        );
    }
}
