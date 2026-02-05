//! Role routing and classification logic for FAC.
//!
//! This module implements the heuristics for routing work to specialist roles
//! based on diff analysis and issue labels, per TCK-00334.

use crate::fac::builtin_roles::{
    dependency_updater_role, implementer_role, rust_compile_error_fixer_role, test_flake_fixer_role,
};
use crate::fac::role_spec::RoleSpecV1;

/// The decision made by the router.
#[derive(Debug, Clone, PartialEq)]
pub enum RoutingDecision {
    /// Route to a specialist role with narrowed scope.
    Specialist(RoleSpecV1),
    /// Route to the generalist implementer role.
    Generalist(RoleSpecV1),
}

impl RoutingDecision {
    /// Returns the selected role spec.
    pub fn role_spec(&self) -> &RoleSpecV1 {
        match self {
            Self::Specialist(role) => role,
            Self::Generalist(role) => role,
        }
    }
}

/// Classifies a changeset to determine the best role.
///
/// # Arguments
///
/// * `diff_stats` - List of file paths changed (simplified diff analysis).
/// * `issue_labels` - Labels associated with the work item.
/// * `issue_title` - Title of the work item.
pub fn classify_changeset(
    changed_files: &[String],
    issue_labels: &[String],
    issue_title: &str,
) -> RoutingDecision {
    // 1. Check explicit labels first (strongest signal)
    for label in issue_labels {
        match label.as_str() {
            "flaky-test" | "test-failure" => {
                return RoutingDecision::Specialist(test_flake_fixer_role());
            }
            "compile-error" | "build-failure" => {
                return RoutingDecision::Specialist(rust_compile_error_fixer_role());
            }
            "dependencies" | "deps" => {
                return RoutingDecision::Specialist(dependency_updater_role());
            }
            _ => {}
        }
    }

    // 2. Check title keywords (medium signal)
    let title_lower = issue_title.to_lowercase();
    if title_lower.contains("flake") || title_lower.contains("test fail") {
        return RoutingDecision::Specialist(test_flake_fixer_role());
    }
    if title_lower.contains("compile error") || title_lower.contains("build fail") {
        return RoutingDecision::Specialist(rust_compile_error_fixer_role());
    }
    if title_lower.contains("bump ") || title_lower.contains("dependency") || title_lower.contains("update crate") {
        return RoutingDecision::Specialist(dependency_updater_role());
    }

    // 3. Analyze changed files (heuristic signal)
    if !changed_files.is_empty() {
        if changed_files.iter().all(|f| {
            f.ends_with("Cargo.toml") || f.ends_with("Cargo.lock") || f.ends_with(".cargo/config.toml")
        }) {
            return RoutingDecision::Specialist(dependency_updater_role());
        }

        // If all changes are in test files, suggest test fixer?
        // Maybe, but implementer is also valid. Let's be conservative.
    }

    // Default to generalist implementer
    RoutingDecision::Generalist(implementer_role())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::builtin_roles::{
        DEPENDENCY_UPDATER_ROLE_ID, IMPLEMENTER_ROLE_ID, RUST_COMPILE_ERROR_FIXER_ROLE_ID,
        TEST_FLAKE_FIXER_ROLE_ID,
    };

    #[test]
    fn test_classify_by_label() {
        let decision = classify_changeset(&[], &["flaky-test".to_string()], "Some issue");
        assert_eq!(decision.role_spec().role_id, TEST_FLAKE_FIXER_ROLE_ID);
        assert!(matches!(decision, RoutingDecision::Specialist(_)));

        let decision = classify_changeset(&[], &["compile-error".to_string()], "Some issue");
        assert_eq!(
            decision.role_spec().role_id,
            RUST_COMPILE_ERROR_FIXER_ROLE_ID
        );

        let decision = classify_changeset(&[], &["dependencies".to_string()], "Some issue");
        assert_eq!(decision.role_spec().role_id, DEPENDENCY_UPDATER_ROLE_ID);
    }

    #[test]
    fn test_classify_by_title() {
        let decision = classify_changeset(&[], &[], "Fix CI flake in test_foo");
        assert_eq!(decision.role_spec().role_id, TEST_FLAKE_FIXER_ROLE_ID);

        let decision = classify_changeset(&[], &[], "Bump serde to 1.0.200");
        assert_eq!(decision.role_spec().role_id, DEPENDENCY_UPDATER_ROLE_ID);
    }

    #[test]
    fn test_classify_by_files() {
        let files = vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()];
        let decision = classify_changeset(&files, &[], "Maintenance");
        assert_eq!(decision.role_spec().role_id, DEPENDENCY_UPDATER_ROLE_ID);
    }

    #[test]
    fn test_classify_generalist_fallback() {
        let files = vec!["src/main.rs".to_string()];
        let decision = classify_changeset(&files, &[], "Implement new feature");
        assert_eq!(decision.role_spec().role_id, IMPLEMENTER_ROLE_ID);
        assert!(matches!(decision, RoutingDecision::Generalist(_)));
    }
}
