//! Capability manifest and validation for OCAP enforcement.
//!
//! This module implements capability manifests per AD-TOOL-002. Capabilities
//! are sealed references that grant specific tool access with scoped
//! parameters. Capabilities are delegated, not discovered (OCAP enforcement).
//!
//! # Architecture
//!
//! ```text
//! CapabilityManifest
//!     ├── manifest_id: unique identifier
//!     ├── capabilities: Vec<Capability>
//!     ├── delegator_id: who granted these capabilities
//!     ├── created_at: creation timestamp
//!     └── expires_at: optional expiration
//!           │
//!           └── each Capability:
//!                   ├── capability_id: unique within manifest
//!                   ├── tool_class: Read | Write | Execute | ...
//!                   ├── scope: CapabilityScope
//!                   └── risk_tier_required: minimum tier
//! ```
//!
//! # Security Model
//!
//! Per AD-TOOL-002:
//! - Capabilities MUST NOT be discoverable
//! - Only explicit delegation creates capabilities
//! - Sealed references prevent forgery or escalation
//! - All tool requests are validated against the manifest
//!
//! # Contract References
//!
//! - AD-TOOL-002: Capability manifests as sealed references
//! - AD-EPISODE-001: Capability manifest hash in envelope
//! - REQ-TOOL-001: Tool access control requirements
//! - CTR-1303: Bounded collections with MAX_* constants

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use serde::{Deserialize, Serialize};

use super::envelope::RiskTier;
use super::scope::{CapabilityScope, ScopeError};
use super::tool_class::ToolClass;

/// Maximum number of capabilities in a manifest.
pub const MAX_CAPABILITIES: usize = 1000;

/// Maximum length for manifest ID.
pub const MAX_MANIFEST_ID_LEN: usize = 256;

/// Maximum length for capability ID.
pub const MAX_CAPABILITY_ID_LEN: usize = 256;

/// Maximum length for actor ID.
pub const MAX_ACTOR_ID_LEN: usize = 256;

/// Error type for capability operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// Too many capabilities in manifest.
    TooManyCapabilities {
        /// Actual count of capabilities.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Manifest ID exceeds maximum length.
    ManifestIdTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Capability ID exceeds maximum length.
    CapabilityIdTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Actor ID exceeds maximum length.
    ActorIdTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Duplicate capability ID.
    DuplicateCapabilityId {
        /// The duplicated ID.
        id: String,
    },

    /// Scope validation failed.
    ScopeValidation(ScopeError),

    /// Manifest has expired.
    ManifestExpired,

    /// Required field is empty.
    EmptyField {
        /// Name of the empty field.
        field: &'static str,
    },
}

impl std::fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyCapabilities { count, max } => {
                write!(f, "too many capabilities: {count} (max {max})")
            },
            Self::ManifestIdTooLong { len, max } => {
                write!(f, "manifest ID too long: {len} bytes (max {max})")
            },
            Self::CapabilityIdTooLong { len, max } => {
                write!(f, "capability ID too long: {len} bytes (max {max})")
            },
            Self::ActorIdTooLong { len, max } => {
                write!(f, "actor ID too long: {len} bytes (max {max})")
            },
            Self::DuplicateCapabilityId { id } => {
                write!(f, "duplicate capability ID: {id}")
            },
            Self::ScopeValidation(e) => {
                write!(f, "scope validation failed: {e}")
            },
            Self::ManifestExpired => {
                write!(f, "capability manifest has expired")
            },
            Self::EmptyField { field } => {
                write!(f, "required field is empty: {field}")
            },
        }
    }
}

impl std::error::Error for CapabilityError {}

impl From<ScopeError> for CapabilityError {
    fn from(e: ScopeError) -> Self {
        Self::ScopeValidation(e)
    }
}

/// Decision result for capability validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityDecision {
    /// Request is allowed by the matched capability.
    Allow {
        /// The capability ID that allowed the request.
        capability_id: String,
    },

    /// Request is denied.
    Deny {
        /// Reason for denial.
        reason: DenyReason,
    },
}

impl CapabilityDecision {
    /// Returns `true` if this is an Allow decision.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns `true` if this is a Deny decision.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Reason for capability denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    /// No capability matches the requested tool class.
    NoMatchingCapability {
        /// The tool class that was requested.
        tool_class: ToolClass,
    },

    /// Path is not allowed by any capability scope.
    PathNotAllowed {
        /// The path that was denied.
        path: String,
    },

    /// Size exceeds capability limits.
    SizeExceeded {
        /// The requested size in bytes.
        requested: u64,
        /// The maximum allowed size.
        max: u64,
    },

    /// Network access denied.
    NetworkNotAllowed {
        /// The target host.
        host: String,
        /// The target port.
        port: u16,
    },

    /// Risk tier is insufficient.
    InsufficientRiskTier {
        /// The minimum required risk tier.
        required: RiskTier,
        /// The actual risk tier.
        actual: RiskTier,
    },

    /// Manifest has expired.
    ManifestExpired,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMatchingCapability { tool_class } => {
                write!(f, "no capability for tool class: {tool_class}")
            },
            Self::PathNotAllowed { path } => {
                write!(f, "path not allowed: {path}")
            },
            Self::SizeExceeded { requested, max } => {
                write!(f, "size exceeded: {requested} bytes (max {max})")
            },
            Self::NetworkNotAllowed { host, port } => {
                write!(f, "network access denied: {host}:{port}")
            },
            Self::InsufficientRiskTier { required, actual } => {
                write!(
                    f,
                    "insufficient risk tier: requires {required:?}, have {actual:?}"
                )
            },
            Self::ManifestExpired => {
                write!(f, "capability manifest has expired")
            },
        }
    }
}

/// A single capability granting access to a tool class with scoped parameters.
///
/// Per AD-TOOL-002, capabilities are sealed references that cannot be
/// forged or escalated. Each capability grants access to a specific tool
/// class within the defined scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Unique identifier for this capability within the manifest.
    pub capability_id: String,

    /// The tool class this capability grants access to.
    pub tool_class: ToolClass,

    /// Scope restrictions for this capability.
    pub scope: CapabilityScope,

    /// Minimum risk tier required to use this capability.
    pub risk_tier_required: RiskTier,
}

impl Capability {
    /// Creates a builder for constructing a capability.
    #[must_use]
    pub fn builder(id: impl Into<String>, tool_class: ToolClass) -> CapabilityBuilder {
        CapabilityBuilder::new(id, tool_class)
    }

    /// Validates the capability structure.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.capability_id.is_empty() {
            return Err(CapabilityError::EmptyField {
                field: "capability_id",
            });
        }
        if self.capability_id.len() > MAX_CAPABILITY_ID_LEN {
            return Err(CapabilityError::CapabilityIdTooLong {
                len: self.capability_id.len(),
                max: MAX_CAPABILITY_ID_LEN,
            });
        }
        self.scope.validate()?;
        Ok(())
    }

    /// Checks if this capability allows access to the given path.
    #[must_use]
    pub fn allows_path(&self, path: &Path) -> bool {
        self.scope.allows_path(path)
    }

    /// Checks if this capability allows the given read size.
    #[must_use]
    pub const fn allows_read_size(&self, size: u64) -> bool {
        self.scope.allows_read_size(size)
    }

    /// Checks if this capability allows the given write size.
    #[must_use]
    pub const fn allows_write_size(&self, size: u64) -> bool {
        self.scope.allows_write_size(size)
    }

    /// Checks if this capability allows network access to the given host/port.
    #[must_use]
    pub fn allows_network(&self, host: &str, port: u16) -> bool {
        self.scope.allows_network(host, port)
    }

    /// Checks if the given risk tier is sufficient for this capability.
    #[must_use]
    pub const fn risk_tier_sufficient(&self, actual_tier: RiskTier) -> bool {
        actual_tier.tier() >= self.risk_tier_required.tier()
    }
}

/// Internal protobuf representation for `Capability`.
#[derive(Clone, PartialEq, Message)]
struct CapabilityProto {
    #[prost(string, tag = "1")]
    capability_id: String,
    #[prost(uint32, optional, tag = "2")]
    tool_class: Option<u32>,
    #[prost(bytes = "vec", tag = "3")]
    scope_bytes: Vec<u8>,
    #[prost(uint32, optional, tag = "4")]
    risk_tier_required: Option<u32>,
}

impl Capability {
    /// Returns the canonical bytes for this capability.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = CapabilityProto {
            capability_id: self.capability_id.clone(),
            tool_class: Some(u32::from(self.tool_class.value())),
            scope_bytes: self.scope.canonical_bytes(),
            risk_tier_required: Some(u32::from(self.risk_tier_required.tier())),
        };
        proto.encode_to_vec()
    }
}

/// Builder for `Capability`.
#[derive(Debug, Clone)]
pub struct CapabilityBuilder {
    capability_id: String,
    tool_class: ToolClass,
    scope: CapabilityScope,
    risk_tier_required: RiskTier,
}

impl CapabilityBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new(id: impl Into<String>, tool_class: ToolClass) -> Self {
        Self {
            capability_id: id.into(),
            tool_class,
            scope: CapabilityScope::default(),
            risk_tier_required: RiskTier::default(),
        }
    }

    /// Sets the scope.
    #[must_use]
    pub fn scope(mut self, scope: CapabilityScope) -> Self {
        self.scope = scope;
        self
    }

    /// Sets the required risk tier.
    #[must_use]
    pub const fn risk_tier(mut self, tier: RiskTier) -> Self {
        self.risk_tier_required = tier;
        self
    }

    /// Builds the capability.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn build(self) -> Result<Capability, CapabilityError> {
        let cap = Capability {
            capability_id: self.capability_id,
            tool_class: self.tool_class,
            scope: self.scope,
            risk_tier_required: self.risk_tier_required,
        };
        cap.validate()?;
        Ok(cap)
    }
}

/// Capability manifest containing sealed capability references.
///
/// Per AD-TOOL-002, the manifest:
/// - Contains the complete set of capabilities granted to an episode
/// - Is immutable once created
/// - Is referenced by hash in the episode envelope
/// - Expires at a specified time (optional)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    /// Unique identifier for this manifest.
    pub manifest_id: String,

    /// The capabilities granted by this manifest.
    pub capabilities: Vec<Capability>,

    /// The actor ID that delegated these capabilities.
    pub delegator_id: String,

    /// When this manifest was created (Unix timestamp in seconds).
    pub created_at: u64,

    /// When this manifest expires (Unix timestamp in seconds).
    /// Zero means no expiration.
    pub expires_at: u64,
}

impl CapabilityManifest {
    /// Creates a builder for constructing a manifest.
    #[must_use]
    pub fn builder(manifest_id: impl Into<String>) -> CapabilityManifestBuilder {
        CapabilityManifestBuilder::new(manifest_id)
    }

    /// Validates the manifest structure.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        // Check ID lengths
        if self.manifest_id.is_empty() {
            return Err(CapabilityError::EmptyField {
                field: "manifest_id",
            });
        }
        if self.manifest_id.len() > MAX_MANIFEST_ID_LEN {
            return Err(CapabilityError::ManifestIdTooLong {
                len: self.manifest_id.len(),
                max: MAX_MANIFEST_ID_LEN,
            });
        }
        if self.delegator_id.is_empty() {
            return Err(CapabilityError::EmptyField {
                field: "delegator_id",
            });
        }
        if self.delegator_id.len() > MAX_ACTOR_ID_LEN {
            return Err(CapabilityError::ActorIdTooLong {
                len: self.delegator_id.len(),
                max: MAX_ACTOR_ID_LEN,
            });
        }

        // Check capability count (CTR-1303: bounded collections)
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(CapabilityError::TooManyCapabilities {
                count: self.capabilities.len(),
                max: MAX_CAPABILITIES,
            });
        }

        // Validate each capability and check for duplicates
        let mut seen_ids = std::collections::HashSet::with_capacity(self.capabilities.len());
        for cap in &self.capabilities {
            cap.validate()?;
            if !seen_ids.insert(&cap.capability_id) {
                return Err(CapabilityError::DuplicateCapabilityId {
                    id: cap.capability_id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Returns `true` if this manifest has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        now > self.expires_at
    }

    /// Returns `true` if this manifest has no capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Returns the number of capabilities in this manifest.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Finds capabilities matching the given tool class.
    pub fn find_by_tool_class(&self, tool_class: ToolClass) -> impl Iterator<Item = &Capability> {
        self.capabilities
            .iter()
            .filter(move |c| c.tool_class == tool_class)
    }

    /// Validates a tool request against this manifest.
    ///
    /// This is the main entry point for capability validation. It checks:
    /// 1. Manifest expiration
    /// 2. Matching tool class
    /// 3. Path containment (for filesystem operations)
    /// 4. Size limits
    /// 5. Network policy (for network operations)
    /// 6. Risk tier requirements
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to validate
    ///
    /// # Returns
    ///
    /// `CapabilityDecision::Allow` with the matching capability ID, or
    /// `CapabilityDecision::Deny` with the reason for denial.
    pub fn validate_request(&self, request: &ToolRequest) -> CapabilityDecision {
        // Check expiration first
        if self.is_expired() {
            return CapabilityDecision::Deny {
                reason: DenyReason::ManifestExpired,
            };
        }

        // Find capabilities matching the tool class
        let matching: Vec<_> = self.find_by_tool_class(request.tool_class).collect();

        if matching.is_empty() {
            return CapabilityDecision::Deny {
                reason: DenyReason::NoMatchingCapability {
                    tool_class: request.tool_class,
                },
            };
        }

        // Try each matching capability
        for cap in matching {
            // Check risk tier
            if !cap.risk_tier_sufficient(request.risk_tier) {
                continue;
            }

            // Check path if applicable
            if let Some(ref path) = request.path {
                if !cap.allows_path(path) {
                    continue;
                }
            }

            // Check size limits if applicable
            if let Some(size) = request.size {
                let size_allowed = match request.tool_class {
                    ToolClass::Read => cap.allows_read_size(size),
                    ToolClass::Write => cap.allows_write_size(size),
                    _ => true,
                };
                if !size_allowed {
                    continue;
                }
            }

            // Check network access if applicable
            if let Some((ref host, port)) = request.network {
                if !cap.allows_network(host, port) {
                    continue;
                }
            }

            // All checks passed
            return CapabilityDecision::Allow {
                capability_id: cap.capability_id.clone(),
            };
        }

        // No capability matched - determine best reason
        // This provides the most specific denial reason
        if let Some(ref path) = request.path {
            return CapabilityDecision::Deny {
                reason: DenyReason::PathNotAllowed {
                    path: path.to_string_lossy().to_string(),
                },
            };
        }

        if let Some((ref host, port)) = request.network {
            return CapabilityDecision::Deny {
                reason: DenyReason::NetworkNotAllowed {
                    host: host.clone(),
                    port,
                },
            };
        }

        // Fall back to risk tier reason
        if let Some(cap) = self.find_by_tool_class(request.tool_class).next() {
            return CapabilityDecision::Deny {
                reason: DenyReason::InsufficientRiskTier {
                    required: cap.risk_tier_required,
                    actual: request.risk_tier,
                },
            };
        }

        CapabilityDecision::Deny {
            reason: DenyReason::NoMatchingCapability {
                tool_class: request.tool_class,
            },
        }
    }

    /// Computes the BLAKE3 digest of this manifest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        blake3::hash(&bytes).into()
    }
}

/// Internal protobuf representation for `CapabilityManifest`.
#[derive(Clone, PartialEq, Message)]
struct CapabilityManifestProto {
    #[prost(string, tag = "1")]
    manifest_id: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    capability_bytes: Vec<Vec<u8>>,
    #[prost(string, tag = "3")]
    delegator_id: String,
    #[prost(uint64, optional, tag = "4")]
    created_at: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    expires_at: Option<u64>,
}

impl CapabilityManifest {
    /// Returns the canonical bytes for this manifest.
    ///
    /// Per AD-VERIFY-001, capabilities are sorted by ID for determinism.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Sort capabilities by ID for deterministic ordering
        let mut sorted_caps: Vec<_> = self.capabilities.iter().collect();
        sorted_caps.sort_by(|a, b| a.capability_id.cmp(&b.capability_id));

        let proto = CapabilityManifestProto {
            manifest_id: self.manifest_id.clone(),
            capability_bytes: sorted_caps.iter().map(|c| c.canonical_bytes()).collect(),
            delegator_id: self.delegator_id.clone(),
            created_at: Some(self.created_at),
            expires_at: Some(self.expires_at),
        };
        proto.encode_to_vec()
    }
}

/// Builder for `CapabilityManifest`.
#[derive(Debug, Clone)]
pub struct CapabilityManifestBuilder {
    manifest_id: String,
    capabilities: Vec<Capability>,
    delegator_id: String,
    created_at: u64,
    expires_at: u64,
}

impl CapabilityManifestBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new(manifest_id: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        Self {
            manifest_id: manifest_id.into(),
            capabilities: Vec::new(),
            delegator_id: String::new(),
            created_at: now,
            expires_at: 0,
        }
    }

    /// Sets the delegator ID.
    #[must_use]
    pub fn delegator(mut self, id: impl Into<String>) -> Self {
        self.delegator_id = id.into();
        self
    }

    /// Adds a capability.
    #[must_use]
    pub fn capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Sets the capabilities.
    #[must_use]
    pub fn capabilities(mut self, caps: Vec<Capability>) -> Self {
        self.capabilities = caps;
        self
    }

    /// Sets the creation timestamp.
    #[must_use]
    pub const fn created_at(mut self, timestamp: u64) -> Self {
        self.created_at = timestamp;
        self
    }

    /// Sets the expiration timestamp.
    #[must_use]
    pub const fn expires_at(mut self, timestamp: u64) -> Self {
        self.expires_at = timestamp;
        self
    }

    /// Sets expiration to a duration from now.
    #[must_use]
    pub fn expires_in(mut self, duration: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.expires_at = now + duration.as_secs();
        self
    }

    /// Builds the manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn build(self) -> Result<CapabilityManifest, CapabilityError> {
        let manifest = CapabilityManifest {
            manifest_id: self.manifest_id,
            capabilities: self.capabilities,
            delegator_id: self.delegator_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Tool request for capability validation.
///
/// This is a simplified representation of a tool request used for
/// capability validation. It extracts the relevant fields from the
/// full protobuf `ToolRequest`.
#[derive(Debug, Clone)]
pub struct ToolRequest {
    /// The tool class being requested.
    pub tool_class: ToolClass,

    /// Optional path for filesystem operations.
    pub path: Option<std::path::PathBuf>,

    /// Optional size for read/write operations.
    pub size: Option<u64>,

    /// Optional network target (host, port).
    pub network: Option<(String, u16)>,

    /// The risk tier of the current episode.
    pub risk_tier: RiskTier,
}

impl ToolRequest {
    /// Creates a new tool request.
    #[must_use]
    pub const fn new(tool_class: ToolClass, risk_tier: RiskTier) -> Self {
        Self {
            tool_class,
            path: None,
            size: None,
            network: None,
            risk_tier,
        }
    }

    /// Sets the path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the size.
    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Sets the network target.
    #[must_use]
    pub fn with_network(mut self, host: impl Into<String>, port: u16) -> Self {
        self.network = Some((host.into(), port));
        self
    }
}

/// Capability validator that wraps a manifest and provides validation.
///
/// Per AD-TOOL-002, the validator integrates with the policy engine
/// to provide OCAP enforcement.
#[derive(Debug, Clone)]
pub struct CapabilityValidator {
    manifest: CapabilityManifest,
}

impl CapabilityValidator {
    /// Creates a new validator with the given manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is invalid or expired.
    pub fn new(manifest: CapabilityManifest) -> Result<Self, CapabilityError> {
        manifest.validate()?;
        if manifest.is_expired() {
            return Err(CapabilityError::ManifestExpired);
        }
        Ok(Self { manifest })
    }

    /// Returns a reference to the underlying manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    /// Validates a tool request.
    #[must_use]
    pub fn validate(&self, request: &ToolRequest) -> CapabilityDecision {
        self.manifest.validate_request(request)
    }

    /// Validates a read request.
    #[must_use]
    pub fn validate_read(&self, path: &Path, size: u64, risk_tier: RiskTier) -> CapabilityDecision {
        let request = ToolRequest::new(ToolClass::Read, risk_tier)
            .with_path(path)
            .with_size(size);
        self.validate(&request)
    }

    /// Validates a write request.
    #[must_use]
    pub fn validate_write(
        &self,
        path: &Path,
        size: u64,
        risk_tier: RiskTier,
    ) -> CapabilityDecision {
        let request = ToolRequest::new(ToolClass::Write, risk_tier)
            .with_path(path)
            .with_size(size);
        self.validate(&request)
    }

    /// Validates an execute request.
    #[must_use]
    pub fn validate_execute(&self, risk_tier: RiskTier) -> CapabilityDecision {
        let request = ToolRequest::new(ToolClass::Execute, risk_tier);
        self.validate(&request)
    }

    /// Validates a network request.
    #[must_use]
    pub fn validate_network(
        &self,
        host: &str,
        port: u16,
        risk_tier: RiskTier,
    ) -> CapabilityDecision {
        let request =
            ToolRequest::new(ToolClass::Network, risk_tier).with_network(host.to_string(), port);
        self.validate(&request)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn make_read_capability(id: &str, paths: Vec<PathBuf>) -> Capability {
        Capability {
            capability_id: id.to_string(),
            tool_class: ToolClass::Read,
            scope: CapabilityScope {
                root_paths: paths,
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }
    }

    fn make_manifest(caps: Vec<Capability>) -> CapabilityManifest {
        CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(caps)
            .build()
            .unwrap()
    }

    #[test]
    fn test_capability_validation() {
        let cap = make_read_capability("cap-1", vec![PathBuf::from("/workspace")]);
        assert!(cap.validate().is_ok());
    }

    #[test]
    fn test_capability_empty_id() {
        let cap = Capability {
            capability_id: String::new(),
            tool_class: ToolClass::Read,
            scope: CapabilityScope::default(),
            risk_tier_required: RiskTier::Tier0,
        };
        assert!(matches!(
            cap.validate(),
            Err(CapabilityError::EmptyField { .. })
        ));
    }

    #[test]
    fn test_manifest_validation() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_manifest_duplicate_capability_id() {
        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .capability(make_read_capability("dup", vec![PathBuf::from("/a")]))
            .capability(make_read_capability("dup", vec![PathBuf::from("/b")]))
            .build();
        assert!(matches!(
            result,
            Err(CapabilityError::DuplicateCapabilityId { .. })
        ));
    }

    #[test]
    fn test_manifest_too_many_capabilities() {
        let caps: Vec<_> = (0..=MAX_CAPABILITIES)
            .map(|i| make_read_capability(&format!("cap-{i}"), vec![PathBuf::from("/workspace")]))
            .collect();
        let result = CapabilityManifest::builder("test")
            .delegator("delegator")
            .capabilities(caps)
            .build();
        assert!(matches!(
            result,
            Err(CapabilityError::TooManyCapabilities { .. })
        ));
    }

    #[test]
    fn test_validate_request_allowed() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier0)
            .with_path("/workspace/file.rs")
            .with_size(1024);

        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_validate_request_denied_no_capability() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let request =
            ToolRequest::new(ToolClass::Write, RiskTier::Tier0).with_path("/workspace/file.rs");

        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::NoMatchingCapability { .. }));
        }
    }

    #[test]
    fn test_validate_request_denied_path_not_allowed() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier0).with_path("/etc/passwd");

        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::PathNotAllowed { .. }));
        }
    }

    #[test]
    fn test_validate_request_denied_expired() {
        let manifest = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![make_read_capability(
                "cap-1",
                vec![PathBuf::from("/workspace")],
            )],
            delegator_id: "delegator".to_string(),
            created_at: 0,
            expires_at: 1, // Expired in 1970
        };

        let request = ToolRequest::new(ToolClass::Read, RiskTier::Tier0);

        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());
        if let CapabilityDecision::Deny { reason } = decision {
            assert!(matches!(reason, DenyReason::ManifestExpired));
        }
    }

    #[test]
    fn test_canonical_bytes_determinism() {
        let manifest1 = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![
                make_read_capability("b", vec![PathBuf::from("/b")]),
                make_read_capability("a", vec![PathBuf::from("/a")]),
            ],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 2000,
        };

        let manifest2 = CapabilityManifest {
            manifest_id: "test".to_string(),
            capabilities: vec![
                make_read_capability("a", vec![PathBuf::from("/a")]),
                make_read_capability("b", vec![PathBuf::from("/b")]),
            ],
            delegator_id: "delegator".to_string(),
            created_at: 1000,
            expires_at: 2000,
        };

        // Different order should produce same canonical bytes
        assert_eq!(manifest1.canonical_bytes(), manifest2.canonical_bytes());
        assert_eq!(manifest1.digest(), manifest2.digest());
    }

    #[test]
    fn test_capability_validator() {
        let manifest = make_manifest(vec![make_read_capability(
            "cap-1",
            vec![PathBuf::from("/workspace")],
        )]);

        let validator = CapabilityValidator::new(manifest).unwrap();

        let allowed =
            validator.validate_read(Path::new("/workspace/file.rs"), 1024, RiskTier::Tier0);
        assert!(allowed.is_allowed());

        let denied = validator.validate_read(Path::new("/etc/passwd"), 1024, RiskTier::Tier0);
        assert!(denied.is_denied());
    }

    #[test]
    fn test_risk_tier_enforcement() {
        let cap = Capability {
            capability_id: "high-risk".to_string(),
            tool_class: ToolClass::Execute,
            scope: CapabilityScope::allow_all(),
            risk_tier_required: RiskTier::Tier3,
        };
        let manifest = make_manifest(vec![cap]);

        // Tier 1 should be denied
        let request = ToolRequest::new(ToolClass::Execute, RiskTier::Tier1);
        let decision = manifest.validate_request(&request);
        assert!(decision.is_denied());

        // Tier 3 should be allowed
        let request = ToolRequest::new(ToolClass::Execute, RiskTier::Tier3);
        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());

        // Tier 4 should also be allowed (higher than required)
        let request = ToolRequest::new(ToolClass::Execute, RiskTier::Tier4);
        let decision = manifest.validate_request(&request);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_network_capability() {
        let cap = Capability {
            capability_id: "net".to_string(),
            tool_class: ToolClass::Network,
            scope: CapabilityScope {
                root_paths: Vec::new(),
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: Some(super::super::scope::NetworkPolicy {
                    allowed_hosts: vec!["*.example.com".to_string()],
                    allowed_ports: vec![443],
                    require_tls: true,
                }),
            },
            risk_tier_required: RiskTier::Tier0,
        };
        let manifest = make_manifest(vec![cap]);
        let validator = CapabilityValidator::new(manifest).unwrap();

        // Allowed host and port
        let allowed = validator.validate_network("api.example.com", 443, RiskTier::Tier0);
        assert!(allowed.is_allowed());

        // Wrong port
        let denied = validator.validate_network("api.example.com", 80, RiskTier::Tier0);
        assert!(denied.is_denied());

        // Wrong host
        let denied = validator.validate_network("evil.com", 443, RiskTier::Tier0);
        assert!(denied.is_denied());
    }
}
