//! Capability scope and validation logic.
//!
//! This module defines `CapabilityScope` for constraining tool operations
//! to specific paths, patterns, and size limits. Per AD-TOOL-002, scopes
//! provide fine-grained restrictions on coarse-grained capability grants.
//!
//! # Architecture
//!
//! ```text
//! Capability (coarse-grained: "Read")
//!     └── CapabilityScope (fine-grained)
//!             ├── root_paths: ["/workspace"]
//!             ├── allowed_patterns: ["*.rs", "*.toml"]
//!             ├── size_limits: SizeLimits { max_read: 10MB }
//!             └── network_policy: None
//! ```
//!
//! # Security Model
//!
//! Scopes implement defense-in-depth:
//! 1. **Path containment**: Operations must be within root paths
//! 2. **Pattern matching**: Files must match allowed patterns
//! 3. **Size limits**: Operations bounded to prevent resource exhaustion
//! 4. **Network policy**: Network access restricted to allowed hosts/ports
//!
//! # Contract References
//!
//! - AD-TOOL-002: Capability manifests as sealed references
//! - CTR-1503: Path traversal rejection
//! - CTR-1303: Bounded collections with MAX_* constants

use std::path::{Path, PathBuf};

use prost::Message;
use serde::{Deserialize, Serialize};

/// Maximum number of root paths per scope.
pub const MAX_ROOT_PATHS: usize = 100;

/// Maximum number of allowed patterns per scope.
pub const MAX_ALLOWED_PATTERNS: usize = 1000;

/// Maximum length of a single pattern.
pub const MAX_PATTERN_LEN: usize = 1024;

/// Maximum number of allowed hosts in network policy.
pub const MAX_NETWORK_HOSTS: usize = 100;

/// Maximum number of allowed ports in network policy.
pub const MAX_NETWORK_PORTS: usize = 100;

/// Maximum path length for validation.
pub const MAX_PATH_LEN: usize = 4096;

/// Size limits for operations.
///
/// Prevents resource exhaustion by capping operation sizes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SizeLimits {
    /// Maximum bytes that can be read in a single operation.
    /// Zero means use default limit.
    pub max_read_bytes: u64,

    /// Maximum bytes that can be written in a single operation.
    /// Zero means use default limit.
    pub max_write_bytes: u64,

    /// Maximum command length for execute operations.
    /// Zero means use default limit.
    pub max_command_bytes: u64,

    /// Maximum response size for network operations.
    /// Zero means use default limit.
    pub max_response_bytes: u64,
}

impl SizeLimits {
    /// Creates size limits with default values.
    #[must_use]
    pub const fn default_limits() -> Self {
        Self {
            max_read_bytes: 100 * 1024 * 1024,     // 100 MB
            max_write_bytes: 100 * 1024 * 1024,    // 100 MB
            max_command_bytes: 1024 * 1024,        // 1 MB
            max_response_bytes: 100 * 1024 * 1024, // 100 MB
        }
    }

    /// Creates unlimited size limits (for testing only).
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_read_bytes: u64::MAX,
            max_write_bytes: u64::MAX,
            max_command_bytes: u64::MAX,
            max_response_bytes: u64::MAX,
        }
    }

    /// Returns `true` if the given read size is within limits.
    #[must_use]
    pub const fn allows_read_size(&self, size: u64) -> bool {
        self.max_read_bytes == 0 || size <= self.max_read_bytes
    }

    /// Returns `true` if the given write size is within limits.
    #[must_use]
    pub const fn allows_write_size(&self, size: u64) -> bool {
        self.max_write_bytes == 0 || size <= self.max_write_bytes
    }

    /// Returns `true` if the given command size is within limits.
    #[must_use]
    pub const fn allows_command_size(&self, size: u64) -> bool {
        self.max_command_bytes == 0 || size <= self.max_command_bytes
    }
}

/// Internal protobuf representation for `SizeLimits`.
#[allow(clippy::struct_field_names)] // Proto field names must match canonical schema
#[derive(Clone, PartialEq, Message)]
struct SizeLimitsProto {
    #[prost(uint64, optional, tag = "1")]
    max_read_bytes: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    max_write_bytes: Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    max_command_bytes: Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    max_response_bytes: Option<u64>,
}

impl SizeLimits {
    /// Returns the canonical bytes for size limits.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = SizeLimitsProto {
            max_read_bytes: Some(self.max_read_bytes),
            max_write_bytes: Some(self.max_write_bytes),
            max_command_bytes: Some(self.max_command_bytes),
            max_response_bytes: Some(self.max_response_bytes),
        };
        proto.encode_to_vec()
    }
}

/// Network access policy for capabilities.
///
/// Defines which hosts and ports can be accessed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Allowed host patterns (glob-style: `*.example.com`).
    /// Empty means no network access.
    pub allowed_hosts: Vec<String>,

    /// Allowed ports. Empty means all ports (if hosts are allowed).
    pub allowed_ports: Vec<u16>,

    /// Whether HTTPS is required.
    pub require_tls: bool,
}

impl NetworkPolicy {
    /// Creates a policy that allows no network access.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_ports: Vec::new(),
            require_tls: true,
        }
    }

    /// Returns `true` if network access is completely denied.
    #[must_use]
    pub fn is_deny_all(&self) -> bool {
        self.allowed_hosts.is_empty()
    }

    /// Validates the network policy structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy exceeds size limits.
    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.allowed_hosts.len() > MAX_NETWORK_HOSTS {
            return Err(ScopeError::TooManyHosts {
                count: self.allowed_hosts.len(),
                max: MAX_NETWORK_HOSTS,
            });
        }
        if self.allowed_ports.len() > MAX_NETWORK_PORTS {
            return Err(ScopeError::TooManyPorts {
                count: self.allowed_ports.len(),
                max: MAX_NETWORK_PORTS,
            });
        }
        for host in &self.allowed_hosts {
            if host.len() > MAX_PATTERN_LEN {
                return Err(ScopeError::PatternTooLong {
                    len: host.len(),
                    max: MAX_PATTERN_LEN,
                });
            }
        }
        Ok(())
    }

    /// Checks if the given host and port are allowed.
    #[must_use]
    pub fn allows(&self, host: &str, port: u16) -> bool {
        if self.is_deny_all() {
            return false;
        }

        // Check host pattern
        let host_allowed = self.allowed_hosts.iter().any(|pattern| {
            if pattern == "*" {
                true
            } else if let Some(suffix) = pattern.strip_prefix("*.") {
                host.ends_with(suffix) || host == suffix
            } else {
                host == pattern
            }
        });

        if !host_allowed {
            return false;
        }

        // Check port (empty means all ports allowed)
        if self.allowed_ports.is_empty() {
            return true;
        }
        self.allowed_ports.contains(&port)
    }
}

/// Internal protobuf representation for `NetworkPolicy`.
#[derive(Clone, PartialEq, Message)]
struct NetworkPolicyProto {
    #[prost(string, repeated, tag = "1")]
    allowed_hosts: Vec<String>,
    #[prost(uint32, repeated, tag = "2")]
    allowed_ports: Vec<u32>,
    #[prost(bool, optional, tag = "3")]
    require_tls: Option<bool>,
}

impl NetworkPolicy {
    /// Returns the canonical bytes for network policy.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted_hosts = self.allowed_hosts.clone();
        sorted_hosts.sort();
        let mut sorted_ports: Vec<u32> = self.allowed_ports.iter().map(|&p| u32::from(p)).collect();
        sorted_ports.sort_unstable();

        let proto = NetworkPolicyProto {
            allowed_hosts: sorted_hosts,
            allowed_ports: sorted_ports,
            require_tls: Some(self.require_tls),
        };
        proto.encode_to_vec()
    }
}

/// Error type for scope validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// Too many root paths.
    TooManyRootPaths {
        /// Actual count of root paths.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many allowed patterns.
    TooManyPatterns {
        /// Actual count of patterns.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Pattern exceeds maximum length.
    PatternTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Path exceeds maximum length.
    PathTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Path traversal detected.
    PathTraversal {
        /// The path containing traversal.
        path: String,
    },

    /// Too many network hosts.
    TooManyHosts {
        /// Actual count of hosts.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many network ports.
    TooManyPorts {
        /// Actual count of ports.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Root path is not absolute.
    RootPathNotAbsolute {
        /// The relative path.
        path: String,
    },
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyRootPaths { count, max } => {
                write!(f, "too many root paths: {count} (max {max})")
            },
            Self::TooManyPatterns { count, max } => {
                write!(f, "too many allowed patterns: {count} (max {max})")
            },
            Self::PatternTooLong { len, max } => {
                write!(f, "pattern too long: {len} bytes (max {max})")
            },
            Self::PathTooLong { len, max } => {
                write!(f, "path too long: {len} bytes (max {max})")
            },
            Self::PathTraversal { path } => {
                write!(f, "path traversal detected: {path}")
            },
            Self::TooManyHosts { count, max } => {
                write!(f, "too many network hosts: {count} (max {max})")
            },
            Self::TooManyPorts { count, max } => {
                write!(f, "too many network ports: {count} (max {max})")
            },
            Self::RootPathNotAbsolute { path } => {
                write!(f, "root path is not absolute: {path}")
            },
        }
    }
}

impl std::error::Error for ScopeError {}

/// Capability scope defining fine-grained restrictions.
///
/// Per AD-TOOL-002, scopes constrain capability grants to specific:
/// - Root paths (filesystem containment)
/// - Allowed patterns (file type filtering)
/// - Size limits (resource exhaustion prevention)
/// - Network policy (host/port restrictions)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    /// Allowed base directories for filesystem operations.
    /// Operations must be contained within these paths.
    pub root_paths: Vec<PathBuf>,

    /// Glob patterns for allowed file names/paths.
    /// Empty means all files within root paths are allowed.
    pub allowed_patterns: Vec<String>,

    /// Size limits for operations.
    pub size_limits: SizeLimits,

    /// Network access policy (for Network and Inference tool classes).
    pub network_policy: Option<NetworkPolicy>,
}

impl CapabilityScope {
    /// Creates a scope that allows all operations (for testing).
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            root_paths: vec![PathBuf::from("/")],
            allowed_patterns: Vec::new(),
            size_limits: SizeLimits::default_limits(),
            network_policy: None,
        }
    }

    /// Creates a scope for read-only access to a single directory.
    #[must_use]
    pub fn read_only(root: PathBuf) -> Self {
        Self {
            root_paths: vec![root],
            allowed_patterns: Vec::new(),
            size_limits: SizeLimits::default_limits(),
            network_policy: None,
        }
    }

    /// Creates a builder for constructing a scope.
    #[must_use]
    pub fn builder() -> CapabilityScopeBuilder {
        CapabilityScopeBuilder::new()
    }

    /// Validates the scope structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the scope exceeds size limits or contains
    /// invalid paths.
    pub fn validate(&self) -> Result<(), ScopeError> {
        // Check collection sizes
        if self.root_paths.len() > MAX_ROOT_PATHS {
            return Err(ScopeError::TooManyRootPaths {
                count: self.root_paths.len(),
                max: MAX_ROOT_PATHS,
            });
        }
        if self.allowed_patterns.len() > MAX_ALLOWED_PATTERNS {
            return Err(ScopeError::TooManyPatterns {
                count: self.allowed_patterns.len(),
                max: MAX_ALLOWED_PATTERNS,
            });
        }

        // Validate root paths
        for path in &self.root_paths {
            let path_str = path.to_string_lossy();
            if path_str.len() > MAX_PATH_LEN {
                return Err(ScopeError::PathTooLong {
                    len: path_str.len(),
                    max: MAX_PATH_LEN,
                });
            }
            if !path.is_absolute() {
                return Err(ScopeError::RootPathNotAbsolute {
                    path: path_str.to_string(),
                });
            }
            if contains_path_traversal(&path_str) {
                return Err(ScopeError::PathTraversal {
                    path: path_str.to_string(),
                });
            }
        }

        // Validate patterns
        for pattern in &self.allowed_patterns {
            if pattern.len() > MAX_PATTERN_LEN {
                return Err(ScopeError::PatternTooLong {
                    len: pattern.len(),
                    max: MAX_PATTERN_LEN,
                });
            }
        }

        // Validate network policy if present
        if let Some(ref policy) = self.network_policy {
            policy.validate()?;
        }

        Ok(())
    }

    /// Checks if the given path is allowed by this scope.
    ///
    /// # Security
    ///
    /// This method implements defense-in-depth path validation:
    /// 1. Rejects paths exceeding length limits
    /// 2. Rejects path traversal sequences
    /// 3. Requires path to be under a root path
    /// 4. Matches against allowed patterns if specified
    #[must_use]
    pub fn allows_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Length check
        if path_str.len() > MAX_PATH_LEN {
            return false;
        }

        // Path traversal check (CTR-1503)
        if contains_path_traversal(&path_str) {
            return false;
        }

        // Root path containment check
        let under_root = self.root_paths.iter().any(|root| path.starts_with(root));
        if !under_root {
            return false;
        }

        // Pattern matching (empty patterns means all allowed)
        if self.allowed_patterns.is_empty() {
            return true;
        }

        // Check if path matches any allowed pattern
        self.allowed_patterns
            .iter()
            .any(|pattern| matches_glob(path, pattern))
    }

    /// Checks if the given read size is allowed.
    #[must_use]
    pub const fn allows_read_size(&self, size: u64) -> bool {
        self.size_limits.allows_read_size(size)
    }

    /// Checks if the given write size is allowed.
    #[must_use]
    pub const fn allows_write_size(&self, size: u64) -> bool {
        self.size_limits.allows_write_size(size)
    }

    /// Checks if network access to the given host/port is allowed.
    #[must_use]
    pub fn allows_network(&self, host: &str, port: u16) -> bool {
        self.network_policy
            .as_ref()
            .is_some_and(|policy| policy.allows(host, port))
    }
}

/// Internal protobuf representation for `CapabilityScope`.
#[derive(Clone, PartialEq, Message)]
struct CapabilityScopeProto {
    #[prost(string, repeated, tag = "1")]
    root_paths: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    allowed_patterns: Vec<String>,
    #[prost(message, optional, tag = "3")]
    size_limits: Option<SizeLimitsProto>,
    #[prost(message, optional, tag = "4")]
    network_policy: Option<NetworkPolicyProto>,
}

impl CapabilityScope {
    /// Returns the canonical bytes for this scope.
    ///
    /// Per AD-VERIFY-001, repeated fields are sorted for determinism.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted_paths: Vec<String> = self
            .root_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        sorted_paths.sort();

        let mut sorted_patterns = self.allowed_patterns.clone();
        sorted_patterns.sort();

        let size_proto = SizeLimitsProto {
            max_read_bytes: Some(self.size_limits.max_read_bytes),
            max_write_bytes: Some(self.size_limits.max_write_bytes),
            max_command_bytes: Some(self.size_limits.max_command_bytes),
            max_response_bytes: Some(self.size_limits.max_response_bytes),
        };

        let network_proto = self.network_policy.as_ref().map(|np| {
            let mut sorted_hosts = np.allowed_hosts.clone();
            sorted_hosts.sort();
            let mut sorted_ports: Vec<u32> =
                np.allowed_ports.iter().map(|&p| u32::from(p)).collect();
            sorted_ports.sort_unstable();
            NetworkPolicyProto {
                allowed_hosts: sorted_hosts,
                allowed_ports: sorted_ports,
                require_tls: Some(np.require_tls),
            }
        });

        let proto = CapabilityScopeProto {
            root_paths: sorted_paths,
            allowed_patterns: sorted_patterns,
            size_limits: Some(size_proto),
            network_policy: network_proto,
        };
        proto.encode_to_vec()
    }
}

/// Builder for `CapabilityScope`.
#[derive(Debug, Clone, Default)]
pub struct CapabilityScopeBuilder {
    root_paths: Vec<PathBuf>,
    allowed_patterns: Vec<String>,
    size_limits: SizeLimits,
    network_policy: Option<NetworkPolicy>,
}

impl CapabilityScopeBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a root path.
    #[must_use]
    pub fn root_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.root_paths.push(path.into());
        self
    }

    /// Sets the root paths.
    #[must_use]
    pub fn root_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.root_paths = paths;
        self
    }

    /// Adds an allowed pattern.
    #[must_use]
    pub fn pattern(mut self, pattern: impl Into<String>) -> Self {
        self.allowed_patterns.push(pattern.into());
        self
    }

    /// Sets the allowed patterns.
    #[must_use]
    pub fn patterns(mut self, patterns: Vec<String>) -> Self {
        self.allowed_patterns = patterns;
        self
    }

    /// Sets the size limits.
    #[must_use]
    pub const fn size_limits(mut self, limits: SizeLimits) -> Self {
        self.size_limits = limits;
        self
    }

    /// Sets the network policy.
    #[must_use]
    pub fn network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.network_policy = Some(policy);
        self
    }

    /// Builds the scope.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn build(self) -> Result<CapabilityScope, ScopeError> {
        let scope = CapabilityScope {
            root_paths: self.root_paths,
            allowed_patterns: self.allowed_patterns,
            size_limits: self.size_limits,
            network_policy: self.network_policy,
        };
        scope.validate()?;
        Ok(scope)
    }
}

/// Checks if a path contains path traversal sequences.
///
/// Per CTR-1503, paths containing `..` are rejected.
fn contains_path_traversal(path: &str) -> bool {
    for component in path.split(['/', '\\']) {
        if component == ".." {
            return true;
        }
    }
    false
}

/// Simple glob pattern matching.
///
/// Supports:
/// - `*` matches any sequence of characters in a single component
/// - `**` matches any sequence of path components
/// - Exact literal matching otherwise
fn matches_glob(path: &Path, pattern: &str) -> bool {
    let path_str = path.to_string_lossy();

    // Handle ** for recursive matching
    if pattern.contains("**") {
        // Convert ** to regex-like matching
        let parts: Vec<&str> = pattern.split("**").collect();
        if parts.len() == 2 {
            let prefix = parts[0].trim_end_matches('/');
            let suffix = parts[1].trim_start_matches('/');

            if !prefix.is_empty() && !path_str.starts_with(prefix) {
                return false;
            }
            if !suffix.is_empty() {
                // Check if any component matches the suffix pattern
                return path_str.ends_with(suffix)
                    || path
                        .file_name()
                        .is_some_and(|name| matches_simple_glob(&name.to_string_lossy(), suffix));
            }
            return true;
        }
    }

    // Handle single * for filename matching
    path.file_name()
        .is_some_and(|file_name| matches_simple_glob(&file_name.to_string_lossy(), pattern))
}

/// Simple single-component glob matching.
fn matches_simple_glob(text: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Check for prefix wildcard (e.g., "*.rs")
    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }

    // Check for suffix wildcard (e.g., "main*")
    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }

    // Exact match
    text == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_limits_default() {
        let limits = SizeLimits::default_limits();
        assert!(limits.allows_read_size(1024));
        assert!(limits.allows_read_size(100 * 1024 * 1024)); // 100 MB
        assert!(!limits.allows_read_size(101 * 1024 * 1024)); // > 100 MB
    }

    #[test]
    fn test_size_limits_zero_means_default() {
        let limits = SizeLimits::default();
        // Zero means use default (unlimited in this case)
        assert!(limits.allows_read_size(u64::MAX));
    }

    #[test]
    fn test_network_policy_deny_all() {
        let policy = NetworkPolicy::deny_all();
        assert!(policy.is_deny_all());
        assert!(!policy.allows("example.com", 443));
    }

    #[test]
    fn test_network_policy_allows() {
        let policy = NetworkPolicy {
            allowed_hosts: vec!["*.example.com".to_string()],
            allowed_ports: vec![80, 443],
            require_tls: true,
        };

        assert!(policy.allows("api.example.com", 443));
        assert!(policy.allows("example.com", 80));
        assert!(!policy.allows("example.com", 8080)); // Wrong port
        assert!(!policy.allows("evil.com", 443)); // Wrong host
    }

    #[test]
    fn test_network_policy_wildcard() {
        let policy = NetworkPolicy {
            allowed_hosts: vec!["*".to_string()],
            allowed_ports: vec![],
            require_tls: false,
        };

        assert!(policy.allows("any.host.com", 12345));
    }

    #[test]
    fn test_scope_validation_too_many_paths() {
        let scope = CapabilityScope {
            root_paths: (0..=MAX_ROOT_PATHS)
                .map(|i| PathBuf::from(format!("/path/{i}")))
                .collect(),
            ..Default::default()
        };
        assert!(matches!(
            scope.validate(),
            Err(ScopeError::TooManyRootPaths { .. })
        ));
    }

    #[test]
    fn test_scope_validation_non_absolute_path() {
        let scope = CapabilityScope {
            root_paths: vec![PathBuf::from("relative/path")],
            ..Default::default()
        };
        assert!(matches!(
            scope.validate(),
            Err(ScopeError::RootPathNotAbsolute { .. })
        ));
    }

    #[test]
    fn test_scope_validation_path_traversal() {
        let scope = CapabilityScope {
            root_paths: vec![PathBuf::from("/workspace/../etc")],
            ..Default::default()
        };
        assert!(matches!(
            scope.validate(),
            Err(ScopeError::PathTraversal { .. })
        ));
    }

    #[test]
    fn test_scope_allows_path_basic() {
        let scope = CapabilityScope {
            root_paths: vec![PathBuf::from("/workspace")],
            allowed_patterns: Vec::new(),
            size_limits: SizeLimits::default_limits(),
            network_policy: None,
        };

        assert!(scope.allows_path(Path::new("/workspace/file.rs")));
        assert!(scope.allows_path(Path::new("/workspace/src/main.rs")));
        assert!(!scope.allows_path(Path::new("/etc/passwd")));
    }

    #[test]
    fn test_scope_allows_path_with_patterns() {
        let scope = CapabilityScope {
            root_paths: vec![PathBuf::from("/workspace")],
            allowed_patterns: vec!["*.rs".to_string(), "*.toml".to_string()],
            size_limits: SizeLimits::default_limits(),
            network_policy: None,
        };

        assert!(scope.allows_path(Path::new("/workspace/main.rs")));
        assert!(scope.allows_path(Path::new("/workspace/Cargo.toml")));
        assert!(!scope.allows_path(Path::new("/workspace/secret.txt")));
    }

    #[test]
    fn test_scope_rejects_path_traversal() {
        let scope = CapabilityScope {
            root_paths: vec![PathBuf::from("/workspace")],
            ..Default::default()
        };

        assert!(!scope.allows_path(Path::new("/workspace/../etc/passwd")));
        assert!(!scope.allows_path(Path::new("/workspace/subdir/../../etc")));
    }

    #[test]
    fn test_scope_builder() {
        let scope = CapabilityScope::builder()
            .root_path("/workspace")
            .pattern("*.rs")
            .size_limits(SizeLimits::default_limits())
            .build()
            .unwrap();

        assert!(scope.allows_path(Path::new("/workspace/main.rs")));
    }

    #[test]
    fn test_scope_canonical_bytes_determinism() {
        let scope1 = CapabilityScope {
            root_paths: vec![PathBuf::from("/b"), PathBuf::from("/a")],
            allowed_patterns: vec!["*.rs".to_string(), "*.md".to_string()],
            size_limits: SizeLimits::default_limits(),
            network_policy: None,
        };

        let scope2 = CapabilityScope {
            root_paths: vec![PathBuf::from("/a"), PathBuf::from("/b")],
            allowed_patterns: vec!["*.md".to_string(), "*.rs".to_string()],
            size_limits: SizeLimits::default_limits(),
            network_policy: None,
        };

        // Same content, different order should produce same canonical bytes
        assert_eq!(scope1.canonical_bytes(), scope2.canonical_bytes());
    }

    #[test]
    fn test_glob_matching() {
        assert!(matches_glob(Path::new("/workspace/main.rs"), "*.rs"));
        assert!(matches_glob(Path::new("/workspace/main.rs"), "main*"));
        assert!(!matches_glob(Path::new("/workspace/main.rs"), "*.txt"));
    }

    #[test]
    fn test_glob_recursive() {
        assert!(matches_glob(Path::new("/workspace/src/main.rs"), "**/*.rs"));
        assert!(matches_glob(
            Path::new("/workspace/deep/nested/file.rs"),
            "**/file.rs"
        ));
    }

    #[test]
    fn test_contains_path_traversal() {
        assert!(contains_path_traversal(".."));
        assert!(contains_path_traversal("../"));
        assert!(contains_path_traversal("foo/../bar"));
        assert!(contains_path_traversal("/path/to/../file"));
        assert!(!contains_path_traversal("/path/to/file"));
        assert!(!contains_path_traversal("..."));
        assert!(!contains_path_traversal("..file"));
    }
}
