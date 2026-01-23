//! Node identity management.
//!
//! Provides a stable, persistent identity for holonic nodes.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a node actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId(Uuid);

impl ActorId {
    /// Create a new random actor ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ActorId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ActorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Role of a node in the holonic network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    /// Root/kernel node.
    Kernel,
    /// Worker/child node.
    Worker,
}

/// Persistent identity for a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Stable actor ID for this node.
    pub id: ActorId,
    /// Node role in the network.
    pub role: NodeRole,
    /// UNIX timestamp (seconds) when identity was created.
    pub created_at: u64,
}

impl NodeIdentity {
    /// Create a new identity with the given role.
    #[must_use]
    pub fn new(role: NodeRole) -> Self {
        Self {
            id: ActorId::new(),
            role,
            created_at: now_epoch_secs(),
        }
    }

    /// Load identity from a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = resolve_identity_path(path.as_ref());
        let content = std::fs::read_to_string(&path).map_err(IdentityError::Io)?;
        let identity = serde_json::from_str(&content).map_err(IdentityError::Parse)?;
        Ok(identity)
    }

    /// Save identity to a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), IdentityError> {
        let path = resolve_identity_path(path.as_ref());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(IdentityError::Io)?;
        }

        let temp_path = path.with_extension("tmp");
        let content = serde_json::to_string_pretty(self).map_err(IdentityError::Serialize)?;
        std::fs::write(&temp_path, content).map_err(IdentityError::Io)?;
        std::fs::rename(&temp_path, &path).map_err(IdentityError::Io)?;
        Ok(())
    }

    /// Load identity from disk or create a new one if missing.
    ///
    /// The default role for a newly created identity is `Worker`.
    ///
    /// # Errors
    ///
    /// Returns an error if the existing file cannot be read or a new file
    /// cannot be written.
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        Self::load_or_create_with_role(path, NodeRole::Worker)
    }

    /// Load identity from disk or create a new one with a specific role.
    ///
    /// # Errors
    ///
    /// Returns an error if the existing file cannot be read or a new file
    /// cannot be written.
    pub fn load_or_create_with_role(
        path: impl AsRef<Path>,
        role: NodeRole,
    ) -> Result<Self, IdentityError> {
        let path = resolve_identity_path(path.as_ref());
        if path.exists() {
            return Self::load(&path);
        }

        let identity = Self::new(role);
        identity.save(&path)?;
        Ok(identity)
    }
}

/// Identity persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse error.
    #[error("failed to parse identity: {0}")]
    Parse(#[from] serde_json::Error),

    /// JSON serialize error.
    #[error("failed to serialize identity: {0}")]
    Serialize(serde_json::Error),
}

fn resolve_identity_path(path: &Path) -> PathBuf {
    if path.exists() {
        if path.is_dir() {
            return path.join("identity.json");
        }
        return path.to_path_buf();
    }

    if path.file_name().and_then(|name| name.to_str()) == Some("identity.json") {
        return path.to_path_buf();
    }

    if path.extension().is_some() {
        return path.to_path_buf();
    }

    path.join("identity.json")
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_persistence_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("apm2-identity-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let identity_path = temp_dir.join("identity.json");
        let identity = NodeIdentity::new(NodeRole::Worker);
        identity.save(&identity_path).unwrap();

        let loaded = NodeIdentity::load(&identity_path).unwrap();
        assert_eq!(identity, loaded);

        let loaded_or_created = NodeIdentity::load_or_create(&temp_dir).unwrap();
        assert_eq!(identity, loaded_or_created);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
