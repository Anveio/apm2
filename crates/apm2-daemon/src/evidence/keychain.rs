//! OS keychain integration for receipt signing keys.
//!
//! This module implements secure storage and retrieval of Ed25519 signing
//! keys using the OS-native keychain per AD-KEY-001.
//!
//! # Architecture
//!
//! ```text
//! SigningKeyStore (trait)
//!     |-- store_key(key_id, key_bytes, version)
//!     |-- load_key(key_id) -> SigningKey + version
//!     |-- delete_key(key_id)
//!     |-- list_keys() -> Vec<KeyInfo>
//!     `-- key_exists(key_id) -> bool
//!
//! OsKeychain (impl SigningKeyStore)
//!     `-- Uses `keyring` crate for Secret Service (Linux) / Keychain (macOS)
//!
//! InMemoryKeyStore (impl SigningKeyStore)
//!     `-- For testing without OS keychain
//! ```
//!
//! # Security Model
//!
//! Per AD-KEY-001:
//! - Keys are stored in OS keychain, never in plaintext files
//! - Key versioning enables rotation without breaking verification
//! - 90-day rotation schedule (enforced by caller)
//! - Old keys preserved for verification (1 year)
//!
//! # Contract References
//!
//! - AD-KEY-001: Key lifecycle management
//! - CTR-1303: Bounded collections
//! - CTR-2003: Fail-closed security defaults

use std::collections::HashMap;
use std::sync::RwLock;

use secrecy::zeroize::Zeroizing;
use thiserror::Error;

use super::signer::{KeyId, ReceiptSigner, SignerError};

// =============================================================================
// Constants
// =============================================================================

/// Service name for keychain entries.
pub const KEYCHAIN_SERVICE_NAME: &str = "apm2-receipt-signing";

/// Maximum number of keys to store (CTR-1303).
pub const MAX_STORED_KEYS: usize = 100;

/// Key data version for serialization compatibility.
const KEY_DATA_VERSION: u8 = 1;

// =============================================================================
// KeychainError
// =============================================================================

/// Errors that can occur during keychain operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeychainError {
    /// Key not found in keychain.
    #[error("key not found: {key_id}")]
    NotFound {
        /// The key ID that was not found.
        key_id: String,
    },

    /// Key already exists in keychain.
    #[error("key already exists: {key_id}")]
    AlreadyExists {
        /// The key ID that already exists.
        key_id: String,
    },

    /// Keychain operation failed.
    #[error("keychain error: {0}")]
    Keychain(String),

    /// Invalid key data format.
    #[error("invalid key data: {0}")]
    InvalidData(String),

    /// Maximum key limit exceeded.
    #[error("maximum key limit exceeded ({max} keys)")]
    LimitExceeded {
        /// Maximum number of keys.
        max: usize,
    },

    /// Key ID validation failed.
    #[error("key ID error: {0}")]
    KeyId(#[from] SignerError),

    /// Lock poisoned.
    #[error("internal lock poisoned")]
    LockPoisoned,
}

// =============================================================================
// KeyInfo
// =============================================================================

/// Metadata about a stored key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// Unique identifier for the key.
    pub key_id: KeyId,
    /// Version number for rotation tracking.
    pub version: u32,
    /// Timestamp when the key was created (Unix epoch seconds).
    pub created_at: u64,
}

// =============================================================================
// SigningKeyStore Trait
// =============================================================================

/// Trait for signing key storage backends.
///
/// This trait abstracts the key storage mechanism to allow:
/// - OS keychain storage for production
/// - In-memory storage for testing
pub trait SigningKeyStore: Send + Sync {
    /// Stores a signing key in the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `key_bytes` - 32-byte Ed25519 signing key seed
    /// * `version` - Version number for rotation tracking
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key already exists
    /// - Maximum key limit exceeded
    /// - Keychain operation fails
    fn store_key(
        &self,
        key_id: &KeyId,
        key_bytes: &[u8; 32],
        version: u32,
    ) -> Result<(), KeychainError>;

    /// Loads a signing key from the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key not found
    /// - Key data is corrupted
    /// - Keychain operation fails
    fn load_key(&self, key_id: &KeyId) -> Result<ReceiptSigner, KeychainError>;

    /// Deletes a signing key from the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    ///
    /// # Errors
    ///
    /// Returns an error if the keychain operation fails.
    /// Returns Ok(()) if key doesn't exist (idempotent delete).
    fn delete_key(&self, key_id: &KeyId) -> Result<(), KeychainError>;

    /// Lists all keys in the keystore.
    ///
    /// # Errors
    ///
    /// Returns an error if the keychain operation fails.
    fn list_keys(&self) -> Result<Vec<KeyInfo>, KeychainError>;

    /// Checks if a key exists in the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    fn key_exists(&self, key_id: &KeyId) -> Result<bool, KeychainError>;

    /// Updates the version of an existing key.
    ///
    /// This is used during key rotation to update the version number
    /// while preserving the same key bytes.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `new_version` - New version number
    ///
    /// # Errors
    ///
    /// Returns an error if the key doesn't exist or the operation fails.
    fn update_version(&self, key_id: &KeyId, new_version: u32) -> Result<(), KeychainError>;
}

// =============================================================================
// OsKeychain
// =============================================================================

/// OS keychain-backed signing key store.
///
/// Uses the `keyring` crate to store keys in the OS-native keychain:
/// - Linux: Secret Service API (GNOME Keyring, KDE Wallet)
/// - macOS: Keychain
/// - Windows: Credential Manager
pub struct OsKeychain {
    /// Service name for keychain entries.
    service_name: String,
    /// Cache of key metadata (key IDs and versions only, not secrets).
    metadata_cache: RwLock<HashMap<String, KeyInfo>>,
}

impl OsKeychain {
    /// Creates a new OS keychain store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            service_name: KEYCHAIN_SERVICE_NAME.to_string(),
            metadata_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new OS keychain store with a custom service name.
    ///
    /// # Arguments
    ///
    /// * `service_name` - Custom service name for keychain entries
    #[must_use]
    pub fn with_service_name(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            metadata_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Gets the keyring entry for a key.
    fn entry(&self, key_id: &KeyId) -> Result<keyring::Entry, KeychainError> {
        keyring::Entry::new(&self.service_name, key_id.as_str())
            .map_err(|e| KeychainError::Keychain(e.to_string()))
    }

    /// Serializes key data for storage.
    fn serialize_key_data(key_bytes: &[u8; 32], version: u32, created_at: u64) -> String {
        // Simple format: version:created_at:hex_key
        // Version prefix allows future format changes
        format!(
            "{}:{}:{}:{}",
            KEY_DATA_VERSION,
            version,
            created_at,
            hex::encode(key_bytes)
        )
    }

    /// Deserializes key data from storage.
    fn deserialize_key_data(data: &str) -> Result<(Zeroizing<[u8; 32]>, u32, u64), KeychainError> {
        let parts: Vec<&str> = data.split(':').collect();
        if parts.len() != 4 {
            return Err(KeychainError::InvalidData(
                "expected 4 colon-separated parts".to_string(),
            ));
        }

        let data_version: u8 = parts[0]
            .parse()
            .map_err(|_| KeychainError::InvalidData("invalid data version".to_string()))?;
        if data_version != KEY_DATA_VERSION {
            return Err(KeychainError::InvalidData(format!(
                "unsupported data version: {data_version}"
            )));
        }

        let version: u32 = parts[1]
            .parse()
            .map_err(|_| KeychainError::InvalidData("invalid key version".to_string()))?;

        let created_at: u64 = parts[2]
            .parse()
            .map_err(|_| KeychainError::InvalidData("invalid timestamp".to_string()))?;

        let key_bytes = hex::decode(parts[3])
            .map_err(|_| KeychainError::InvalidData("invalid hex key".to_string()))?;

        if key_bytes.len() != 32 {
            return Err(KeychainError::InvalidData(format!(
                "expected 32 key bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        Ok((Zeroizing::new(arr), version, created_at))
    }
}

impl Default for OsKeychain {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningKeyStore for OsKeychain {
    fn store_key(
        &self,
        key_id: &KeyId,
        key_bytes: &[u8; 32],
        version: u32,
    ) -> Result<(), KeychainError> {
        // Check if key already exists
        if self.key_exists(key_id)? {
            return Err(KeychainError::AlreadyExists {
                key_id: key_id.as_str().to_string(),
            });
        }

        // Check limit (CTR-1303)
        {
            let cache = self
                .metadata_cache
                .read()
                .map_err(|_| KeychainError::LockPoisoned)?;
            if cache.len() >= MAX_STORED_KEYS {
                return Err(KeychainError::LimitExceeded {
                    max: MAX_STORED_KEYS,
                });
            }
        }

        // Get current timestamp
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Serialize and store
        let data = Self::serialize_key_data(key_bytes, version, created_at);
        let entry = self.entry(key_id)?;
        entry
            .set_password(&data)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        // Update cache
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        cache.insert(
            key_id.as_str().to_string(),
            KeyInfo {
                key_id: key_id.clone(),
                version,
                created_at,
            },
        );

        Ok(())
    }

    fn load_key(&self, key_id: &KeyId) -> Result<ReceiptSigner, KeychainError> {
        let entry = self.entry(key_id)?;
        let data = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeychainError::NotFound {
                key_id: key_id.as_str().to_string(),
            },
            _ => KeychainError::Keychain(e.to_string()),
        })?;

        let (key_bytes, version, created_at) = Self::deserialize_key_data(&data)?;

        // Create signer from bytes
        let signer = ReceiptSigner::from_bytes(&*key_bytes, key_id.clone(), version)
            .map_err(KeychainError::KeyId)?;

        // Update cache
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        cache.insert(
            key_id.as_str().to_string(),
            KeyInfo {
                key_id: key_id.clone(),
                version,
                created_at,
            },
        );

        Ok(signer)
    }

    fn delete_key(&self, key_id: &KeyId) -> Result<(), KeychainError> {
        let entry = self.entry(key_id)?;

        // Attempt to delete, ignore NotFound (idempotent)
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {},
            Err(e) => return Err(KeychainError::Keychain(e.to_string())),
        }

        // Remove from cache
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        cache.remove(key_id.as_str());

        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<KeyInfo>, KeychainError> {
        let cache = self
            .metadata_cache
            .read()
            .map_err(|_| KeychainError::LockPoisoned)?;
        Ok(cache.values().cloned().collect())
    }

    fn key_exists(&self, key_id: &KeyId) -> Result<bool, KeychainError> {
        // Check cache first
        {
            let cache = self
                .metadata_cache
                .read()
                .map_err(|_| KeychainError::LockPoisoned)?;
            if cache.contains_key(key_id.as_str()) {
                return Ok(true);
            }
        }

        // Try to load from keychain
        let entry = self.entry(key_id)?;
        match entry.get_password() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KeychainError::Keychain(e.to_string())),
        }
    }

    fn update_version(&self, key_id: &KeyId, new_version: u32) -> Result<(), KeychainError> {
        // Load existing key
        let entry = self.entry(key_id)?;
        let data = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeychainError::NotFound {
                key_id: key_id.as_str().to_string(),
            },
            _ => KeychainError::Keychain(e.to_string()),
        })?;

        let (key_bytes, _old_version, created_at) = Self::deserialize_key_data(&data)?;

        // Store with new version
        let new_data = Self::serialize_key_data(&key_bytes, new_version, created_at);
        entry
            .set_password(&new_data)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        // Update cache
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        if let Some(info) = cache.get_mut(key_id.as_str()) {
            info.version = new_version;
        }

        Ok(())
    }
}

// =============================================================================
// InMemoryKeyStore
// =============================================================================

/// Entry stored in the in-memory key store.
type InMemoryKeyEntry = (Zeroizing<[u8; 32]>, KeyInfo);

/// In-memory signing key store for testing.
///
/// This implementation does not persist keys and is intended for unit tests
/// that should not interact with the real OS keychain.
pub struct InMemoryKeyStore {
    /// Storage for key data.
    keys: RwLock<HashMap<String, InMemoryKeyEntry>>,
}

impl InMemoryKeyStore {
    /// Creates a new in-memory key store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningKeyStore for InMemoryKeyStore {
    fn store_key(
        &self,
        key_id: &KeyId,
        key_bytes: &[u8; 32],
        version: u32,
    ) -> Result<(), KeychainError> {
        let mut keys = self.keys.write().map_err(|_| KeychainError::LockPoisoned)?;

        if keys.contains_key(key_id.as_str()) {
            return Err(KeychainError::AlreadyExists {
                key_id: key_id.as_str().to_string(),
            });
        }

        if keys.len() >= MAX_STORED_KEYS {
            return Err(KeychainError::LimitExceeded {
                max: MAX_STORED_KEYS,
            });
        }

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let info = KeyInfo {
            key_id: key_id.clone(),
            version,
            created_at,
        };

        keys.insert(
            key_id.as_str().to_string(),
            (Zeroizing::new(*key_bytes), info),
        );
        Ok(())
    }

    fn load_key(&self, key_id: &KeyId) -> Result<ReceiptSigner, KeychainError> {
        let keys = self.keys.read().map_err(|_| KeychainError::LockPoisoned)?;

        let (key_bytes, info) =
            keys.get(key_id.as_str())
                .ok_or_else(|| KeychainError::NotFound {
                    key_id: key_id.as_str().to_string(),
                })?;

        ReceiptSigner::from_bytes(&**key_bytes, key_id.clone(), info.version)
            .map_err(KeychainError::KeyId)
    }

    fn delete_key(&self, key_id: &KeyId) -> Result<(), KeychainError> {
        let mut keys = self.keys.write().map_err(|_| KeychainError::LockPoisoned)?;
        keys.remove(key_id.as_str());
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<KeyInfo>, KeychainError> {
        let keys = self.keys.read().map_err(|_| KeychainError::LockPoisoned)?;
        Ok(keys.values().map(|(_, info)| info.clone()).collect())
    }

    fn key_exists(&self, key_id: &KeyId) -> Result<bool, KeychainError> {
        let keys = self.keys.read().map_err(|_| KeychainError::LockPoisoned)?;
        Ok(keys.contains_key(key_id.as_str()))
    }

    fn update_version(&self, key_id: &KeyId, new_version: u32) -> Result<(), KeychainError> {
        let mut keys = self.keys.write().map_err(|_| KeychainError::LockPoisoned)?;

        let (_, info) = keys
            .get_mut(key_id.as_str())
            .ok_or_else(|| KeychainError::NotFound {
                key_id: key_id.as_str().to_string(),
            })?;

        info.version = new_version;
        Ok(())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generates a new signing key and stores it in the keystore.
///
/// # Arguments
///
/// * `store` - The key store to use
/// * `key_id` - Unique identifier for the key
/// * `version` - Version number for rotation tracking
///
/// # Errors
///
/// Returns an error if key generation or storage fails.
pub fn generate_and_store_key(
    store: &impl SigningKeyStore,
    key_id: &KeyId,
    version: u32,
) -> Result<ReceiptSigner, KeychainError> {
    // Generate a new signer
    let receipt_signer =
        ReceiptSigner::generate(key_id.clone(), version).map_err(KeychainError::KeyId)?;

    // Store the key bytes
    let key_bytes = receipt_signer.signing_key_bytes();
    store.store_key(key_id, &key_bytes, version)?;

    Ok(receipt_signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_store_key_roundtrip() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("test-key").unwrap();
        let key_bytes = [0x42u8; 32];

        // Store key
        store.store_key(&key_id, &key_bytes, 1).unwrap();

        // Load key
        let signer = store.load_key(&key_id).unwrap();
        assert_eq!(signer.key_id().as_str(), "test-key");
        assert_eq!(signer.key_version(), 1);
    }

    #[test]
    fn test_in_memory_key_already_exists() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("test-key").unwrap();
        let key_bytes = [0x42u8; 32];

        store.store_key(&key_id, &key_bytes, 1).unwrap();

        // Try to store again
        let result = store.store_key(&key_id, &key_bytes, 2);
        assert!(matches!(result, Err(KeychainError::AlreadyExists { .. })));
    }

    #[test]
    fn test_in_memory_key_not_found() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("nonexistent").unwrap();

        let result = store.load_key(&key_id);
        assert!(matches!(result, Err(KeychainError::NotFound { .. })));
    }

    #[test]
    fn test_in_memory_delete_key() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("test-key").unwrap();
        let key_bytes = [0x42u8; 32];

        store.store_key(&key_id, &key_bytes, 1).unwrap();
        assert!(store.key_exists(&key_id).unwrap());

        store.delete_key(&key_id).unwrap();
        assert!(!store.key_exists(&key_id).unwrap());
    }

    #[test]
    fn test_in_memory_delete_nonexistent_is_ok() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("nonexistent").unwrap();

        // Delete should be idempotent
        assert!(store.delete_key(&key_id).is_ok());
    }

    #[test]
    fn test_in_memory_list_keys() {
        let store = InMemoryKeyStore::new();

        // Empty list
        assert!(store.list_keys().unwrap().is_empty());

        // Add some keys
        store
            .store_key(&KeyId::new("key-1").unwrap(), &[0x01u8; 32], 1)
            .unwrap();
        store
            .store_key(&KeyId::new("key-2").unwrap(), &[0x02u8; 32], 2)
            .unwrap();

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_in_memory_update_version() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("test-key").unwrap();
        let key_bytes = [0x42u8; 32];

        store.store_key(&key_id, &key_bytes, 1).unwrap();

        // Update version
        store.update_version(&key_id, 2).unwrap();

        // Verify version was updated
        let signer = store.load_key(&key_id).unwrap();
        assert_eq!(signer.key_version(), 2);
    }

    #[test]
    fn test_generate_and_store_key() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("generated-key").unwrap();

        let receipt_signer = generate_and_store_key(&store, &key_id, 1).unwrap();
        assert_eq!(receipt_signer.key_id().as_str(), "generated-key");
        assert_eq!(receipt_signer.key_version(), 1);

        // Verify it was stored
        assert!(store.key_exists(&key_id).unwrap());

        // Verify we can load it
        let loaded = store.load_key(&key_id).unwrap();
        assert_eq!(loaded.public_key_bytes(), receipt_signer.public_key_bytes());
    }

    #[test]
    fn test_serialize_deserialize_key_data() {
        let key_bytes = [0x42u8; 32];
        let version = 3;
        let created_at = 1_704_067_200;

        let data = OsKeychain::serialize_key_data(&key_bytes, version, created_at);
        let (loaded_bytes, loaded_version, loaded_created_at) =
            OsKeychain::deserialize_key_data(&data).unwrap();

        assert_eq!(&*loaded_bytes, &key_bytes);
        assert_eq!(loaded_version, version);
        assert_eq!(loaded_created_at, created_at);
    }

    #[test]
    fn test_deserialize_invalid_data() {
        // Missing parts
        assert!(OsKeychain::deserialize_key_data("1:2:3").is_err());

        // Invalid version
        assert!(OsKeychain::deserialize_key_data("99:1:0:00").is_err());

        // Invalid hex
        assert!(OsKeychain::deserialize_key_data("1:1:0:not-hex").is_err());

        // Wrong key length
        assert!(OsKeychain::deserialize_key_data("1:1:0:00112233").is_err());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test only, i is bounded by MAX_STORED_KEYS
    fn test_key_limit_enforced() {
        let store = InMemoryKeyStore::new();

        // Store up to the limit
        for i in 0..MAX_STORED_KEYS {
            let key_id = KeyId::new(format!("key-{i}")).unwrap();
            store.store_key(&key_id, &[i as u8; 32], 1).unwrap();
        }

        // One more should fail
        let key_id = KeyId::new("key-overflow").unwrap();
        let result = store.store_key(&key_id, &[0xff; 32], 1);
        assert!(matches!(result, Err(KeychainError::LimitExceeded { .. })));
    }
}
