//! HMAC-SHA256 signature validation for GitHub webhooks.
//!
//! GitHub signs webhook payloads using HMAC-SHA256 with a shared secret.
//! The signature is provided in the `X-Hub-Signature-256` header in the
//! format: `sha256=<hex-encoded-signature>`.
//!
//! # Security Properties
//!
//! - Uses constant-time comparison to prevent timing attacks (CTR-WH001)
//! - The secret is wrapped in `SecretString` to prevent accidental logging
//! - Signature comparison uses the `subtle` crate for constant-time equality

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::error::WebhookError;

/// HMAC-SHA256 signature validator for GitHub webhooks.
///
/// This validator implements the GitHub webhook signature verification
/// protocol using HMAC-SHA256 with a shared secret.
#[derive(Clone)]
pub struct SignatureValidator {
    secret: SecretString,
}

impl SignatureValidator {
    /// Creates a new signature validator with the given secret.
    ///
    /// # Arguments
    ///
    /// * `secret` - The shared webhook secret configured in GitHub
    ///
    /// # Security Note
    ///
    /// The secret should be at least 32 bytes of cryptographically random data.
    /// It is stored in a `SecretString` to prevent accidental logging.
    #[must_use]
    pub const fn new(secret: SecretString) -> Self {
        Self { secret }
    }

    /// Verifies the HMAC-SHA256 signature of a webhook payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw request body bytes
    /// * `signature_header` - The value of the `X-Hub-Signature-256` header
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature header format is invalid
    /// - The signature doesn't match the computed HMAC
    ///
    /// # Security
    ///
    /// - Uses constant-time comparison to prevent timing attacks (CTR-WH001)
    /// - Never logs the secret or signature details (CTR-WH002)
    pub fn verify(&self, payload: &[u8], signature_header: &str) -> Result<(), WebhookError> {
        // Parse the signature header (format: "sha256=<hex>")
        let signature_hex = signature_header
            .strip_prefix("sha256=")
            .ok_or_else(|| WebhookError::InvalidSignatureFormat("missing sha256= prefix".into()))?;

        // Decode the hex signature
        let expected_signature = hex_decode(signature_hex)
            .map_err(|e| WebhookError::InvalidSignatureFormat(format!("invalid hex: {e}")))?;

        // Compute the HMAC-SHA256
        let computed_signature = self.compute_signature(payload);

        // Constant-time comparison (CTR-WH001)
        if computed_signature.ct_eq(&expected_signature).into() {
            Ok(())
        } else {
            tracing::warn!("webhook signature verification failed");
            Err(WebhookError::InvalidSignature)
        }
    }

    /// Computes the HMAC-SHA256 signature for a payload.
    fn compute_signature(&self, payload: &[u8]) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(self.secret.expose_secret().as_bytes())
            .expect("HMAC can take key of any size; this should not fail for valid SecretString");

        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }
}

/// Decodes a hex string into bytes.
///
/// Returns an error if the input contains invalid hex characters or has odd
/// length.
fn hex_decode(hex: &str) -> Result<Vec<u8>, HexDecodeError> {
    if hex.len() % 2 != 0 {
        return Err(HexDecodeError::OddLength);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();

    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi = hex_char_to_nibble(hi)?;
        let lo = hex_char_to_nibble(lo)?;
        bytes.push((hi << 4) | lo);
    }

    Ok(bytes)
}

const fn hex_char_to_nibble(c: char) -> Result<u8, HexDecodeError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(HexDecodeError::InvalidChar(c)),
    }
}

#[derive(Debug)]
enum HexDecodeError {
    OddLength,
    InvalidChar(char),
}

impl std::fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OddLength => write!(f, "odd number of hex characters"),
            Self::InvalidChar(c) => write!(f, "invalid hex character: '{c}'"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator() -> SignatureValidator {
        SignatureValidator::new(SecretString::from("test-secret-key"))
    }

    fn compute_expected_signature(secret: &str, payload: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        format!(
            "sha256={}",
            bytes.iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            })
        )
    }

    #[test]
    fn test_valid_signature() {
        let validator = create_test_validator();
        let payload = b"test payload";
        let signature = compute_expected_signature("test-secret-key", payload);

        let result = validator.verify(payload, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let validator = create_test_validator();
        let payload = b"test payload";
        // Use wrong secret
        let signature = compute_expected_signature("wrong-secret", payload);

        let result = validator.verify(payload, &signature);
        assert!(matches!(result, Err(WebhookError::InvalidSignature)));
    }

    #[test]
    fn test_missing_sha256_prefix() {
        let validator = create_test_validator();
        let payload = b"test payload";

        let result = validator.verify(payload, "abcdef1234567890");
        assert!(matches!(
            result,
            Err(WebhookError::InvalidSignatureFormat(_))
        ));
    }

    #[test]
    fn test_invalid_hex_in_signature() {
        let validator = create_test_validator();
        let payload = b"test payload";

        let result = validator.verify(payload, "sha256=notvalidhex!!!");
        assert!(matches!(
            result,
            Err(WebhookError::InvalidSignatureFormat(_))
        ));
    }

    #[test]
    fn test_odd_length_hex() {
        let validator = create_test_validator();
        let payload = b"test payload";

        let result = validator.verify(payload, "sha256=abc");
        assert!(matches!(
            result,
            Err(WebhookError::InvalidSignatureFormat(_))
        ));
    }

    #[test]
    fn test_empty_payload() {
        let validator = create_test_validator();
        let payload = b"";
        let signature = compute_expected_signature("test-secret-key", payload);

        let result = validator.verify(payload, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_payload() {
        let validator = create_test_validator();
        let payload = vec![0xab_u8; 100_000]; // 100KB
        let signature = compute_expected_signature("test-secret-key", &payload);

        let result = validator.verify(&payload, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hex_decode_valid() {
        let result = hex_decode("48656c6c6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_hex_decode_uppercase() {
        let result = hex_decode("48656C6C6F").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_hex_decode_empty() {
        let result = hex_decode("").unwrap();
        assert!(result.is_empty());
    }
}
