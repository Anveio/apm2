//! Protocol handshake for version negotiation.
//!
//! This module implements the Hello/HelloAck handshake protocol for
//! establishing a connection between client and server. The handshake
//! performs protocol version negotiation and exchanges initial metadata.
//!
//! # Handshake Sequence
//!
//! ```text
//! Client                                    Server
//!   |                                          |
//!   |  -- Hello { version, client_info } -->   |
//!   |                                          |
//!   |  <-- HelloAck { version, server_info } --|
//!   |      OR                                  |
//!   |  <-- HelloNack { error } ----------------|
//!   |                                          |
//! ```
//!
//! # Version Negotiation
//!
//! The server accepts clients with compatible protocol versions:
//! - Same major version
//! - Client minor version <= server minor version (backward compatible)
//!
//! # Security Considerations
//!
//! - Handshake must complete before any other messages
//! - Invalid handshake terminates the connection
//! - Version mismatch provides diagnostic info without leaking internals

use serde::{Deserialize, Serialize};

use super::error::{PROTOCOL_VERSION, ProtocolError, ProtocolResult};

/// Hello message sent by client to initiate handshake.
///
/// The client sends this as the first message after connecting.
/// The server validates the version and responds with [`HelloAck`]
/// or [`HelloNack`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// Protocol version requested by the client.
    pub protocol_version: u32,

    /// Client identifier for logging and diagnostics.
    ///
    /// Should include client name and version, e.g., "apm2-cli/0.3.0".
    pub client_info: String,

    /// Optional client capabilities for future extension.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

impl Hello {
    /// Create a new Hello message.
    #[must_use]
    pub fn new(client_info: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            client_info: client_info.into(),
            capabilities: Vec::new(),
        }
    }

    /// Create a Hello with specific protocol version (for testing).
    #[must_use]
    pub fn with_version(protocol_version: u32, client_info: impl Into<String>) -> Self {
        Self {
            protocol_version,
            client_info: client_info.into(),
            capabilities: Vec::new(),
        }
    }

    /// Add capabilities to the Hello message.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }
}

/// Successful handshake acknowledgment from server.
///
/// Sent when the server accepts the client's Hello message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HelloAck {
    /// Protocol version agreed upon.
    ///
    /// This may be lower than the client requested if the server
    /// only supports an older version.
    pub protocol_version: u32,

    /// Server identifier for logging and diagnostics.
    ///
    /// Should include server name and version, e.g., "apm2-daemon/0.3.0".
    pub server_info: String,

    /// Hash of the current policy configuration (optional).
    ///
    /// Allows clients to verify they're connecting to the expected
    /// daemon instance with the expected policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,

    /// Server capabilities for feature negotiation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

impl HelloAck {
    /// Create a new `HelloAck` message.
    #[must_use]
    pub fn new(server_info: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            server_info: server_info.into(),
            policy_hash: None,
            capabilities: Vec::new(),
        }
    }

    /// Set the policy hash.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.policy_hash = Some(hash.into());
        self
    }

    /// Add capabilities to the `HelloAck` message.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }
}

/// Handshake rejection from server.
///
/// Sent when the server cannot accept the client's Hello message.
/// The connection should be closed after sending/receiving this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HelloNack {
    /// Error code for the rejection.
    pub error_code: HandshakeErrorCode,

    /// Human-readable error message.
    pub message: String,

    /// Server's protocol version (for version mismatch diagnostics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_version: Option<u32>,
}

impl HelloNack {
    /// Create a version mismatch rejection.
    #[must_use]
    pub fn version_mismatch(client_version: u32) -> Self {
        Self {
            error_code: HandshakeErrorCode::VersionMismatch,
            message: format!(
                "protocol version {client_version} not supported, server supports version {PROTOCOL_VERSION}"
            ),
            server_version: Some(PROTOCOL_VERSION),
        }
    }

    /// Create a generic rejection with custom message.
    #[must_use]
    pub fn rejected(message: impl Into<String>) -> Self {
        Self {
            error_code: HandshakeErrorCode::Rejected,
            message: message.into(),
            server_version: None,
        }
    }
}

/// Error codes for handshake rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeErrorCode {
    /// Protocol version not supported.
    VersionMismatch,

    /// Handshake rejected for other reasons.
    Rejected,

    /// Server is shutting down.
    ServerShuttingDown,

    /// Too many connections.
    TooManyConnections,
}

/// Handshake message envelope.
///
/// Used for serialization to determine the message type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandshakeMessage {
    /// Client Hello.
    Hello(Hello),

    /// Server acknowledgment.
    HelloAck(HelloAck),

    /// Server rejection.
    HelloNack(HelloNack),
}

impl From<Hello> for HandshakeMessage {
    fn from(hello: Hello) -> Self {
        Self::Hello(hello)
    }
}

impl From<HelloAck> for HandshakeMessage {
    fn from(ack: HelloAck) -> Self {
        Self::HelloAck(ack)
    }
}

impl From<HelloNack> for HandshakeMessage {
    fn from(nack: HelloNack) -> Self {
        Self::HelloNack(nack)
    }
}

/// Handshake state machine for the server side.
///
/// Tracks the current state of the handshake negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeState {
    /// Waiting for client Hello.
    #[default]
    AwaitingHello,

    /// Handshake completed successfully.
    Completed,

    /// Handshake failed.
    Failed,
}

/// Server-side handshake handler.
///
/// Validates client Hello messages and generates appropriate responses.
#[derive(Debug)]
pub struct ServerHandshake {
    /// Server info string for `HelloAck`.
    server_info: String,

    /// Optional policy hash to include in `HelloAck`.
    policy_hash: Option<String>,

    /// Current handshake state.
    state: HandshakeState,

    /// Negotiated protocol version (after successful handshake).
    negotiated_version: Option<u32>,
}

impl ServerHandshake {
    /// Create a new server handshake handler.
    #[must_use]
    pub fn new(server_info: impl Into<String>) -> Self {
        Self {
            server_info: server_info.into(),
            policy_hash: None,
            state: HandshakeState::AwaitingHello,
            negotiated_version: None,
        }
    }

    /// Set the policy hash for the handshake.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.policy_hash = Some(hash.into());
        self
    }

    /// Process a client Hello message.
    ///
    /// Returns the response to send to the client.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the handshake is not in `AwaitingHello` state.
    pub fn process_hello(&mut self, hello: &Hello) -> ProtocolResult<HandshakeMessage> {
        if self.state != HandshakeState::AwaitingHello {
            self.state = HandshakeState::Failed;
            return Err(ProtocolError::handshake_failed(
                "unexpected Hello message (already handshaked)",
            ));
        }

        // Validate protocol version
        if !Self::is_version_compatible(hello.protocol_version) {
            self.state = HandshakeState::Failed;
            return Ok(HelloNack::version_mismatch(hello.protocol_version).into());
        }

        // Handshake successful
        self.state = HandshakeState::Completed;
        self.negotiated_version = Some(hello.protocol_version.min(PROTOCOL_VERSION));

        let mut ack = HelloAck::new(&self.server_info);
        if let Some(ref hash) = self.policy_hash {
            ack = ack.with_policy_hash(hash);
        }

        Ok(ack.into())
    }

    /// Check if a client protocol version is compatible.
    ///
    /// Currently only version 1 is supported (exact match).
    /// Future versions may implement backward compatibility.
    const fn is_version_compatible(client_version: u32) -> bool {
        // For now, only exact version match is supported
        // Future: could implement major/minor version compatibility
        client_version == PROTOCOL_VERSION
    }

    /// Returns the current handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Returns the negotiated protocol version if handshake completed.
    #[must_use]
    pub const fn negotiated_version(&self) -> Option<u32> {
        self.negotiated_version
    }

    /// Returns `true` if the handshake completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self.state, HandshakeState::Completed)
    }
}

/// Client-side handshake handler.
///
/// Generates Hello messages and processes server responses.
#[derive(Debug)]
pub struct ClientHandshake {
    /// Client info string for Hello.
    client_info: String,

    /// Current handshake state.
    state: HandshakeState,

    /// Negotiated protocol version (after successful handshake).
    negotiated_version: Option<u32>,

    /// Server info from `HelloAck`.
    server_info: Option<String>,
}

impl ClientHandshake {
    /// Create a new client handshake handler.
    #[must_use]
    pub fn new(client_info: impl Into<String>) -> Self {
        Self {
            client_info: client_info.into(),
            state: HandshakeState::AwaitingHello,
            negotiated_version: None,
            server_info: None,
        }
    }

    /// Generate the Hello message to send to the server.
    #[must_use]
    pub fn create_hello(&self) -> Hello {
        Hello::new(&self.client_info)
    }

    /// Process the server's response to our Hello.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the server rejected the handshake.
    pub fn process_response(&mut self, response: HandshakeMessage) -> ProtocolResult<()> {
        match response {
            HandshakeMessage::HelloAck(ack) => {
                self.state = HandshakeState::Completed;
                self.negotiated_version = Some(ack.protocol_version);
                self.server_info = Some(ack.server_info);
                Ok(())
            },
            HandshakeMessage::HelloNack(nack) => {
                self.state = HandshakeState::Failed;
                match nack.error_code {
                    HandshakeErrorCode::VersionMismatch => {
                        Err(ProtocolError::version_mismatch(PROTOCOL_VERSION))
                    },
                    _ => Err(ProtocolError::handshake_failed(nack.message)),
                }
            },
            HandshakeMessage::Hello(_) => {
                self.state = HandshakeState::Failed;
                Err(ProtocolError::handshake_failed(
                    "received Hello instead of HelloAck/HelloNack",
                ))
            },
        }
    }

    /// Returns the current handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Returns the negotiated protocol version if handshake completed.
    #[must_use]
    pub const fn negotiated_version(&self) -> Option<u32> {
        self.negotiated_version
    }

    /// Returns the server info if handshake completed.
    #[must_use]
    pub fn server_info(&self) -> Option<&str> {
        self.server_info.as_deref()
    }

    /// Returns `true` if the handshake completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self.state, HandshakeState::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_serialization() {
        let hello = Hello::new("test-client/1.0");
        let json = serde_json::to_string(&hello).unwrap();

        assert!(json.contains("protocol_version"));
        assert!(json.contains("test-client/1.0"));

        let parsed: Hello = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, hello);
    }

    #[test]
    fn test_hello_ack_serialization() {
        let ack = HelloAck::new("test-server/1.0").with_policy_hash("abc123");

        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("policy_hash"));
        assert!(json.contains("abc123"));

        let parsed: HelloAck = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ack);
    }

    #[test]
    fn test_hello_nack_serialization() {
        let nack = HelloNack::version_mismatch(99);
        let json = serde_json::to_string(&nack).unwrap();

        assert!(json.contains("version_mismatch"));
        assert!(json.contains(&PROTOCOL_VERSION.to_string()));

        let parsed: HelloNack = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, nack);
    }

    #[test]
    fn test_handshake_message_envelope() {
        let hello: HandshakeMessage = Hello::new("client").into();
        let json = serde_json::to_string(&hello).unwrap();

        assert!(json.contains(r#""type":"hello""#));

        let parsed: HandshakeMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HandshakeMessage::Hello(_)));
    }

    #[test]
    fn test_server_handshake_success() {
        let mut server = ServerHandshake::new("daemon/1.0");
        assert_eq!(server.state(), HandshakeState::AwaitingHello);

        let hello = Hello::new("cli/1.0");
        let response = server.process_hello(&hello).unwrap();

        assert!(matches!(response, HandshakeMessage::HelloAck(_)));
        assert!(server.is_completed());
        assert_eq!(server.negotiated_version(), Some(PROTOCOL_VERSION));
    }

    #[test]
    fn test_server_handshake_version_mismatch() {
        let mut server = ServerHandshake::new("daemon/1.0");

        let hello = Hello::with_version(99, "cli/1.0");
        let response = server.process_hello(&hello).unwrap();

        assert!(matches!(response, HandshakeMessage::HelloNack(_)));
        assert_eq!(server.state(), HandshakeState::Failed);
    }

    #[test]
    fn test_server_handshake_duplicate_hello() {
        let mut server = ServerHandshake::new("daemon/1.0");

        // First hello succeeds
        let hello1 = Hello::new("cli/1.0");
        server.process_hello(&hello1).unwrap();

        // Second hello fails
        let hello2 = Hello::new("cli/1.0");
        let result = server.process_hello(&hello2);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_handshake_success() {
        let mut client = ClientHandshake::new("cli/1.0");

        let hello = client.create_hello();
        assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
        assert_eq!(hello.client_info, "cli/1.0");

        let ack = HelloAck::new("daemon/1.0");
        client.process_response(ack.into()).unwrap();

        assert!(client.is_completed());
        assert_eq!(client.server_info(), Some("daemon/1.0"));
    }

    #[test]
    fn test_client_handshake_rejected() {
        let mut client = ClientHandshake::new("cli/1.0");

        let nack = HelloNack::version_mismatch(PROTOCOL_VERSION);
        let result = client.process_response(nack.into());

        assert!(result.is_err());
        assert_eq!(client.state(), HandshakeState::Failed);
    }

    #[test]
    fn test_server_with_policy_hash() {
        let mut server = ServerHandshake::new("daemon/1.0").with_policy_hash("policy123");

        let hello = Hello::new("cli/1.0");
        let response = server.process_hello(&hello).unwrap();

        if let HandshakeMessage::HelloAck(ack) = response {
            assert_eq!(ack.policy_hash, Some("policy123".to_string()));
        } else {
            panic!("Expected HelloAck");
        }
    }

    #[test]
    fn test_hello_with_capabilities() {
        let hello = Hello::new("cli/1.0").with_capabilities(vec!["streaming".to_string()]);

        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("streaming"));

        let parsed: Hello = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.capabilities, vec!["streaming"]);
    }

    #[test]
    fn test_deny_unknown_fields() {
        // Hello should reject unknown fields (defense against injection)
        let json = r#"{"protocol_version": 1, "client_info": "test", "unknown": "field"}"#;
        let result: Result<Hello, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
