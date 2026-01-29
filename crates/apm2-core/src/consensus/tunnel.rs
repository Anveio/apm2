//! Reverse-TLS tunnel management for NAT traversal.
//!
//! This module implements reverse-TLS tunnels that allow workers behind NAT
//! to maintain persistent outbound connections to a Relay. The Relay can then
//! route messages to the worker over these established tunnels.
//!
//! # Protocol
//!
//! 1. Worker initiates outbound TLS connection to Relay
//! 2. Worker sends `TUNNEL_REGISTER` with its identity
//! 3. Relay validates identity via mTLS certificate
//! 4. Relay sends `TUNNEL_ACCEPT` or `TUNNEL_REJECT`
//! 5. Tunnel becomes bidirectional message channel
//! 6. Periodic `TUNNEL_HEARTBEAT` maintains connection
//!
//! # Security Invariants
//!
//! - INV-0021: Tunnel registration requires valid mTLS identity
//! - INV-0022: Tunnel heartbeats prevent zombie connections
//! - INV-0023: Relay validates worker identity matches certificate CN

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio_rustls::TlsStream;

use super::network::{
    Connection, ControlFrame, NetworkError, TCP_CONNECT_TIMEOUT, TLS_HANDSHAKE_TIMEOUT, TlsConfig,
};

// =============================================================================
// Message Types for Tunnel Protocol
// =============================================================================

/// Message type for tunnel registration request.
pub const MSG_TUNNEL_REGISTER: u32 = 100;

/// Message type for tunnel accept response.
pub const MSG_TUNNEL_ACCEPT: u32 = 101;

/// Message type for tunnel reject response.
pub const MSG_TUNNEL_REJECT: u32 = 102;

/// Message type for tunnel heartbeat.
pub const MSG_TUNNEL_HEARTBEAT: u32 = 103;

/// Message type for tunnel heartbeat ack.
pub const MSG_TUNNEL_HEARTBEAT_ACK: u32 = 104;

/// Message type for tunnel close.
pub const MSG_TUNNEL_CLOSE: u32 = 105;

/// Message type for relayed data.
pub const MSG_TUNNEL_DATA: u32 = 106;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of registered tunnels per relay (CTR-1303: Bounded Stores).
pub const MAX_TUNNELS: usize = 256;

/// Heartbeat interval for tunnel keepalive.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Heartbeat timeout before marking tunnel as dead.
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

/// Tunnel registration timeout.
pub const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum tunnel ID length.
pub const MAX_TUNNEL_ID_LEN: usize = 128;

/// Maximum worker ID length.
pub const MAX_WORKER_ID_LEN: usize = 128;

/// Maximum reason length for rejection.
pub const MAX_REASON_LEN: usize = 256;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur in tunnel operations.
#[derive(Debug, Error)]
pub enum TunnelError {
    /// Network error.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Registration rejected.
    #[error("registration rejected: {reason}")]
    RegistrationRejected {
        /// Reason for rejection.
        reason: String,
    },

    /// Registration timeout.
    #[error("registration timed out")]
    RegistrationTimeout,

    /// Heartbeat timeout.
    #[error("heartbeat timeout for tunnel {tunnel_id}")]
    HeartbeatTimeout {
        /// The tunnel that timed out.
        tunnel_id: String,
    },

    /// Invalid tunnel state.
    #[error("invalid tunnel state: expected {expected}, found {actual}")]
    InvalidState {
        /// Expected state.
        expected: String,
        /// Actual state.
        actual: String,
    },

    /// Tunnel not found.
    #[error("tunnel not found: {tunnel_id}")]
    TunnelNotFound {
        /// The missing tunnel ID.
        tunnel_id: String,
    },

    /// Maximum tunnels reached.
    #[error("maximum tunnels reached: {max}")]
    MaxTunnelsReached {
        /// Maximum allowed tunnels.
        max: usize,
    },

    /// Identity mismatch.
    #[error("identity mismatch: certificate CN {cert_cn} does not match worker ID {worker_id}")]
    IdentityMismatch {
        /// CN from certificate.
        cert_cn: String,
        /// Worker ID from registration.
        worker_id: String,
    },

    /// Invalid message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Channel error.
    #[error("channel error: {0}")]
    Channel(String),
}

// =============================================================================
// Tunnel State
// =============================================================================

/// State of a tunnel connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunnelState {
    /// Tunnel is being established.
    #[default]
    Connecting,
    /// Tunnel registration sent, waiting for response.
    Registering,
    /// Tunnel is active and can carry data.
    Active,
    /// Tunnel is closing.
    Closing,
    /// Tunnel is closed.
    Closed,
}

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connecting => write!(f, "connecting"),
            Self::Registering => write!(f, "registering"),
            Self::Active => write!(f, "active"),
            Self::Closing => write!(f, "closing"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

// =============================================================================
// Protocol Messages
// =============================================================================

/// Tunnel registration request sent by worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelRegisterRequest {
    /// Unique tunnel identifier (generated by worker).
    pub tunnel_id: String,
    /// Worker's identity (must match certificate CN).
    pub worker_id: String,
    /// Timestamp of registration (Unix epoch seconds).
    pub timestamp: u64,
}

impl TunnelRegisterRequest {
    /// Creates a new registration request.
    #[must_use]
    pub const fn new(tunnel_id: String, worker_id: String, timestamp: u64) -> Self {
        Self {
            tunnel_id,
            worker_id,
            timestamp,
        }
    }

    /// Validates the registration request.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate(&self) -> Result<(), TunnelError> {
        if self.tunnel_id.is_empty() {
            return Err(TunnelError::InvalidMessage("empty tunnel_id".into()));
        }
        if self.tunnel_id.len() > MAX_TUNNEL_ID_LEN {
            return Err(TunnelError::InvalidMessage(format!(
                "tunnel_id too long: {} > {MAX_TUNNEL_ID_LEN}",
                self.tunnel_id.len()
            )));
        }
        if self.worker_id.is_empty() {
            return Err(TunnelError::InvalidMessage("empty worker_id".into()));
        }
        if self.worker_id.len() > MAX_WORKER_ID_LEN {
            return Err(TunnelError::InvalidMessage(format!(
                "worker_id too long: {} > {MAX_WORKER_ID_LEN}",
                self.worker_id.len()
            )));
        }
        Ok(())
    }

    /// Serializes to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TunnelError> {
        serde_json::to_vec(self).map_err(|e| TunnelError::Serialization(e.to_string()))
    }

    /// Deserializes from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TunnelError> {
        serde_json::from_slice(bytes).map_err(|e| TunnelError::Serialization(e.to_string()))
    }
}

/// Tunnel accept response sent by relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelAcceptResponse {
    /// The tunnel ID being accepted.
    pub tunnel_id: String,
    /// Relay's identity.
    pub relay_id: String,
    /// Recommended heartbeat interval in seconds.
    pub heartbeat_interval_secs: u64,
}

impl TunnelAcceptResponse {
    /// Creates a new accept response.
    #[must_use]
    pub const fn new(tunnel_id: String, relay_id: String, heartbeat_interval_secs: u64) -> Self {
        Self {
            tunnel_id,
            relay_id,
            heartbeat_interval_secs,
        }
    }

    /// Serializes to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TunnelError> {
        serde_json::to_vec(self).map_err(|e| TunnelError::Serialization(e.to_string()))
    }

    /// Deserializes from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TunnelError> {
        serde_json::from_slice(bytes).map_err(|e| TunnelError::Serialization(e.to_string()))
    }
}

/// Tunnel reject response sent by relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelRejectResponse {
    /// The tunnel ID being rejected.
    pub tunnel_id: String,
    /// Reason for rejection.
    pub reason: String,
}

impl TunnelRejectResponse {
    /// Creates a new reject response.
    #[must_use]
    pub fn new(tunnel_id: String, reason: String) -> Self {
        let reason = if reason.len() > MAX_REASON_LEN {
            reason[..MAX_REASON_LEN].to_string()
        } else {
            reason
        };
        Self { tunnel_id, reason }
    }

    /// Serializes to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TunnelError> {
        serde_json::to_vec(self).map_err(|e| TunnelError::Serialization(e.to_string()))
    }

    /// Deserializes from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TunnelError> {
        serde_json::from_slice(bytes).map_err(|e| TunnelError::Serialization(e.to_string()))
    }
}

/// Tunnel heartbeat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelHeartbeat {
    /// The tunnel ID.
    pub tunnel_id: String,
    /// Sequence number for ordering.
    pub sequence: u64,
    /// Timestamp (Unix epoch seconds).
    pub timestamp: u64,
}

impl TunnelHeartbeat {
    /// Creates a new heartbeat.
    #[must_use]
    pub const fn new(tunnel_id: String, sequence: u64, timestamp: u64) -> Self {
        Self {
            tunnel_id,
            sequence,
            timestamp,
        }
    }

    /// Serializes to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TunnelError> {
        serde_json::to_vec(self).map_err(|e| TunnelError::Serialization(e.to_string()))
    }

    /// Deserializes from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TunnelError> {
        serde_json::from_slice(bytes).map_err(|e| TunnelError::Serialization(e.to_string()))
    }
}

/// Tunnel data message for relaying application data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelData {
    /// The tunnel ID.
    pub tunnel_id: String,
    /// The actual data payload (base64 encoded for JSON safety).
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
}

impl TunnelData {
    /// Creates a new data message.
    #[must_use]
    pub const fn new(tunnel_id: String, payload: Vec<u8>) -> Self {
        Self { tunnel_id, payload }
    }

    /// Serializes to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TunnelError> {
        serde_json::to_vec(self).map_err(|e| TunnelError::Serialization(e.to_string()))
    }

    /// Deserializes from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TunnelError> {
        serde_json::from_slice(bytes).map_err(|e| TunnelError::Serialization(e.to_string()))
    }
}

/// Base64 serialization for binary data in JSON.
mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// =============================================================================
// Tunnel Handle
// =============================================================================

/// Information about an established tunnel.
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    /// Unique tunnel identifier.
    pub tunnel_id: String,
    /// Worker identity.
    pub worker_id: String,
    /// Remote peer address.
    pub peer_addr: SocketAddr,
    /// Current state.
    pub state: TunnelState,
    /// When the tunnel was established.
    pub established_at: Instant,
    /// Last heartbeat received.
    pub last_heartbeat: Instant,
    /// Heartbeat sequence number.
    pub heartbeat_sequence: u64,
}

impl TunnelInfo {
    /// Creates new tunnel info.
    #[must_use]
    pub fn new(tunnel_id: String, worker_id: String, peer_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            tunnel_id,
            worker_id,
            peer_addr,
            state: TunnelState::Active,
            established_at: now,
            last_heartbeat: now,
            heartbeat_sequence: 0,
        }
    }

    /// Checks if the tunnel is stale (no recent heartbeat).
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.last_heartbeat.elapsed() > HEARTBEAT_TIMEOUT
    }

    /// Updates the last heartbeat time.
    pub fn touch(&mut self) {
        self.last_heartbeat = Instant::now();
    }
}

// =============================================================================
// Managed Tunnel (Worker Side)
// =============================================================================

/// A managed tunnel from the worker's perspective.
///
/// This struct manages the worker-side of a reverse-TLS tunnel, handling:
/// - Connection establishment
/// - Registration with relay
/// - Heartbeat maintenance
/// - Message sending/receiving
pub struct ManagedTunnel {
    /// Tunnel identifier.
    tunnel_id: String,
    /// Worker identifier.
    worker_id: String,
    /// Current state.
    state: RwLock<TunnelState>,
    /// Underlying connection (when established).
    connection: RwLock<Option<Connection>>,
    /// Heartbeat sequence number.
    heartbeat_seq: RwLock<u64>,
    /// Last heartbeat time.
    last_heartbeat: RwLock<Instant>,
    /// TLS configuration.
    tls_config: TlsConfig,
}

impl ManagedTunnel {
    /// Creates a new managed tunnel.
    #[must_use]
    pub fn new(tunnel_id: String, worker_id: String, tls_config: TlsConfig) -> Self {
        Self {
            tunnel_id,
            worker_id,
            state: RwLock::new(TunnelState::Connecting),
            connection: RwLock::new(None),
            heartbeat_seq: RwLock::new(0),
            last_heartbeat: RwLock::new(Instant::now()),
            tls_config,
        }
    }

    /// Returns the tunnel ID.
    #[must_use]
    pub fn tunnel_id(&self) -> &str {
        &self.tunnel_id
    }

    /// Returns the worker ID.
    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Returns the current state.
    pub async fn state(&self) -> TunnelState {
        *self.state.read().await
    }

    /// Establishes the tunnel to the relay.
    ///
    /// # Errors
    ///
    /// Returns an error if connection or registration fails.
    #[allow(clippy::too_many_lines)]
    pub async fn connect(
        &self,
        relay_addr: SocketAddr,
        relay_server_name: &str,
    ) -> Result<(), TunnelError> {
        // Update state to connecting
        {
            let mut state = self.state.write().await;
            *state = TunnelState::Connecting;
        }

        // Establish TCP connection with timeout
        let tcp_stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(relay_addr))
            .await
            .map_err(|_| NetworkError::Timeout {
                operation: "TCP connect to relay".into(),
            })??;

        // Perform TLS handshake
        let server_name = rustls::pki_types::ServerName::try_from(relay_server_name.to_owned())
            .map_err(|e| NetworkError::Handshake(format!("invalid relay server name: {e}")))?;

        let connector = self.tls_config.connector();
        let tls_stream = timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| NetworkError::Timeout {
            operation: "TLS handshake with relay".into(),
        })?
        .map_err(|e| NetworkError::Handshake(format!("TLS handshake failed: {e}")))?;

        let peer_addr = relay_addr;
        let conn = Connection::new(TlsStream::Client(tls_stream), peer_addr);

        // Store connection
        {
            let mut connection = self.connection.write().await;
            *connection = Some(conn);
        }

        // Update state to registering
        {
            let mut state = self.state.write().await;
            *state = TunnelState::Registering;
        }

        // Send registration request
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let register =
            TunnelRegisterRequest::new(self.tunnel_id.clone(), self.worker_id.clone(), timestamp);
        register.validate()?;

        let payload = register.to_bytes()?;
        let frame = ControlFrame::new(MSG_TUNNEL_REGISTER, &payload)?;

        // Send registration
        {
            let mut conn_guard = self.connection.write().await;
            if let Some(conn) = conn_guard.as_mut() {
                conn.send_frame_with_timeout(&frame, REGISTRATION_TIMEOUT)
                    .await?;
            } else {
                return Err(TunnelError::InvalidState {
                    expected: "connected".into(),
                    actual: "disconnected".into(),
                });
            }
        }

        // Wait for response
        let response = {
            let mut conn_guard = self.connection.write().await;
            if let Some(conn) = conn_guard.as_mut() {
                conn.recv_frame_with_timeout(REGISTRATION_TIMEOUT).await?
            } else {
                return Err(TunnelError::InvalidState {
                    expected: "connected".into(),
                    actual: "disconnected".into(),
                });
            }
        };

        match response.message_type() {
            MSG_TUNNEL_ACCEPT => {
                let accept = TunnelAcceptResponse::from_bytes(response.payload())?;
                if accept.tunnel_id != self.tunnel_id {
                    return Err(TunnelError::InvalidMessage(format!(
                        "tunnel_id mismatch: expected {}, got {}",
                        self.tunnel_id, accept.tunnel_id
                    )));
                }

                // Update state to active
                {
                    let mut state = self.state.write().await;
                    *state = TunnelState::Active;
                }

                // Initialize heartbeat
                {
                    let mut last_hb = self.last_heartbeat.write().await;
                    *last_hb = Instant::now();
                }

                tracing::info!(
                    tunnel_id = %self.tunnel_id,
                    relay_id = %accept.relay_id,
                    "Tunnel registered with relay"
                );

                Ok(())
            },
            MSG_TUNNEL_REJECT => {
                let reject = TunnelRejectResponse::from_bytes(response.payload())?;

                // Update state to closed
                {
                    let mut state = self.state.write().await;
                    *state = TunnelState::Closed;
                }

                Err(TunnelError::RegistrationRejected {
                    reason: reject.reason,
                })
            },
            msg_type => Err(TunnelError::InvalidMessage(format!(
                "unexpected response type during registration: {msg_type}"
            ))),
        }
    }

    /// Sends a heartbeat to the relay.
    ///
    /// # Errors
    ///
    /// Returns an error if the heartbeat cannot be sent.
    pub async fn send_heartbeat(&self) -> Result<(), TunnelError> {
        let state = self.state.read().await;
        if *state != TunnelState::Active {
            return Err(TunnelError::InvalidState {
                expected: "active".into(),
                actual: state.to_string(),
            });
        }
        drop(state);

        // Increment sequence
        let sequence = {
            let mut seq = self.heartbeat_seq.write().await;
            *seq += 1;
            *seq
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let heartbeat = TunnelHeartbeat::new(self.tunnel_id.clone(), sequence, timestamp);
        let payload = heartbeat.to_bytes()?;
        let frame = ControlFrame::new(MSG_TUNNEL_HEARTBEAT, &payload)?;

        let mut conn_guard = self.connection.write().await;
        if let Some(conn) = conn_guard.as_mut() {
            conn.send_frame(&frame).await?;
        } else {
            return Err(TunnelError::InvalidState {
                expected: "connected".into(),
                actual: "disconnected".into(),
            });
        }

        Ok(())
    }

    /// Sends data through the tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be sent.
    pub async fn send_data(&self, data: Vec<u8>) -> Result<(), TunnelError> {
        let state = self.state.read().await;
        if *state != TunnelState::Active {
            return Err(TunnelError::InvalidState {
                expected: "active".into(),
                actual: state.to_string(),
            });
        }
        drop(state);

        let tunnel_data = TunnelData::new(self.tunnel_id.clone(), data);
        let payload = tunnel_data.to_bytes()?;
        let frame = ControlFrame::new(MSG_TUNNEL_DATA, &payload)?;

        let mut conn_guard = self.connection.write().await;
        if let Some(conn) = conn_guard.as_mut() {
            conn.send_frame(&frame).await?;
        } else {
            return Err(TunnelError::InvalidState {
                expected: "connected".into(),
                actual: "disconnected".into(),
            });
        }

        Ok(())
    }

    /// Receives a frame from the tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub async fn recv_frame(&self) -> Result<ControlFrame, TunnelError> {
        let mut conn_guard = self.connection.write().await;
        if let Some(conn) = conn_guard.as_mut() {
            let frame = conn.recv_frame().await?;

            // Update heartbeat time on any message received
            {
                let mut last_hb = self.last_heartbeat.write().await;
                *last_hb = Instant::now();
            }

            Ok(frame)
        } else {
            Err(TunnelError::InvalidState {
                expected: "connected".into(),
                actual: "disconnected".into(),
            })
        }
    }

    /// Closes the tunnel gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if the close message cannot be sent.
    pub async fn close(&self) -> Result<(), TunnelError> {
        {
            let mut state = self.state.write().await;
            if *state == TunnelState::Closed {
                return Ok(());
            }
            *state = TunnelState::Closing;
        }

        // Send close message
        let frame = ControlFrame::new(MSG_TUNNEL_CLOSE, self.tunnel_id.as_bytes())?;

        let result = {
            let mut conn_guard = self.connection.write().await;
            if let Some(conn) = conn_guard.as_mut() {
                conn.send_frame(&frame).await
            } else {
                Ok(())
            }
        };

        // Update state regardless of send result
        {
            let mut state = self.state.write().await;
            *state = TunnelState::Closed;
        }

        // Clear connection
        {
            let mut conn_guard = self.connection.write().await;
            *conn_guard = None;
        }

        result.map_err(Into::into)
    }

    /// Checks if the tunnel is healthy (active with recent heartbeat).
    pub async fn is_healthy(&self) -> bool {
        let state = self.state.read().await;
        if *state != TunnelState::Active {
            return false;
        }
        drop(state);

        let last_hb = self.last_heartbeat.read().await;
        last_hb.elapsed() < HEARTBEAT_TIMEOUT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_register_request_validate() {
        let valid = TunnelRegisterRequest::new(
            "tunnel-123".to_string(),
            "worker-456".to_string(),
            1_234_567_890,
        );
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_tunnel_register_request_empty_tunnel_id() {
        let invalid =
            TunnelRegisterRequest::new(String::new(), "worker-456".to_string(), 1_234_567_890);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_tunnel_register_request_empty_worker_id() {
        let invalid =
            TunnelRegisterRequest::new("tunnel-123".to_string(), String::new(), 1_234_567_890);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_tunnel_register_request_too_long_tunnel_id() {
        let invalid = TunnelRegisterRequest::new(
            "x".repeat(MAX_TUNNEL_ID_LEN + 1),
            "worker-456".to_string(),
            1_234_567_890,
        );
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_tunnel_register_request_roundtrip() {
        let original = TunnelRegisterRequest::new(
            "tunnel-123".to_string(),
            "worker-456".to_string(),
            1_234_567_890,
        );
        let bytes = original.to_bytes().unwrap();
        let parsed = TunnelRegisterRequest::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.tunnel_id, original.tunnel_id);
        assert_eq!(parsed.worker_id, original.worker_id);
        assert_eq!(parsed.timestamp, original.timestamp);
    }

    #[test]
    fn test_tunnel_accept_response_roundtrip() {
        let original =
            TunnelAcceptResponse::new("tunnel-123".to_string(), "relay-789".to_string(), 30);
        let bytes = original.to_bytes().unwrap();
        let parsed = TunnelAcceptResponse::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.tunnel_id, original.tunnel_id);
        assert_eq!(parsed.relay_id, original.relay_id);
        assert_eq!(
            parsed.heartbeat_interval_secs,
            original.heartbeat_interval_secs
        );
    }

    #[test]
    fn test_tunnel_reject_response_roundtrip() {
        let original =
            TunnelRejectResponse::new("tunnel-123".to_string(), "identity mismatch".to_string());
        let bytes = original.to_bytes().unwrap();
        let parsed = TunnelRejectResponse::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.tunnel_id, original.tunnel_id);
        assert_eq!(parsed.reason, original.reason);
    }

    #[test]
    fn test_tunnel_reject_response_truncates_reason() {
        let long_reason = "x".repeat(MAX_REASON_LEN + 100);
        let response = TunnelRejectResponse::new("tunnel-123".to_string(), long_reason);
        assert_eq!(response.reason.len(), MAX_REASON_LEN);
    }

    #[test]
    fn test_tunnel_heartbeat_roundtrip() {
        let original = TunnelHeartbeat::new("tunnel-123".to_string(), 42, 1_234_567_890);
        let bytes = original.to_bytes().unwrap();
        let parsed = TunnelHeartbeat::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.tunnel_id, original.tunnel_id);
        assert_eq!(parsed.sequence, original.sequence);
        assert_eq!(parsed.timestamp, original.timestamp);
    }

    #[test]
    fn test_tunnel_data_roundtrip() {
        let original = TunnelData::new("tunnel-123".to_string(), vec![1, 2, 3, 4, 5]);
        let bytes = original.to_bytes().unwrap();
        let parsed = TunnelData::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.tunnel_id, original.tunnel_id);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_tunnel_info_is_stale() {
        let info = TunnelInfo::new(
            "tunnel-123".to_string(),
            "worker-456".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
        );

        // Fresh tunnel should not be stale
        assert!(!info.is_stale());
    }

    #[test]
    fn test_tunnel_state_display() {
        assert_eq!(TunnelState::Connecting.to_string(), "connecting");
        assert_eq!(TunnelState::Registering.to_string(), "registering");
        assert_eq!(TunnelState::Active.to_string(), "active");
        assert_eq!(TunnelState::Closing.to_string(), "closing");
        assert_eq!(TunnelState::Closed.to_string(), "closed");
    }
}

#[cfg(test)]
mod tck_00184_tunnel_tests {
    use super::*;

    #[test]
    fn test_tck_00184_message_types_unique() {
        // All message types must be unique
        let msg_types = [
            MSG_TUNNEL_REGISTER,
            MSG_TUNNEL_ACCEPT,
            MSG_TUNNEL_REJECT,
            MSG_TUNNEL_HEARTBEAT,
            MSG_TUNNEL_HEARTBEAT_ACK,
            MSG_TUNNEL_CLOSE,
            MSG_TUNNEL_DATA,
        ];

        let mut seen = std::collections::HashSet::new();
        for msg_type in msg_types {
            assert!(seen.insert(msg_type), "Duplicate message type: {msg_type}");
        }
    }

    #[test]
    fn test_tck_00184_constants_reasonable() {
        // INV-0022: Heartbeat interval must be less than timeout
        assert!(
            HEARTBEAT_INTERVAL < HEARTBEAT_TIMEOUT,
            "Heartbeat interval must be less than timeout"
        );

        // Registration timeout should be reasonable
        assert!(
            REGISTRATION_TIMEOUT.as_secs() >= 5,
            "Registration timeout too short"
        );
        assert!(
            REGISTRATION_TIMEOUT.as_secs() <= 60,
            "Registration timeout too long"
        );
    }

    // Bounded stores - compile-time assertions
    const _: () = {
        assert!(MAX_TUNNELS > 0, "MAX_TUNNELS must be positive");
        assert!(MAX_TUNNELS <= 1024, "MAX_TUNNELS should be bounded");
    };

    #[test]
    #[allow(clippy::similar_names)]
    fn test_tck_00184_tunnel_register_validation() {
        // Valid request
        let valid =
            TunnelRegisterRequest::new("t-123".to_string(), "w-456".to_string(), 1_234_567_890);
        assert!(valid.validate().is_ok(), "Valid request should pass");

        // Empty tunnel_id
        let empty_tunnel_id =
            TunnelRegisterRequest::new(String::new(), "w-456".to_string(), 1_234_567_890);
        assert!(
            empty_tunnel_id.validate().is_err(),
            "Empty tunnel_id should fail"
        );

        // Empty worker_id
        let empty_worker_id =
            TunnelRegisterRequest::new("t-123".to_string(), String::new(), 1_234_567_890);
        assert!(
            empty_worker_id.validate().is_err(),
            "Empty worker_id should fail"
        );

        // Too long tunnel_id
        let long_tunnel_id = TunnelRegisterRequest::new(
            "x".repeat(MAX_TUNNEL_ID_LEN + 1),
            "w-456".to_string(),
            1_234_567_890,
        );
        assert!(
            long_tunnel_id.validate().is_err(),
            "Too long tunnel_id should fail"
        );

        // Too long worker_id
        let long_worker_id = TunnelRegisterRequest::new(
            "t-123".to_string(),
            "x".repeat(MAX_WORKER_ID_LEN + 1),
            1_234_567_890,
        );
        assert!(
            long_worker_id.validate().is_err(),
            "Too long worker_id should fail"
        );
    }

    #[test]
    fn test_tck_00184_tunnel_data_binary_payload() {
        // Test with binary data including non-UTF8 bytes
        let binary_data: Vec<u8> = (0..=255).collect();
        let original = TunnelData::new("tunnel-123".to_string(), binary_data.clone());

        let bytes = original.to_bytes().unwrap();
        let parsed = TunnelData::from_bytes(&bytes).unwrap();

        assert_eq!(
            parsed.payload, binary_data,
            "Binary payload must survive roundtrip"
        );
    }

    #[test]
    fn test_tck_00184_tunnel_info_lifecycle() {
        let mut info = TunnelInfo::new(
            "tunnel-123".to_string(),
            "worker-456".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
        );

        assert_eq!(info.state, TunnelState::Active);
        assert!(!info.is_stale());

        // Touch should update heartbeat
        let old_seq = info.heartbeat_sequence;
        info.touch();
        assert!(!info.is_stale());
        // touch() doesn't increment sequence, that's done separately
        assert_eq!(info.heartbeat_sequence, old_seq);
    }

    #[test]
    fn test_tck_00184_serde_strict_mode() {
        // CTR-1604: All wire format structs use deny_unknown_fields

        // Test TunnelRegisterRequest rejects unknown fields
        let json_with_extra =
            r#"{"tunnel_id":"t1","worker_id":"w1","timestamp":123,"extra":"bad"}"#;
        let result: Result<TunnelRegisterRequest, _> = serde_json::from_str(json_with_extra);
        assert!(result.is_err(), "Should reject unknown fields");

        // Test TunnelAcceptResponse rejects unknown fields
        let json_with_extra =
            r#"{"tunnel_id":"t1","relay_id":"r1","heartbeat_interval_secs":30,"extra":"bad"}"#;
        let result: Result<TunnelAcceptResponse, _> = serde_json::from_str(json_with_extra);
        assert!(result.is_err(), "Should reject unknown fields");

        // Test TunnelRejectResponse rejects unknown fields
        let json_with_extra = r#"{"tunnel_id":"t1","reason":"denied","extra":"bad"}"#;
        let result: Result<TunnelRejectResponse, _> = serde_json::from_str(json_with_extra);
        assert!(result.is_err(), "Should reject unknown fields");

        // Test TunnelHeartbeat rejects unknown fields
        let json_with_extra = r#"{"tunnel_id":"t1","sequence":1,"timestamp":123,"extra":"bad"}"#;
        let result: Result<TunnelHeartbeat, _> = serde_json::from_str(json_with_extra);
        assert!(result.is_err(), "Should reject unknown fields");

        // Test TunnelData rejects unknown fields
        let json_with_extra = r#"{"tunnel_id":"t1","payload":"AQID","extra":"bad"}"#;
        let result: Result<TunnelData, _> = serde_json::from_str(json_with_extra);
        assert!(result.is_err(), "Should reject unknown fields");
    }

    #[test]
    fn test_tck_00184_error_messages() {
        // Verify error variants exist and format correctly
        let errors = [
            TunnelError::RegistrationRejected {
                reason: "identity mismatch".into(),
            },
            TunnelError::RegistrationTimeout,
            TunnelError::HeartbeatTimeout {
                tunnel_id: "t-123".into(),
            },
            TunnelError::TunnelNotFound {
                tunnel_id: "t-123".into(),
            },
            TunnelError::MaxTunnelsReached { max: MAX_TUNNELS },
            TunnelError::IdentityMismatch {
                cert_cn: "cert-cn".into(),
                worker_id: "worker-id".into(),
            },
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "Error message should not be empty");
        }
    }
}
