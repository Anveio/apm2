//! Holonic node networking and liveness loops.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use apm2_core::identity::NodeIdentity;
use apm2_core::ledger::{FileLedger, Ledger};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{error, info, warn};
use url::Url;

/// Holon runtime configuration.
#[derive(Debug, Clone)]
pub struct HolonConfig {
    /// Node identity.
    pub identity: NodeIdentity,
    /// Ledger for local events.
    pub ledger: Arc<RwLock<FileLedger>>,
    /// Parent URL, if any.
    pub parent: Option<Url>,
    /// Public address for this node.
    pub my_address: Url,
}

/// Holonic node with connection state.
#[derive(Clone)]
pub struct Holon {
    identity: NodeIdentity,
    ledger: Arc<RwLock<FileLedger>>,
    parent: Option<Url>,
    my_address: Url,
    client: reqwest::Client,
    connected: Arc<AtomicBool>,
}

impl Holon {
    /// Create a new holon from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be initialized.
    pub fn new(config: HolonConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            identity: config.identity,
            ledger: config.ledger,
            parent: config.parent,
            my_address: config.my_address,
            client,
            connected: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Build the axum router for inbound connections.
    pub fn router(&self) -> Router {
        let state = ServerState {
            ledger: Arc::clone(&self.ledger),
        };

        Router::new()
            .route("/connect", post(connect_handler))
            .route("/heartbeat", post(heartbeat_handler))
            .with_state(state)
    }

    /// Returns `true` if this holon has a parent configured.
    #[must_use]
    pub const fn has_parent(&self) -> bool {
        self.parent.is_some()
    }

    /// Start the handshake loop if a parent is configured.
    pub async fn handshake_loop(self) {
        let Some(parent) = self.parent.clone() else {
            return;
        };

        let connect_url = match parent.join("connect") {
            Ok(url) => url,
            Err(err) => {
                error!(error = %err, "invalid parent connect URL");
                return;
            },
        };

        info!(parent = %parent, "starting handshake loop");

        loop {
            if self.connected.load(Ordering::SeqCst) {
                break;
            }

            let payload = ConnectRequest {
                my_id: self.identity.id.to_string(),
                my_address: self.my_address.to_string(),
            };

            match self
                .client
                .post(connect_url.clone())
                .json(&payload)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    self.connected.store(true, Ordering::SeqCst);
                    info!(parent = %parent, "connected to parent");
                },
                Ok(response) => {
                    warn!(
                        status = %response.status(),
                        parent = %parent,
                        "handshake rejected"
                    );
                },
                Err(err) => {
                    warn!(error = %err, parent = %parent, "handshake failed");
                },
            }

            sleep(Duration::from_secs(5)).await;
        }
    }

    /// Start the heartbeat loop if a parent is configured.
    pub async fn heartbeat_loop(self) {
        let Some(parent) = self.parent.clone() else {
            return;
        };

        let heartbeat_url = match parent.join("heartbeat") {
            Ok(url) => url,
            Err(err) => {
                error!(error = %err, "invalid parent heartbeat URL");
                return;
            },
        };

        info!(parent = %parent, "starting heartbeat loop");

        loop {
            if !self.connected.load(Ordering::SeqCst) {
                sleep(Duration::from_millis(500)).await;
                continue;
            }

            let last_seq = {
                let ledger = self.ledger.read().await;
                ledger.last_seq()
            };

            let payload = HeartbeatRequest {
                my_id: self.identity.id.to_string(),
                last_seq,
            };

            let mut ok = false;
            match self
                .client
                .post(heartbeat_url.clone())
                .json(&payload)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    ok = true;
                },
                Ok(response) => {
                    warn!(
                        status = %response.status(),
                        parent = %parent,
                        "heartbeat rejected"
                    );
                    self.connected.store(false, Ordering::SeqCst);
                },
                Err(err) => {
                    warn!(error = %err, parent = %parent, "heartbeat failed");
                    self.connected.store(false, Ordering::SeqCst);
                },
            }

            let event = json!({
                "type": "HeartbeatSent",
                "my_id": payload.my_id,
                "parent": parent.as_str(),
                "last_seq": payload.last_seq,
                "ok": ok,
                "sent_at": now_epoch_secs(),
            });

            let result = self.ledger.write().await.append(event);
            if let Err(err) = result {
                error!(error = %err, "failed to append heartbeat event");
            }

            sleep(Duration::from_secs(3)).await;
        }
    }
}

#[derive(Clone)]
struct ServerState {
    ledger: Arc<RwLock<FileLedger>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ConnectRequest {
    my_id: String,
    my_address: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct HeartbeatRequest {
    my_id: String,
    last_seq: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Ack {
    status: &'static str,
}

async fn connect_handler(
    State(state): State<ServerState>,
    Json(payload): Json<ConnectRequest>,
) -> (StatusCode, Json<Ack>) {
    let event = json!({
        "type": "ChildConnected",
        "child_id": payload.my_id,
        "child_address": payload.my_address,
        "received_at": now_epoch_secs(),
    });

    let result = state.ledger.write().await.append(event);
    match result {
        Ok(_) => (StatusCode::OK, Json(Ack { status: "ok" })),
        Err(err) => {
            error!(error = %err, "failed to append child connection event");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Ack { status: "error" }),
            )
        },
    }
}

async fn heartbeat_handler(
    State(state): State<ServerState>,
    Json(payload): Json<HeartbeatRequest>,
) -> (StatusCode, Json<Ack>) {
    let event = json!({
        "type": "HeartbeatReceived",
        "child_id": payload.my_id,
        "last_seq": payload.last_seq,
        "received_at": now_epoch_secs(),
    });

    let result = state.ledger.write().await.append(event);
    match result {
        Ok(_) => (StatusCode::OK, Json(Ack { status: "ok" })),
        Err(err) => {
            error!(error = %err, "failed to append heartbeat event");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Ack { status: "error" }),
            )
        },
    }
}

fn now_epoch_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
