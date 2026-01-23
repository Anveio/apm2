//! apm2-node - Holonic runtime node.

mod holon;
mod worker;

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use apm2_core::identity::{NodeIdentity, NodeRole};
use apm2_core::ledger::FileLedger;
use holon::{Holon, HolonConfig};
use tokio::sync::RwLock;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use url::Url;
use worker::WorkerAdapter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = NodeConfig::from_env()?;
    info!(
        bind_addr = %config.bind_addr,
        public_url = %config.public_url,
        parent_url = %config.parent_url.as_ref().map_or("none", Url::as_str),
        data_dir = %config.data_dir.display(),
        "starting apm2-node"
    );

    let role = if config.parent_url.is_some() {
        NodeRole::Worker
    } else {
        NodeRole::Kernel
    };

    let identity_path = config.data_dir.join("identity.json");
    let ledger_path = config.data_dir.join("events.jsonl");

    let identity = NodeIdentity::load_or_create_with_role(&identity_path, role)
        .context("failed to load or create identity")?;
    let ledger = FileLedger::open(&ledger_path).context("failed to open ledger")?;
    let ledger = Arc::new(RwLock::new(ledger));
    let holon_ledger = Arc::clone(&ledger);

    let holon = Holon::new(HolonConfig {
        identity,
        ledger,
        parent: config.parent_url.clone(),
        my_address: config.public_url.clone(),
    })?;

    let worker_handle = WorkerAdapter::from_env(Arc::clone(&holon_ledger))?.map(|worker| {
        tokio::spawn(async move {
            if let Err(err) = worker.run().await {
                error!(error = %err, "worker adapter failed");
            }
        })
    });

    let router = holon.router();
    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .context("failed to bind TCP listener")?;

    let (handshake_handle, heartbeat_handle) = if holon.has_parent() {
        (
            Some(tokio::spawn(holon.clone().handshake_loop())),
            Some(tokio::spawn(holon.clone().heartbeat_loop())),
        )
    } else {
        (None, None)
    };

    let server = axum::serve(listener, router);

    tokio::select! {
        result = server => {
            if let Err(err) = result {
                error!(error = %err, "server error");
            }
        }
        signal = tokio::signal::ctrl_c() => {
            if let Err(err) = signal {
                error!(error = %err, "failed to listen for shutdown signal");
            }
        }
    }

    if let Some(handle) = worker_handle {
        handle.abort();
    }
    if let Some(handle) = handshake_handle {
        handle.abort();
    }
    if let Some(handle) = heartbeat_handle {
        handle.abort();
    }

    Ok(())
}

struct NodeConfig {
    bind_addr: SocketAddr,
    public_url: Url,
    parent_url: Option<Url>,
    data_dir: PathBuf,
}

impl NodeConfig {
    fn from_env() -> Result<Self> {
        let bind_addr = env::var("NODE_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
        let bind_addr: SocketAddr = bind_addr.parse().context("failed to parse NODE_ADDR")?;

        let public_url = match env::var("NODE_URL") {
            Ok(url) if !url.trim().is_empty() => Url::parse(&url).context("invalid NODE_URL")?,
            _ => Url::parse(&format!("http://{bind_addr}"))
                .context("failed to build default node URL")?,
        };

        let parent_url = match env::var("PARENT_URL") {
            Ok(url) if !url.trim().is_empty() => {
                Some(Url::parse(&url).context("invalid PARENT_URL")?)
            },
            _ => None,
        };

        let data_dir = env::var("NODE_DATA_DIR").unwrap_or_else(|_| "node-data".to_string());
        let data_dir = PathBuf::from(data_dir);

        Ok(Self {
            bind_addr,
            public_url,
            parent_url,
            data_dir,
        })
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
