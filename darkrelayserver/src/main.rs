mod auth;
mod channel;
mod handler;
mod registry;

use std::{
    env,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::{
    net::TcpListener,
    sync::{broadcast, RwLock},
};
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::{auth::AuthService, channel::ChannelManager, registry::Registry};

pub struct AppState {
    pub auth: RwLock<AuthService>,
    pub channels: RwLock<ChannelManager>,
    pub registry: RwLock<Registry>,

    pub special_key: String,

    pub next_client_id: AtomicU64,
    pub next_server_msg_id: AtomicU64,
}

impl AppState {
    pub fn new(special_key: String) -> Self {
        Self {
            auth: RwLock::new(AuthService::new()),
            channels: RwLock::new(ChannelManager::new()),
            registry: RwLock::new(Registry::new()),
            special_key,
            next_client_id: AtomicU64::new(1),
            next_server_msg_id: AtomicU64::new(1),
        }
    }

    pub fn next_client_id(&self) -> u64 {
        self.next_client_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn next_server_msg_id(&self) -> u64 {
        self.next_server_msg_id.fetch_add(1, Ordering::Relaxed)
    }
}

fn init_tracing() {
    let log_dir = Path::new("darkrelayserver/logs");
    let _ = fs::create_dir_all(log_dir);

    let file_path = log_dir.join("server.log");

    let file_writer = move || {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .expect("open log file")
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,darkrelayserver=debug"));

    let layer = fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .json()
        .with_writer(file_writer);

    tracing_subscriber::registry().with(filter).with(layer).init();
}

#[tokio::main]
async fn main() {
    init_tracing();

    let special_key = env::var("DARKRELAY_SPECIAL_KEY").unwrap_or_else(|_| "darkrelay-dev-key".to_string());
    let state = Arc::new(AppState::new(special_key));

    {
        let mut channels = state.channels.write().await;
        channels.ensure_channel("general", true, None);
    }

    let listener = TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("bind to 0.0.0.0:8080");

    info!(addr = "0.0.0.0:8080", "darkrelay server started");

    let (shutdown_tx, _) = broadcast::channel::<()>(16);
    let mut shutdown_rx = shutdown_tx.subscribe();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                let _ = shutdown_tx.send(());
                break;
            }
            _ = shutdown_rx.recv() => {
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((socket, peer_addr)) => {
                        let client_id = state.next_client_id();
                        info!(client_id, %peer_addr, "client connected");

                        let state = Arc::clone(&state);
                        let mut shutdown_rx = shutdown_tx.subscribe();

                        tokio::spawn(async move {
                            if let Err(e) = handler::handle_client(state, client_id, socket, &mut shutdown_rx).await {
                                error!(client_id, error = %e, "client handler error");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept failed");
                    }
                }
            }
        }
    }

    info!("server exiting");
}
