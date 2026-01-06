mod auth;
mod channel;
mod handler;
mod registry;
mod tls;
mod crypto;
mod admin;
mod ban_manager;
mod dm_manager;
mod file_transfer;
mod federation;

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
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::{
    admin::AdminManager,
    auth::AuthService,
    ban_manager::BanManager,
    channel::ChannelManager,
    crypto::EcdhManager,
    dm_manager::DMManager,
    file_transfer::FileTransferManager,
    federation::{PeerManager, MessageRelay, UserDirectory},
    registry::Registry,
};

/// Generate a unique server ID (using random UUID format)
fn generate_server_id() -> u64 {
    let mut bytes = [0u8; 8];
    let mut rng = rand::thread_rng();
    rng.fill(&mut bytes[..]);
    u64::from_be_bytes(bytes)
}

pub struct AppState {
    pub auth: RwLock<AuthService>,
    pub channels: RwLock<ChannelManager>,
    pub registry: RwLock<Registry>,
    pub ecdh: RwLock<EcdhManager>,
    pub admin: RwLock<AdminManager>,
    pub bans: RwLock<BanManager>,
    pub dm_manager: RwLock<DMManager>,
    pub file_transfer: RwLock<FileTransferManager>,
    pub federation_peers: RwLock<PeerManager>,
    pub federation_relay: RwLock<MessageRelay>,
    pub federation_user_dir: RwLock<UserDirectory>,

    pub special_key: String,
    pub server_id: u64,
    pub server_name: String,

    pub next_client_id: AtomicU64,
    pub next_server_msg_id: AtomicU64,
    pub next_federation_msg_id: AtomicU64,
}

impl AppState {
    pub fn new(special_key: String, server_id: u64, server_name: String) -> Self {
        Self {
            auth: RwLock::new(AuthService::new()),
            channels: RwLock::new(ChannelManager::new()),
            registry: RwLock::new(Registry::new()),
            ecdh: RwLock::new(EcdhManager::new()),
            admin: RwLock::new(AdminManager::new()),
            bans: RwLock::new(BanManager::new()),
            dm_manager: RwLock::new(DMManager::new()),
            file_transfer: RwLock::new(FileTransferManager::new()),
            federation_peers: RwLock::new(PeerManager::new(server_id, server_name.clone())),
            federation_relay: RwLock::new(MessageRelay::new()),
            federation_user_dir: RwLock::new(UserDirectory::new()),
            special_key,
            server_id,
            server_name,
            next_client_id: AtomicU64::new(1),
            next_server_msg_id: AtomicU64::new(1),
            next_federation_msg_id: AtomicU64::new(1),
        }
    }

    pub fn next_client_id(&self) -> u64 {
        self.next_client_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn next_server_msg_id(&self) -> u64 {
        self.next_server_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn next_federation_msg_id(&self) -> u64 {
        self.next_federation_msg_id.fetch_add(1, Ordering::Relaxed)
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

/// Load federation configuration from environment or use defaults
fn load_federation_config() -> (u64, String, Vec<String>) {
    // Server ID - can be set via environment or generated
    let server_id = env::var("FEDERATION_SERVER_ID")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(generate_server_id);

    // Server name - defaults to hostname or "relay-node-X"
    let server_name = env::var("FEDERATION_SERVER_NAME")
        .unwrap_or_else(|_| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| format!("relay-node-{}", server_id % 1000))
        });

    // Peer list - comma-separated addresses
    let peers: Vec<String> = env::var("FEDERATION_PEERS")
        .ok()
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_default();

    info!(server_id, server_name, peers = peers.len(), "federation config loaded");

    (server_id, server_name, peers)
}

#[tokio::main]
async fn main() {
    init_tracing();

    let special_key = env::var("DARKRELAY_SPECIAL_KEY").unwrap_or_else(|_| "darkrelay-dev-key".to_string());
    let (server_id, server_name, federation_peers) = load_federation_config();
    let state = Arc::new(AppState::new(special_key, server_id, server_name.clone()));

    // Add configured federation peers
    for (idx, peer_addr) in federation_peers.iter().enumerate() {
        // Assign sequential server IDs for configured peers
        let peer_server_id = server_id + (idx as u64 + 1);
        let peer_name = format!("peer-{}", idx + 1);
        state.federation_peers.write().await.add_peer(peer_server_id, peer_addr.clone(), peer_name).await;
    }

    {
        let mut channels = state.channels.write().await;
        channels.ensure_channel("general", true, None, None);
    }

    let ban_cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut bans = ban_cleanup_state.bans.write().await;
            bans.cleanup_expired();
        }
    });

    // Federation cache cleanup task
    let cache_cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            let mut user_dir = cache_cleanup_state.federation_user_dir.write().await;
            user_dir.cleanup_expired_cache().await;
        }
    });

    // Federation relay cleanup task
    let relay_cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600)); // 10 minutes
        loop {
            interval.tick().await;
            let mut relay = relay_cleanup_state.federation_relay.write().await;
            relay.cleanup_expired().await;
        }
    });

    // Federation peer reconnection task
    let reconnect_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let peers = reconnect_state.federation_peers.read().await.get_all_peers();
            for peer in peers {
                if !reconnect_state.federation_peers.read().await.is_connected(peer.server_id) {
                    info!(server_id = peer.server_id, "attempting to reconnect to peer");
                    if let Err(e) = reconnect_state.federation_peers.write().await.connect_to_peer(peer.server_id).await {
                        warn!(server_id = peer.server_id, error = %e, "reconnection failed");
                    }
                }
            }
        }
    });

    // Start federation listener (port 9000)
    let fed_state = Arc::clone(&state);
    let fed_listener = tokio::spawn(async move {
        let fed_tls_config = tls::load_or_generate_tls_config(None, None)
            .expect("load TLS config for federation");
        let fed_tls_acceptor = tokio_rustls::TlsAcceptor::from(fed_tls_config);

        let fed_addr = format!("0.0.0.0:{}", env::var("FEDERATION_PORT").unwrap_or_else(|_| "9000".to_string()));
        match tokio::net::TcpListener::bind(&fed_addr).await {
            Ok(listener) => {
                info!(addr = fed_addr, "federation listener started");
                loop {
                    if let Ok((socket, peer_addr)) = listener.accept().await {
                        let fed_state = Arc::clone(&fed_state);
                        tokio::spawn(async move {
                            if let Ok(tls_stream) = fed_tls_acceptor.accept(socket).await {
                                info!(%peer_addr, "incoming federation connection");
                                // TODO: Handle federation connection
                            }
                        });
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "failed to start federation listener");
            }
        }
    });

    let tls_config = tls::load_or_generate_tls_config(None, None).expect("load TLS config");
    let tls_acceptor = TlsAcceptor::from(tls_config);

    let listener = TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("bind to 0.0.0.0:8080");

    info!(addr = "0.0.0.0:8080", tls = true, "darkrelay server started");

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
                        let tls_acceptor = tls_acceptor.clone();
                        let mut shutdown_rx = shutdown_tx.subscribe();

                        tokio::spawn(async move {
                            let tls_stream = match tls_acceptor.accept(socket).await {
                                Ok(s) => s,
                                Err(e) => {
                                    error!(client_id, error = %e, "TLS handshake failed");
                                    return;
                                }
                            };

                            if let Err(e) = handler::handle_client(state, client_id, tls_stream, &mut shutdown_rx).await {
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

    // Graceful shutdown - disconnect all federation peers
    info!("shutting down federation connections");
    let peers = state.federation_peers.write().await.get_all_peers();
    for peer in peers {
        state.federation_peers.write().await.disconnect_peer(peer.server_id).await;
    }

    // Clear pending relays
    state.federation_relay.write().await.clear_all().await;

    // Wait for federation listener
    let _ = fed_listener.abort();

    info!("server exiting");
}
