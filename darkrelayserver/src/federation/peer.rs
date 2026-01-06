use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpSocket};
use tokio::sync::Mutex;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, info, warn, error};
use std::sync::atomic::{AtomicU64, Ordering};
use bincode;

use darkrelayprotocol::federation::{
    ServerFederationMessage, ServerId, FederationPeer, FederationStatus,
    ServerIntro, ServerAck, FEDERATION_RECONNECT_INTERVAL_SECS, FEDERATION_PROTOCOL_VERSION,
};
use crate::federation::user_lookup::UserDirectory;
use crate::federation::handshake;

pub struct FederatedServerConnection {
    pub server_id: u64,
    pub server_name: String,
    // Store stream wrapped in Arc<Mutex<>> for shared access
    pub stream: Arc<Mutex<TlsStream<TcpStream>>>,
    // Store shared secret as [u8; 32] - it's Copy, not Clone-dependent
    pub shared_secret: [u8; 32],
    // Use AtomicU64 for nonce (lock-free)
    pub outgoing_nonce: Arc<AtomicU64>,
}

impl FederatedServerConnection {
    pub async fn send_message(&self, msg: &ServerFederationMessage) -> io::Result<()> {
        let bytes = bincode::serialize(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut stream = self.stream.lock().await;
        
        // Write length prefix + message (using little-endian as per ticket proposal)
        let len = bytes.len() as u32;
        stream.write_all(&len.to_le_bytes()).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    }
    
    pub async fn recv_message(&self) -> io::Result<ServerFederationMessage> {
        let mut stream = self.stream.lock().await;
        
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        
        // Read message
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        
        let msg = bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(msg)
    }

    pub fn next_nonce(&self) -> u64 {
        self.outgoing_nonce.fetch_add(1, Ordering::SeqCst) + 1
    }
}

pub struct PeerManager {
    /// Connected peer connections
    connections: Arc<Mutex<HashMap<ServerId, Arc<FederatedServerConnection>>>>,
    /// Federation shared secrets per peer
    secrets: Arc<Mutex<HashMap<ServerId, [u8; 32]>>>,
    /// Peer metadata
    peers: Arc<Mutex<HashMap<ServerId, FederationPeer>>>,
    /// User directory for lookups
    user_directory: Arc<UserDirectory>,
    /// Our server ID
    our_server_id: ServerId,
    /// Our server name
    our_server_name: String,
}

impl PeerManager {
    pub fn new(our_server_id: ServerId, our_server_name: String) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            secrets: Arc::new(Mutex::new(HashMap::new())),
            peers: Arc::new(Mutex::new(HashMap::new())),
            user_directory: Arc::new(UserDirectory::new()),
            our_server_id,
            our_server_name,
        }
    }

    /// Add a peer to connect to
    pub async fn add_peer(&self, server_id: ServerId, address: String, server_name: String) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let peer = FederationPeer {
            server_id,
            server_name,
            address,
            status: FederationStatus::Disconnected,
            last_seen: now,
            connected_at: None,
        };

        let mut peers = self.peers.lock().await;
        peers.insert(server_id, peer);
        debug!(server_id, "peer added");
    }

    /// Connect to a peer and perform handshake
    pub async fn connect_to_peer(&self, server_id: ServerId) -> io::Result<Arc<FederatedServerConnection>> {
        let peer = {
            let peers = self.peers.lock().await;
            peers.get(&server_id).cloned()
        };

        let Some(peer) = peer else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "peer not found"));
        };

        debug!(server_id, address = %peer.address, "connecting to peer");

        // Create TLS connector
        let tls_config = crate::tls::load_or_generate_tls_config(None, None)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let connector = TlsConnector::from(tls_config);

        // Connect to peer
        let socket = TcpSocket::new_v4()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        socket.set_nodelay(true).ok();
        
        let addr = peer.address.parse::<SocketAddr>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        
        let stream = socket.connect(addr)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        // Perform TLS handshake
        let domain = rustls::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(domain, stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS error: {e}")))?;

        // ECDH Handshake (using handshake module)
        let shared_secret = handshake::perform_client_handshake(
            &mut tls_stream,
            self.our_server_id,
            self.our_server_name.clone()
        ).await?;

        let conn = Arc::new(FederatedServerConnection {
            server_id,
            server_name: peer.server_name.clone(),
            stream: Arc::new(Mutex::new(tls_stream)),
            shared_secret,
            outgoing_nonce: Arc::new(AtomicU64::new(0)),
        });

        // Store connection
        {
            let mut conns = self.connections.lock().await;
            conns.insert(server_id, conn.clone());
        }

        // Store secret
        {
            let mut secrets = self.secrets.lock().await;
            secrets.insert(server_id, shared_secret);
        }

        // Update peer status
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut peers = self.peers.lock().await;
        if let Some(p) = peers.get_mut(&server_id) {
            p.status = FederationStatus::Connected;
            p.last_seen = now;
            p.connected_at = Some(now);
        }

        info!(server_id, "connected to peer successfully");
        Ok(conn)
    }

    /// Handle incoming connection from peer
    pub async fn handle_incoming_connection(&self, mut stream: TlsStream<TcpStream>, their_intro: ServerIntro) -> io::Result<()> {
        let server_id = their_intro.server_id;

        // Perform ECDH Handshake (using handshake module)
        let shared_secret = handshake::perform_server_handshake(
            &mut stream,
            self.our_server_id,
            self.our_server_name.clone(),
            their_intro.clone()
        ).await?;

        let conn = Arc::new(FederatedServerConnection {
            server_id,
            server_name: their_intro.server_name.clone(),
            stream: Arc::new(Mutex::new(stream)),
            shared_secret,
            outgoing_nonce: Arc::new(AtomicU64::new(0)),
        });

        // Store connection
        {
            let mut conns = self.connections.lock().await;
            conns.insert(server_id, conn);
        }

        // Store secret
        {
            let mut secrets = self.secrets.lock().await;
            secrets.insert(server_id, shared_secret);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add peer if new or update status
        let mut peers = self.peers.lock().await;
        if !peers.contains_key(&server_id) {
            peers.insert(server_id, FederationPeer {
                server_id,
                server_name: their_intro.server_name,
                address: "incoming".to_string(),
                status: FederationStatus::Connected,
                last_seen: now,
                connected_at: Some(now),
            });
        } else if let Some(p) = peers.get_mut(&server_id) {
            p.status = FederationStatus::Connected;
            p.last_seen = now;
            p.connected_at = Some(now);
        }

        info!(server_id, "incoming peer connection established");
        Ok(())
    }

    /// Send a message to a peer
    pub async fn send_to_peer(&self, server_id: ServerId, message: &ServerFederationMessage) -> io::Result<()> {
        let conn = {
            let conns = self.connections.lock().await;
            conns.get(&server_id).cloned()
        };

        let Some(conn) = conn else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "peer not connected"));
        };

        conn.send_message(message).await
    }

    /// Receive a message from a peer
    pub async fn recv_from_peer(&self, server_id: ServerId) -> io::Result<ServerFederationMessage> {
        let conn = {
            let conns = self.connections.lock().await;
            conns.get(&server_id).cloned()
        };

        let Some(conn) = conn else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "peer not connected"));
        };

        conn.recv_message().await
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, server_id: ServerId) {
        let mut connections = self.connections.lock().await;
        connections.remove(&server_id);

        let mut secrets = self.secrets.lock().await;
        secrets.remove(&server_id);

        let mut peers = self.peers.lock().await;
        if let Some(p) = peers.get_mut(&server_id) {
            p.status = FederationStatus::Disconnected;
        }

        debug!(server_id, "disconnected from peer");
    }

    /// Get peer status
    pub async fn get_peer(&self, server_id: ServerId) -> Option<FederationPeer> {
        let peers = self.peers.lock().await;
        peers.get(&server_id).cloned()
    }

    /// Get all peers
    pub async fn get_all_peers(&self) -> Vec<FederationPeer> {
        let peers = self.peers.lock().await;
        peers.values().cloned().collect()
    }

    /// Check if peer is connected
    pub async fn is_connected(&self, server_id: ServerId) -> bool {
        let connections = self.connections.lock().await;
        connections.contains_key(&server_id)
    }

    /// Get user directory (for user lookup)
    pub fn user_directory(&self) -> Arc<UserDirectory> {
        Arc::clone(&self.user_directory)
    }

    /// Get shared secret for encryption
    pub async fn get_shared_secret(&self, server_id: ServerId) -> Option<[u8; 32]> {
        let secrets = self.secrets.lock().await;
        secrets.get(&server_id).copied()
    }

    /// Get next outgoing nonce
    pub async fn next_nonce(&self, server_id: ServerId) -> u64 {
        let conns = self.connections.lock().await;
        if let Some(conn) = conns.get(&server_id) {
            conn.next_nonce()
        } else {
            0
        }
    }

    /// Mark peer as offline
    pub async fn mark_offline(&self, server_id: ServerId) {
        let mut peers = self.peers.lock().await;
        if let Some(p) = peers.get_mut(&server_id) {
            p.status = FederationStatus::Disconnected;
        }
    }
}
