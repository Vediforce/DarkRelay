use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpSocket};
use tokio::sync::{Mutex, RwLock};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, info, warn, error};
use x25519_dalek::SharedSecret;

use darkrelayprotocol::federation::{
    ServerFederationMessage, ServerId, FederationPeer, FederationStatus,
    ServerIntro, ServerAck, FEDERATION_RECONNECT_INTERVAL_SECS, FEDERATION_PROTOCOL_VERSION,
};
use crate::federation::handshake::FederationHandshake;
use crate::federation::user_lookup::UserDirectory;

pub struct PeerManager {
    /// Connected peers
    peers: RwLock<HashMap<ServerId, FederationPeer>>,
    /// Active TLS connections to peers
    connections: RwLock<HashMap<ServerId, TlsStream<TcpStream>>>,
    /// Federation shared secrets per peer
    secrets: RwLock<HashMap<ServerId, SharedSecret>>,
    /// ECDH handshake manager
    handshake: Arc<FederationHandshake>,
    /// User directory for lookups
    user_directory: Arc<UserDirectory>,
    /// Our server ID
    our_server_id: ServerId,
    /// Our server name
    our_server_name: String,
    /// Outgoing nonce counter per connection
    nonces: RwLock<HashMap<ServerId, u64>>,
}

impl PeerManager {
    pub fn new(our_server_id: ServerId, our_server_name: String) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            secrets: RwLock::new(HashMap::new()),
            handshake: Arc::new(FederationHandshake::new()),
            user_directory: Arc::new(UserDirectory::new()),
            our_server_id,
            our_server_name,
            nonces: RwLock::new(HashMap::new()),
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

        let mut peers = self.peers.write().await;
        peers.insert(server_id, peer);
        debug!(server_id, "peer added");
    }

    /// Connect to a peer and perform handshake
    pub async fn connect_to_peer(&self, server_id: ServerId) -> io::Result<()> {
        let peer = {
            let peers = self.peers.read().await;
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
        
        let stream = socket.connect(peer.address.parse::<SocketAddr>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        // Perform TLS handshake
        let domain = rustls::ServerName::try_from("localhost").unwrap();
        let tls_stream = connector.connect(domain, stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS error: {e}")))?;

        // Perform federation handshake
        let (our_public, intro) = self.handshake.initiate_handshake(
            self.our_server_id,
            self.our_server_name.clone(),
        ).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Send ServerIntro
        let intro_bytes = bincode::serialize(&ServerFederationMessage::ServerIntro(intro))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let (mut writer, mut reader) = tokio::io::split(tls_stream);
        Self::write_frame(&mut writer, &intro_bytes).await?;

        // Wait for ServerAck
        let ack_bytes = Self::read_frame::<ServerFederationMessage, _>(&mut reader).await?;
        
        let ServerFederationMessage::ServerAck(ack) = ack_bytes else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ServerAck"));
        };

        // Complete handshake
        let shared_secret = self.handshake.complete_handshake(server_id, &ack)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Store connection and secret
        let mut connections = self.connections.write().await;
        let mut nonces = self.nonces.write().await;
        nonces.insert(server_id, 0);
        connections.insert(server_id, tls_stream);
        
        let mut secrets = self.secrets.write().await;
        secrets.insert(server_id, shared_secret);

        // Update peer status
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(&server_id) {
            p.status = FederationStatus::Connected;
            p.last_seen = now;
            p.connected_at = Some(now);
        }

        info!(server_id, "connected to peer successfully");
        Ok(())
    }

    /// Handle incoming connection from peer
    pub async fn handle_incoming_connection(&self, stream: TlsStream<TcpStream>, their_intro: ServerIntro) -> io::Result<()> {
        let server_id = their_intro.server_id;

        // Create ServerAck
        let ack = self.handshake.create_server_ack(
            &their_intro,
            self.our_server_id,
            self.our_server_name.clone(),
        ).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let ack_msg = ServerFederationMessage::ServerAck(ack);
        let ack_bytes = bincode::serialize(&ack_msg)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        let (mut writer, mut reader) = tokio::io::split(stream);
        Self::write_frame(&mut writer, &ack_bytes).await?;

        // Wait for their ServerAck to complete mutual authentication
        let their_ack_bytes = Self::read_frame::<ServerFederationMessage, _>(&mut reader).await?;
        let ServerFederationMessage::ServerAck(their_ack) = their_ack_bytes else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ServerAck"));
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add peer if new
        let mut peers = self.peers.write().await;
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

    /// Send a message to a peer (with federation encryption)
    pub async fn send_to_peer(&self, server_id: ServerId, message: &ServerFederationMessage) -> io::Result<()> {
        let connections = self.connections.read().await;
        let Some(stream) = connections.get(&server_id) else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "peer not connected"));
        };

        let (mut writer, _) = tokio::io::split(stream);
        let msg_bytes = bincode::serialize(message)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Self::write_frame(&mut writer, &msg_bytes).await
    }

    /// Send a raw message to a peer
    pub async fn send_raw_to_peer(&self, server_id: ServerId, data: &[u8]) -> io::Result<()> {
        let connections = self.connections.read().await;
        let Some(mut stream) = connections.get(&server_id).cloned() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "peer not connected"));
        };

        stream.write_all(data).await
    }

    /// Receive a message from a peer
    pub async fn recv_from_peer(&self, server_id: ServerId) -> io::Result<ServerFederationMessage> {
        let connections = self.connections.read().await;
        let Some(stream) = connections.get(&server_id).cloned() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "peer not connected"));
        };

        let (_, mut reader) = tokio::io::split(stream);
        Self::read_frame::<ServerFederationMessage, _>(&mut reader).await
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, server_id: ServerId) {
        let mut connections = self.connections.write().await;
        connections.remove(&server_id);

        let mut secrets = self.secrets.write().await;
        secrets.remove(&server_id);

        let mut nonces = self.nonces.write().await;
        nonces.remove(&server_id);

        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(&server_id) {
            p.status = FederationStatus::Disconnected;
        }

        self.handshake.remove_secret(server_id);

        debug!(server_id, "disconnected from peer");
    }

    /// Get peer status
    pub async fn get_peer(&self, server_id: ServerId) -> Option<FederationPeer> {
        let peers = self.peers.read().await;
        peers.get(&server_id).cloned()
    }

    /// Get all peers
    pub async fn get_all_peers(&self) -> Vec<FederationPeer> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Check if peer is connected
    pub async fn is_connected(&self, server_id: ServerId) -> bool {
        let connections = self.connections.read().await;
        connections.contains_key(&server_id)
    }

    /// Get handshake manager (for user lookup)
    pub fn handshake_manager(&self) -> Arc<FederationHandshake> {
        Arc::clone(&self.handshake)
    }

    /// Get user directory (for user lookup)
    pub fn user_directory(&self) -> Arc<UserDirectory> {
        Arc::clone(&self.user_directory)
    }

    /// Get shared secret for encryption
    pub async fn get_shared_secret(&self, server_id: ServerId) -> Option<SharedSecret> {
        let secrets = self.secrets.read().await;
        secrets.get(&server_id).cloned()
    }

    /// Get next outgoing nonce
    pub async fn next_nonce(&self, server_id: ServerId) -> u64 {
        let mut nonces = self.nonces.write().await;
        let nonce = nonces.entry(server_id).or_insert(0);
        *nonce += 1;
        *nonce
    }

    /// Mark peer as offline
    pub async fn mark_offline(&self, server_id: ServerId) {
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(&server_id) {
            p.status = FederationStatus::Disconnected;
        }
    }

    /// Get user directory reference
    pub fn user_directory_ref(&self) -> &UserDirectory {
        &self.user_directory
    }

    /// Helper to write a length-prefixed frame
    async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
        let len = data.len() as u32;
        let mut frame = Vec::with_capacity(4 + len);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(data);
        writer.write_all(&frame).await
    }

    /// Helper to read a length-prefixed frame
    async fn read_frame<T: serde::de::DeserializeOwned, R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<T> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).await?;

        bincode::deserialize(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}
