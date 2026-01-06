use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type ServerId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FederationStatus {
    Connected,
    Disconnected,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIntro {
    pub server_id: ServerId,
    pub server_name: String,
    pub server_version: String,
    pub public_key: Vec<u8>,
    pub timestamp: u64,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAck {
    pub server_id: ServerId,
    pub status: FederationStatus,
    pub server_name: String,
    pub server_version: String,
    pub public_key: Vec<u8>,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveUser {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResolved {
    pub user_id: u64,
    pub username: String,
    pub server_id: ServerId,
    pub is_online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserNotFound {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDM {
    pub dm_id: u64,
    pub sender_id: u64,
    pub sender_server_id: ServerId,
    pub recipient_username: String,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp: u64,
    pub hop_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDMAck {
    pub dm_id: u64,
    pub delivered: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayChannelMessage {
    pub channel_id: u64,
    pub message_id: u64,
    pub sender_id: u64,
    pub sender_server_id: ServerId,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp: u64,
    pub hop_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFileTransferRequest {
    pub transfer_id: u64,
    pub sender_id: u64,
    pub sender_server_id: ServerId,
    pub recipient_username: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_hash: Vec<u8>,
    pub hop_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFileChunk {
    pub transfer_id: u64,
    pub chunk_index: u32,
    pub chunk_data: Vec<u8>,
    pub chunk_hash: Vec<u8>,
    pub hop_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFileAck {
    pub transfer_id: u64,
    pub chunk_index: u32,
    pub received: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStatusUpdate {
    pub user_id: u64,
    pub username: String,
    pub server_id: ServerId,
    pub is_online: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationMessage {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerFederationMessage {
    // Handshake & Discovery
    ServerIntro(ServerIntro),
    ServerAck(ServerAck),

    // User Discovery
    ResolveUser(ResolveUser),
    UserResolved(UserResolved),
    UserNotFound(UserNotFound),

    // Message Relay
    RelayDM(RelayDM),
    RelayDMAck(RelayDMAck),

    // Channel Federation (Phase 5+)
    RelayChannelMessage(RelayChannelMessage),

    // File Transfer Relay
    RelayFileTransferRequest(RelayFileTransferRequest),
    RelayFileChunk(RelayFileChunk),
    RelayFileAck(RelayFileAck),

    // User Status Sync
    UserStatusUpdate(UserStatusUpdate),

    // Heartbeat/Ping
    Ping,
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedUser {
    pub local_id: Option<u64>,
    pub username: String,
    pub server_id: ServerId,
    pub server_name: String,
    pub is_online: bool,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    pub server_id: ServerId,
    pub server_name: String,
    pub server_version: String,
    pub protocol_version: u32,
    pub peers: Vec<PeerConfig>,
    pub queue_max_mb: u64,
    pub message_ttl_hours: u64,
    pub retry_max_attempts: u32,
    pub retry_backoff_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPeer {
    pub server_id: ServerId,
    pub server_name: String,
    pub address: String,
    pub status: FederationStatus,
    pub last_seen: u64,
    pub connected_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRelay {
    pub message_type: String,
    pub target_server_id: ServerId,
    pub payload: Vec<u8>,
    pub created_at: u64,
    pub attempts: u32,
    pub next_retry: u64,
}

pub const FEDERATION_PROTOCOL_VERSION: u32 = 1;
pub const FEDERATION_DEFAULT_PORT: u16 = 9000;
pub const FEDERATION_HOP_LIMIT: u8 = 5;
pub const FEDERATION_CACHE_TTL_SECS: u64 = 300; // 5 minutes
pub const FEDERATION_RECONNECT_INTERVAL_SECS: u64 = 30;
pub const FEDERATION_MESSAGE_TTL_HOURS: u64 = 24;
pub const FEDERATION_QUEUE_MAX_MB: u64 = 100;
