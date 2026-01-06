use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::channel::ChannelType;
use crate::permissions::Role;

pub type UserId = u64;
pub type ChannelId = u64;
pub type MessageId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMeta {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
}

impl MessageMeta {
    pub fn new(id: u64, timestamp: DateTime<Utc>) -> Self {
        Self { id, timestamp }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: UserId,
    pub username: String,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub id: ChannelId,
    pub name: String,
    pub is_public: bool,
    pub channel_type: ChannelType,
    pub user_role: Option<Role>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: MessageId,
    pub user_id: UserId,
    pub username: String,
    pub content: Vec<u8>,
    pub timestamp: DateTime<Utc>,

    /// Nonce used for AES-GCM encryption (12 bytes).
    pub nonce: Option<Vec<u8>>,

    /// Extensible map for future phases (encryption headers, routing hints, etc.).
    pub metadata: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanInfo {
    pub user_id: UserId,
    pub username: String,
    pub banned_until: Option<DateTime<Utc>>,
    pub banned_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminInfo {
    pub user_id: UserId,
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub user_id: UserId,
    pub username: String,
    pub action: String,
    pub target: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Declined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDM {
    pub dm_id: u64,
    pub sender_id: u64,
    pub recipient_id: u64,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransfer {
    pub id: u64,
    pub sender_id: u64,
    pub recipient_id: u64,
    pub file_name: String,
    pub file_size: u64,
    pub file_hash: Vec<u8>,
    pub status: TransferStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    Connect {
        meta: MessageMeta,
        client_name: Option<String>,
        client_version: Option<String>,
    },

    /// Special key verification (Phase 1).
    Auth {
        meta: MessageMeta,
        key: String,
    },

    /// ECDH key exchange (Phase 2): client sends its public key.
    EcdhPublicKey {
        meta: MessageMeta,
        public_key: Vec<u8>,
    },

    RegisterUser {
        meta: MessageMeta,
        username: String,
    },

    Login {
        meta: MessageMeta,
        username: String,
        password: String,
    },

    JoinChannel {
        meta: MessageMeta,
        name: String,
        password: Option<String>,
    },

    SendMessage {
        meta: MessageMeta,
        channel: String,

        /// Opaque blob. In Phase 1, the client sends plaintext bytes for testing.
        content: Vec<u8>,

        /// Additional message metadata (reserved for Phase 2+).
        metadata: Vec<(String, String)>,
    },

    ListChannels {
        meta: MessageMeta,
    },

    GetHistory {
        meta: MessageMeta,
        channel: String,
        limit: u16,
    },

    DeleteMessage {
        meta: MessageMeta,
        channel: String,
        message_id: MessageId,
    },

    PromoteUser {
        meta: MessageMeta,
        channel: String,
        username: String,
        role: Role,
    },

    DemoteUser {
        meta: MessageMeta,
        channel: String,
        username: String,
    },

    BanUser {
        meta: MessageMeta,
        channel: String,
        username: String,
        duration_seconds: Option<u64>,
        reason: Option<String>,
    },

    UnbanUser {
        meta: MessageMeta,
        channel: String,
        username: String,
    },

    KickUser {
        meta: MessageMeta,
        channel: String,
        username: String,
        reason: Option<String>,
    },

    ListAdmins {
        meta: MessageMeta,
        channel: String,
    },

    ListBans {
        meta: MessageMeta,
        channel: String,
    },

    ViewLogs {
        meta: MessageMeta,
        channel: String,
        limit: u32,
    },

    ChangeChannelType {
        meta: MessageMeta,
        channel: String,
        channel_type: ChannelType,
    },

    DeleteChannel {
        meta: MessageMeta,
        channel: String,
    },

    Disconnect {
        meta: MessageMeta,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    AuthChallenge {
        meta: MessageMeta,
        message: String,
    },

    AuthSuccess {
        meta: MessageMeta,
        user: UserInfo,

        /// Only present for registration.
        generated_password: Option<String>,
    },

    AuthFailure {
        meta: MessageMeta,
        reason: String,
    },

    /// ECDH acknowledgment (Phase 2): server sends its public key.
    EcdhAck {
        meta: MessageMeta,
        public_key: Vec<u8>,
    },

    ChannelList {
        meta: MessageMeta,
        channels: Vec<ChannelInfo>,
    },

    JoinSuccess {
        meta: MessageMeta,
        channel: ChannelInfo,
    },

    JoinFailure {
        meta: MessageMeta,
        channel: String,
        reason: String,
    },

    MessageReceived {
        meta: MessageMeta,
        channel: String,
        message: ChatMessage,
    },

    HistoryChunk {
        meta: MessageMeta,
        channel: String,
        messages: Vec<ChatMessage>,
    },

    UserJoined {
        meta: MessageMeta,
        channel: String,
        user: UserInfo,
    },

    UserLeft {
        meta: MessageMeta,
        channel: String,
        user: UserInfo,
    },

    SystemMessage {
        meta: MessageMeta,
        text: String,
    },

    ProtocolError {
        meta: MessageMeta,
        text: String,
    },

    MessageDeleted {
        meta: MessageMeta,
        channel: String,
        message_id: MessageId,
        deleted_by: String,
    },

    UserPromoted {
        meta: MessageMeta,
        channel: String,
        user_id: UserId,
        username: String,
        new_role: Role,
        promoted_by: String,
    },

    UserDemoted {
        meta: MessageMeta,
        channel: String,
        user_id: UserId,
        username: String,
        demoted_by: String,
    },

    UserBanned {
        meta: MessageMeta,
        channel: String,
        user_id: UserId,
        username: String,
        banned_until: Option<DateTime<Utc>>,
        banned_by: String,
        reason: Option<String>,
    },

    UserUnbanned {
        meta: MessageMeta,
        channel: String,
        username: String,
        unbanned_by: String,
    },

    UserKicked {
        meta: MessageMeta,
        channel: String,
        user_id: UserId,
        username: String,
        kicked_by: String,
        reason: Option<String>,
    },

    AdminList {
        meta: MessageMeta,
        channel: String,
        admins: Vec<AdminInfo>,
    },

    BanList {
        meta: MessageMeta,
        channel: String,
        bans: Vec<BanInfo>,
    },

    LogList {
        meta: MessageMeta,
        channel: String,
        logs: Vec<LogEntry>,
    },

    ChannelTypeChanged {
        meta: MessageMeta,
        channel: String,
        new_type: ChannelType,
        changed_by: String,
    },

    ChannelDeleted {
        meta: MessageMeta,
        channel: String,
        deleted_by: String,
    },

    AdminError {
        meta: MessageMeta,
        reason: String,
    },

    // Direct Messages
    DMReceived {
        meta: MessageMeta,
        dm_id: u64,
        sender_id: u64,
        content: Vec<u8>,  // encrypted
        nonce: Vec<u8>,
        recipient_id: u64,
    },
    DMHistory {
        meta: MessageMeta,
        messages: Vec<StoredDM>,
    },
    DMReadReceipt {
        meta: MessageMeta,
        dm_id: u64,
        read_at: u64,
    },

    // File Transfer
    FileTransferProposal {
        meta: MessageMeta,
        transfer_id: u64,
        sender_id: u64,
        file_name: String,
        file_size: u64,
    },
    FileTransferAcceptanceRequired {
        meta: MessageMeta,
        transfer_id: u64,
        sender_waiting: bool,  // true = sender waiting for response
    },
    FileTransferReady {
        meta: MessageMeta,
        transfer_id: u64,
        sender_connection_info: String,  // "ip:port"
    },
    FileTransferChunkAck {
        meta: MessageMeta,
        transfer_id: u64,
        chunk_index: u32,
    },
    FileTransferStatus {
        meta: MessageMeta,
        transfer_id: u64,
        status: TransferStatus,
        progress_percent: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    AuthChallenge {
        meta: MessageMeta,
        message: String,
    },

    AuthSuccess {
        meta: MessageMeta,
        user: UserInfo,

        /// Only present for registration.
        generated_password: Option<String>,
    },

    AuthFailure {
        meta: MessageMeta,
        reason: String,
    },

    /// ECDH acknowledgment (Phase 2): server sends its public key.
    EcdhAck {
        meta: MessageMeta,
        public_key: Vec<u8>,
    },

    ChannelList {
        meta: MessageMeta,
        channels: Vec<ChannelInfo>,
    },

    JoinSuccess {
        meta: MessageMeta,
        channel: ChannelInfo,
    },

    JoinFailure {
        meta: MessageMeta,
        channel: String,
        reason: String,
    },

    MessageReceived {
        meta: MessageMeta,
        channel: String,
        message: ChatMessage,
    },

    HistoryChunk {
        meta: MessageMeta,
        channel: String,
        messages: Vec<ChatMessage>,
    },

    UserJoined {
        meta: MessageMeta,
        channel: String,
        user: UserInfo,
    },

    UserLeft {
        meta: MessageMeta,
        channel: String,
        user: UserInfo,
    },

    SystemMessage {
        meta: MessageMeta,
        text: String,
    },

    ProtocolError {
        meta: MessageMeta,
        text: String,
    },

    MessageDeleted {
        meta: MessageMeta,
        channel: String,
        message_id: MessageId,
        deleted_by: String,
    },

    UserPromoted {
        meta: MessageMeta,
        channel: String,
        user_id: UserId,
        username: String,
        new_role: Role,
        promoted_by: String,
    },

    UserDemoted {
        meta: MessageMeta,
        channel: String,
        user_id: UserId,
        username: String,
        demoted_by: String,
    },

    UserBanned {
        meta: MessageMeta,
        channel: String,
        user_id: UserId,
        username: String,
        banned_until: Option<DateTime<Utc>>,
        banned_by: String,
        reason: Option<String>,
    },

    UserUnbanned {
        meta: MessageMeta,
        channel: String,
        username: String,
        unbanned_by: String,
    },

    UserKicked {
        meta: MessageMeta,
        channel: String,
        user_id: UserId,
        username: String,
        kicked_by: String,
        reason: Option<String>,
    },

    AdminList {
        meta: MessageMeta,
        channel: String,
        admins: Vec<AdminInfo>,
    },

    BanList {
        meta: MessageMeta,
        channel: String,
        bans: Vec<BanInfo>,
    },

    LogList {
        meta: MessageMeta,
        channel: String,
        logs: Vec<LogEntry>,
    },

    ChannelTypeChanged {
        meta: MessageMeta,
        channel: String,
        new_type: ChannelType,
        changed_by: String,
    },

    ChannelDeleted {
        meta: MessageMeta,
        channel: String,
        deleted_by: String,
    },

    AdminError {
        meta: MessageMeta,
        reason: String,
    },

    // Direct Messages
    SendDM {
        meta: MessageMeta,
        recipient_user_id: u64,
        content: Vec<u8>,  // encrypted
        nonce: Vec<u8>,
    },
    GetDMHistory {
        meta: MessageMeta,
        user_id: u64,
        limit: u32,  // retrieve last N DMs
    },
    AckDM {
        meta: MessageMeta,
        dm_id: u64,  // mark as read
    },

    // File Transfer
    FileTransferRequest {
        meta: MessageMeta,
        recipient_user_id: u64,
        file_name: String,
        file_size: u64,
        file_hash: Vec<u8>,  // SHA256 for verification
    },
    FileTransferAccept {
        meta: MessageMeta,
        transfer_id: u64,
        recipient_agreed: bool,  // true = accept, false = decline
    },
    FileTransferStart {
        meta: MessageMeta,
        transfer_id: u64,
        recipient_user_id: u64,
    },
    FileTransferChunk {
        meta: MessageMeta,
        transfer_id: u64,
        chunk_index: u32,
        chunk_data: Vec<u8>,  // encrypted
        chunk_hash: Vec<u8>,  // SHA256 of chunk for integrity
    },
    FileTransferComplete {
        meta: MessageMeta,
        transfer_id: u64,
    },
}
