use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: MessageId,
    pub user_id: UserId,
    pub username: String,
    pub content: Vec<u8>,
    pub timestamp: DateTime<Utc>,

    /// Extensible map for future phases (encryption headers, routing hints, etc.).
    pub metadata: Vec<(String, String)>,
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
}
