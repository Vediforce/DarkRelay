use std::collections::HashMap;

use chrono::Utc;
use darkrelayprotocol::protocol::{ChannelInfo, ChatMessage, MessageMeta, UserInfo};
use crate::crypto::CryptoState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Login,
    Register,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppView {
    Channels,
    DirectMessages,
    FileTransfers,
}

#[derive(Debug, Clone)]
pub struct PendingFileTransfer {
    pub transfer_id: u64,
    pub file_name: String,
    pub file_size: u64,
    pub sender_id: Option<u64>,
    pub sender_username: Option<String>,
    pub is_incoming: bool,
    pub progress: u32,
    pub status: FileTransferStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTransferStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
    Declined,
}

pub struct ClientState {
    pub server_addr: String,
    pub user: Option<UserInfo>,
    pub generated_password: Option<String>,

    pub channels: Vec<ChannelInfo>,
    pub current_channel: Option<String>,

    pub messages_by_channel: HashMap<String, Vec<ChatMessage>>,

    pub crypto: CryptoState,

    pub current_view: AppView,
    
    // DM state (will be properly managed via dm_handler module)
    pub dm_conversations: HashMap<u64, Vec<crate::dm_handler::FederatedStoredDM>>,
    pub active_dm_user: Option<u64>,
    pub unread_dms: HashMap<u64, usize>,
    
    // File transfer state
    pub file_transfers: HashMap<u64, PendingFileTransfer>,
    
    next_msg_id: u64,
}

impl ClientState {
    pub fn new(server_addr: String) -> Self {
        Self {
            server_addr,
            user: None,
            generated_password: None,
            channels: Vec::new(),
            current_channel: None,
            messages_by_channel: HashMap::new(),
            crypto: CryptoState::new(),
            current_view: AppView::Channels,
            dm_conversations: HashMap::new(),
            active_dm_user: None,
            unread_dms: HashMap::new(),
            file_transfers: HashMap::new(),
            next_msg_id: 1,
        }
    }

    pub fn reset(&mut self) {
        self.user = None;
        self.generated_password = None;
        self.channels.clear();
        self.current_channel = None;
        self.messages_by_channel.clear();
        self.crypto.reset();
        self.current_view = AppView::Channels;
        self.dm_conversations.clear();
        self.active_dm_user = None;
        self.unread_dms.clear();
        self.file_transfers.clear();
        self.next_msg_id = 1;
    }

    pub fn next_meta(&mut self) -> MessageMeta {
        let id = self.next_msg_id;
        self.next_msg_id += 1;
        MessageMeta::new(id, Utc::now())
    }

    pub fn push_message(&mut self, channel: &str, msg: ChatMessage) {
        let entry = self
            .messages_by_channel
            .entry(channel.to_string())
            .or_default();
        entry.push(msg);
        if entry.len() > 500 {
            let overflow = entry.len() - 500;
            entry.drain(0..overflow);
        }
    }

    pub fn messages_for_current(&self) -> Vec<ChatMessage> {
        let Some(ch) = &self.current_channel else {
            return Vec::new();
        };

        self.messages_by_channel
            .get(ch)
            .cloned()
            .unwrap_or_default()
    }

    pub fn remove_message(&mut self, channel: &str, message_id: u64) {
        if let Some(messages) = self.messages_by_channel.get_mut(channel) {
            messages.retain(|msg| msg.id != message_id);
        }
    }
}
