use std::collections::HashMap;

use chrono::Utc;
use darkrelayprotocol::protocol::{ChannelInfo, ChatMessage, MessageMeta, UserInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Login,
    Register,
}

#[derive(Default)]
pub struct ClientState {
    pub server_addr: String,
    pub user: Option<UserInfo>,
    pub generated_password: Option<String>,

    pub channels: Vec<ChannelInfo>,
    pub current_channel: Option<String>,

    pub messages_by_channel: HashMap<String, Vec<ChatMessage>>,

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
            next_msg_id: 1,
        }
    }

    pub fn reset(&mut self) {
        self.user = None;
        self.generated_password = None;
        self.channels.clear();
        self.current_channel = None;
        self.messages_by_channel.clear();
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
}
