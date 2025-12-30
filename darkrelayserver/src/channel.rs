use std::collections::{HashMap, HashSet};

use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use chrono::Utc;

use darkrelayprotocol::protocol::{ChannelId, ChannelInfo, ChatMessage, MessageId};

pub type ClientId = u64;

#[derive(Debug, Clone)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub is_public: bool,
    pub password_hash: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub members: HashSet<ClientId>,
}

impl Channel {
    pub fn info(&self) -> ChannelInfo {
        ChannelInfo {
            id: self.id,
            name: self.name.clone(),
            is_public: self.is_public,
        }
    }
}

#[derive(Debug, Default)]
pub struct ChannelManager {
    channels_by_name: HashMap<String, Channel>,
    next_channel_id: ChannelId,
    next_message_id: MessageId,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels_by_name: HashMap::new(),
            next_channel_id: 1,
            next_message_id: 1,
        }
    }

    pub fn ensure_channel(&mut self, name: &str, is_public: bool, password: Option<String>) {
        if self.channels_by_name.contains_key(name) {
            return;
        }

        let (is_public, password_hash) = match password {
            Some(pw) if !pw.is_empty() => (false, Some(hash_password(&pw))),
            _ => (is_public, None),
        };

        let channel = Channel {
            id: self.next_channel_id,
            name: name.to_string(),
            is_public,
            password_hash,
            messages: Vec::new(),
            members: HashSet::new(),
        };

        self.next_channel_id += 1;
        self.channels_by_name.insert(name.to_string(), channel);
    }

    pub fn list_public(&self) -> Vec<ChannelInfo> {
        let mut out: Vec<_> = self
            .channels_by_name
            .values()
            .filter(|c| c.is_public)
            .map(|c| c.info())
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn join(
        &mut self,
        client_id: ClientId,
        name: &str,
        password: Option<String>,
    ) -> Result<ChannelInfo, String> {
        if !self.channels_by_name.contains_key(name) {
            let pw = password.clone();
            self.ensure_channel(name, pw.is_none(), pw);
        }

        let channel = self
            .channels_by_name
            .get_mut(name)
            .ok_or_else(|| "channel not found".to_string())?;

        if let Some(hash) = &channel.password_hash {
            let provided = password.unwrap_or_default();
            if !verify_password(&provided, hash) {
                return Err("invalid channel password".to_string());
            }
        }

        channel.members.insert(client_id);
        Ok(channel.info())
    }

    pub fn leave(&mut self, client_id: ClientId, name: &str) {
        if let Some(channel) = self.channels_by_name.get_mut(name) {
            channel.members.remove(&client_id);
        }
    }

    pub fn members(&self, name: &str) -> Vec<ClientId> {
        self.channels_by_name
            .get(name)
            .map(|c| c.members.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn add_message(&mut self, channel: &str, mut message: ChatMessage) -> Result<ChatMessage, String> {
        let ch = self
            .channels_by_name
            .get_mut(channel)
            .ok_or_else(|| "channel not found".to_string())?;

        message.id = self.next_message_id;
        self.next_message_id += 1;
        message.timestamp = Utc::now();

        ch.messages.push(message.clone());
        if ch.messages.len() > 100 {
            let overflow = ch.messages.len() - 100;
            ch.messages.drain(0..overflow);
        }

        Ok(message)
    }

    pub fn history(&self, channel: &str, limit: usize) -> Vec<ChatMessage> {
        let Some(ch) = self.channels_by_name.get(channel) else {
            return Vec::new();
        };

        let mut out: Vec<_> = ch.messages.iter().rev().take(limit).cloned().collect();
        out.reverse();
        out
    }
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("hash password")
        .to_string()
}

fn verify_password(password: &str, hash: &str) -> bool {
    let argon2 = Argon2::default();
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    argon2.verify_password(password.as_bytes(), &parsed).is_ok()
}
