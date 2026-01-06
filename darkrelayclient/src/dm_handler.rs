use std::collections::HashMap;
use darkrelayprotocol::protocol::{StoredDM, UserId}; 
use chrono::Utc;

pub struct DMHandler {
    conversations: HashMap<UserId, Vec<StoredDM>>,
    unread_counts: HashMap<UserId, usize>,
    active_conversation: Option<UserId>,
}

impl DMHandler {
    pub fn new() -> Self {
        Self {
            conversations: HashMap::new(),
            unread_counts: HashMap::new(), 
            active_conversation: None,
        }
    }

    pub fn add_dm(&mut self, dm: StoredDM) {
        let sender_id = dm.sender_id;
        let conversation = self.conversations.entry(dm.sender_id).or_insert_with(Vec::new);
        
        if !conversation.iter().any(|existing| existing.dm_id == dm.dm_id) {
            conversation.push(dm);
        }
        
        if self.active_conversation != Some(sender_id) {
            *self.unread_counts.entry(sender_id).or_insert(0) += 1;
        }
    }

    pub fn set_active_conversation(&mut self, user_id: UserId) {
        self.active_conversation = Some(user_id);
        self.unread_counts.insert(user_id, 0);
    }

    pub fn clear_active_conversation(&mut self) {
        self.active_conversation = None;
    }

    pub fn get_conversations(&self) -> impl Iterator<Item = (&UserId, &Vec<StoredDM>)> {
        self.conversations.iter()
    }

    pub fn get_unread_count(&self, user_id: UserId) -> usize {
        self.unread_counts.get(&user_id).copied().unwrap_or(0)
    }

    pub fn get_total_unread_count(&self) -> usize {
        self.unread_counts.values().sum()
    }

    pub fn get_conversation(&self, user_id: UserId) -> Option<&Vec<StoredDM>> {
        self.conversations.get(&user_id)
    }

    pub fn add_history(&mut self, user_id: UserId, messages: Vec<StoredDM>) {
        let conversation = self.conversations.entry(user_id).or_insert_with(Vec::new);
        
        for message in messages {
            if !conversation.iter().any(|existing| existing.dm_id == message.dm_id) {
                conversation.push(message);
            }
        }
        
        conversation.sort_by_key(|m| m.timestamp);
    }

    pub fn mark_dm_as_read(&mut self, dm_id: u64, recipient_id: UserId) -> bool {
        if let Some(conversation) = self.conversations.get_mut(&recipient_id) {
            for dm in conversation.iter_mut() {
                if dm.dm_id == dm_id {
                    dm.is_read = true;
                    return true;
                }
            }
        }
        false
    }
}