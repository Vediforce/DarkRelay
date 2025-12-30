use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::Utc;

use darkrelayprotocol::protocol::{StoredDM, UserId};

const MAX_DM_PER_PAIR: usize = 100;

#[derive(Clone, Debug)]
pub struct DirectMessage {
    pub id: u64,
    pub sender_id: UserId,
    pub recipient_id: UserId,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_read: bool,
    pub created_at: u64,
}

pub struct DMManager {
    dms: Arc<Mutex<HashMap<(UserId, UserId), VecDeque<DirectMessage>>>>,
    next_dm_id: Arc<Mutex<u64>>,
}

impl DMManager {
    pub fn new() -> Self {
        Self {
            dms: Arc::new(Mutex::new(HashMap::new())),
            next_dm_id: Arc::new(Mutex::new(1)),
        }
    }

    pub async fn store_dm(
        &self,
        sender_id: UserId,
        recipient_id: UserId,
        content: Vec<u8>,
        nonce: Vec<u8>,
    ) -> (u64, chrono::DateTime<chrono::Utc>) {
        let mut dm_id = self.next_dm_id.lock().await;
        let current_id = *dm_id;
        *dm_id += 1;
        drop(dm_id);

        let dm = DirectMessage {
            id: current_id,
            sender_id,
            recipient_id,
            content,
            nonce,
            timestamp: Utc::now(),
            is_read: false,
            created_at: Utc::now().timestamp() as u64,
        };

        let pair_key = if sender_id < recipient_id {
            (sender_id, recipient_id)
        } else {
            (recipient_id, sender_id)
        };

        let mut dms = self.dms.lock().await;
        let dm_list = dms.entry(pair_key).or_insert_with(VecDeque::new);
        
        dm_list.push_back(dm);
        
        // Keep only last MAX_DM_PER_PAIR messages
        if dm_list.len() > MAX_DM_PER_PAIR {
            dm_list.pop_front();
        }

        (current_id, Utc::now())
    }

    pub async fn get_history_for_user(
        &self,
        user_id: UserId,
        other_user_id: UserId,
        limit: u32,
    ) -> Vec<StoredDM> {
        let dms = self.dms.lock().await;
        
        let pair_key = if user_id < other_user_id {
            (user_id, other_user_id)
        } else {
            (other_user_id, user_id)
        };

        if let Some(dm_list) = dms.get(&pair_key) {
            dm_list.iter()
                .filter(|dm| dm.sender_id == user_id || dm.recipient_id == user_id)
                .rev()
                .take(limit as usize)
                .map(|dm| StoredDM {
                    dm_id: dm.id,
                    sender_id: dm.sender_id,
                    recipient_id: dm.recipient_id,
                    content: dm.content.clone(),
                    nonce: dm.nonce.clone(),
                    timestamp: dm.timestamp,
                    is_read: dm.is_read,
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub async fn get_undelivered_dms(&self, user_id: UserId) -> Vec<StoredDM> {
        let dms = self.dms.lock().await;
        let mut result = Vec::new();

        for dm_list in dms.values() {
            for dm in dm_list.iter().filter(|dm| dm.recipient_id == user_id && !dm.is_read) {
                result.push(StoredDM {
                    dm_id: dm.id,
                    sender_id: dm.sender_id,
                    recipient_id: dm.recipient_id,
                    content: dm.content.clone(),
                    nonce: dm.nonce.clone(),
                    timestamp: dm.timestamp,
                    is_read: dm.is_read,
                });
            }
        }

        result
    }

    pub async fn mark_dm_as_read(&self, dm_id: u64, recipient_id: UserId) -> bool {
        let mut dms = self.dms.lock().await;
        
        for dm_list in dms.values_mut() {
            if let Some(dm) = dm_list.iter_mut().find(|dm| dm.id == dm_id && dm.recipient_id == recipient_id) {
                dm.is_read = true;
                return true;
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dm_storage_and_retrieval() {
        let dm_manager = DMManager::new();
        let sender_id = 1u64;
        let recipient_id = 2u64;
        let content = vec![1u8, 2u8, 3u8];
        let nonce = vec![4u8, 5u8, 6u8];

        let (dm_id, timestamp) = dm_manager.store_dm(sender_id, recipient_id, content.clone(), nonce.clone()).await;
        
        assert!(dm_id > 0);
        
        let history = dm_manager.get_history_for_user(sender_id, recipient_id, 10).await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].sender_id, sender_id);
        assert_eq!(history[0].recipient_id, recipient_id);
        assert_eq!(history[0].content, content);
        assert_eq!(history[0].nonce, nonce);
        assert!(!history[0].is_read);
    }

    #[tokio::test]
    async fn test_dm_mark_as_read() {
        let dm_manager = DMManager::new();
        let sender_id = 1u64;
        let recipient_id = 2u64;
        let content = vec![1u8, 2u8, 3u8];
        let nonce = vec![4u8, 5u8, 6u8];

        let (dm_id, _) = dm_manager.store_dm(sender_id, recipient_id, content, nonce).await;
        let marked = dm_manager.mark_dm_as_read(dm_id, recipient_id).await;
        
        assert!(marked);
        
        let history = dm_manager.get_history_for_user(sender_id, recipient_id, 10).await;
        assert_eq!(history.len(), 1);
        assert!(history[0].is_read);
    }
}