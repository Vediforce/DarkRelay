use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use darkrelayprotocol::protocol::{TransferStatus, UserId};
use itertools::Itertools;

const MAX_TRANSFER_QUEUE_SIZE: usize = 100 * 1024 * 1024; // 100MB
const TRANSFER_TIMEOUT_SECS: u64 = 300; // 5 minutes
const CLEANUP_INTERVAL_SECS: u64 = 3600; // 1 hour

#[derive(Clone, Debug)]
pub struct FileTransfer {
    pub id: u64,
    pub sender_id: UserId,
    pub recipient_id: UserId,
    pub file_name: String,
    pub file_size: u64,
    pub file_hash: Vec<u8>,
    pub status: TransferStatus,
    pub created_at: u64,
    pub accepted_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub chunks: Vec<FileChunk>,
}

#[derive(Clone, Debug)]
pub struct FileChunk {
    pub chunk_index: u32,
    pub chunk_data: Vec<u8>,
    pub chunk_hash: Vec<u8>,
    pub received_at: u64,
}

pub struct FileTransferManager {
    transfers: Arc<Mutex<HashMap<u64, FileTransfer>>>,
    next_transfer_id: Arc<Mutex<u64>>,
    active_transfers: Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<()>>>>,
}

impl FileTransferManager {
    pub fn new() -> Self {
        Self {
            transfers: Arc::new(Mutex::new(HashMap::new())),
            next_transfer_id: Arc::new(Mutex::new(1)),
            active_transfers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_transfer(
        &self,
        sender_id: UserId,
        recipient_id: UserId,
        file_name: String,
        file_size: u64,
        file_hash: Vec<u8>,
    ) -> u64 {
        let mut transfer_id = self.next_transfer_id.lock().await;
        let current_id = *transfer_id;
        *transfer_id += 1;
        drop(transfer_id);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let transfer = FileTransfer {
            id: current_id,
            sender_id,
            recipient_id,
            file_name,
            file_size,
            file_hash,
            status: TransferStatus::Pending,
            created_at: now,
            accepted_at: None,
            completed_at: None,
            chunks: Vec::new(),
        };

        self.transfers.lock().await.insert(current_id, transfer);
        current_id
    }

    pub async fn update_transfer_status(&self, transfer_id: u64, status: TransferStatus) -> bool {
        let mut transfers = self.transfers.lock().await;
        if let Some(transfer) = transfers.get_mut(&transfer_id) {
            transfer.status = status;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            match status {
                TransferStatus::InProgress => {
                    transfer.accepted_at = Some(now);
                }
                TransferStatus::Completed | TransferStatus::Failed | TransferStatus::Declined => {
                    transfer.completed_at = Some(now);
                }
                _ => {}
            }
            true
        } else {
            false
        }
    }

    pub async fn accept_transfer(&self, transfer_id: u64) -> bool {
        self.update_transfer_status(transfer_id, TransferStatus::InProgress).await
    }

    pub async fn decline_transfer(&self, transfer_id: u64) -> bool {
        self.update_transfer_status(transfer_id, TransferStatus::Declined).await
    }

    pub async fn add_chunk(
        &self,
        transfer_id: u64,
        chunk_index: u32,
        chunk_data: Vec<u8>,
        chunk_hash: Vec<u8>,
    ) -> bool {
        let mut transfers = self.transfers.lock().await;
        if let Some(transfer) = transfers.get_mut(&transfer_id) {
            let chunk = FileChunk {
                chunk_index,
                chunk_data,
                chunk_hash,
                received_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            transfer.chunks.push(chunk);
            true
        } else {
            false
        }
    }

    pub async fn complete_transfer(&self, transfer_id: u64) -> bool {
        self.update_transfer_status(transfer_id, TransferStatus::Completed).await
    }

    pub async fn fail_transfer(&self, transfer_id: u64) -> bool {
        self.update_transfer_status(transfer_id, TransferStatus::Failed).await
    }

    pub async fn get_transfer(&self, transfer_id: u64) -> Option<FileTransfer> {
        self.transfers.lock().await.get(&transfer_id).cloned()
    }

    pub async fn get_pending_transfers_for_user(&self, user_id: UserId) -> Vec<FileTransfer> {
        let transfers = self.transfers.lock().await;
        transfers
            .values()
            .filter(|t| {
                t.recipient_id == user_id && matches!(t.status, TransferStatus::Pending)
            })
            .cloned()
            .collect()
    }

    pub async fn get_progress(&self, transfer_id: u64) -> Option<(TransferStatus, u32)> {
        let transfers = self.transfers.lock().await;
        if let Some(transfer) = transfers.get(&transfer_id) {
            let progress_percent = if transfer.file_size > 0 {
                let received_bytes: u64 = transfer.chunks.iter().map(|c| c.chunk_data.len() as u64).sum();
                ((received_bytes * 100) / transfer.file_size) as u32
            } else {
                0
            };
            Some((transfer.status.clone(), progress_percent.min(100)))
        } else {
            None
        }
    }

    pub async fn cleanup_expired_transfers(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut transfers = self.transfers.lock().await;
        let mut to_remove = Vec::new();

        for (id, transfer) in transfers.iter() {
            let should_remove = match transfer.status {
                TransferStatus::Completed | TransferStatus::Failed | TransferStatus::Declined => {
                    transfer.completed_at.map_or(false, |t| now - t > 3600) // Remove after 1 hour
                }
                TransferStatus::Pending => {
                    now - transfer.created_at > TRANSFER_TIMEOUT_SECS // Remove after 5 minutes timeout
                }
                TransferStatus::InProgress => {
                    now - transfer.accepted_at.unwrap_or(0) > TRANSFER_TIMEOUT_SECS // Remove hanging transfers
                }
            };

            if should_remove {
                to_remove.push(*id);
            }
        }

        for id in to_remove {
            transfers.remove(&id);
        }
    }

    pub async fn cancel_transfer(&self, transfer_id: u64) -> bool {
        let completed = self.update_transfer_status(transfer_id, TransferStatus::Failed).await;
        if completed {
            // Notify both parties of cancellation
            true
        } else {
            false
        }
    }

    pub async fn verify_chunk_hash(&self, transfer_id: u64, chunk_index: u32, expected_hash: &[u8]) -> bool {
        let transfers = self.transfers.lock().await;
        if let Some(transfer) = transfers.get(&transfer_id) {
            transfer.chunks.iter()
                .find(|c| c.chunk_index == chunk_index)
                .map_or(false, |c| c.chunk_hash == expected_hash)
        } else {
            false
        }
    }

    pub async fn verify_file_integrity(&self, transfer_id: u64) -> bool {
        let transfers = self.transfers.lock().await;
        if let Some(transfer) = transfers.get(&transfer_id) {
            use sha2::{Sha256, Digest};
            
            let mut hasher = Sha256::new();
            for chunk in transfer.chunks.iter().sorted_by_key(|c| c.chunk_index) {
                hasher.update(&chunk.chunk_data);
            }
            let computed_hash = hasher.finalize().to_vec();
            
            computed_hash == transfer.file_hash
        } else {
            false
        }
    }

    pub async fn clear_all_transfers(&self) {
        let mut transfers = self.transfers.lock().await;
        transfers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_get_transfer() {
        let manager = FileTransferManager::new();
        let sender_id = 1;
        let recipient_id = 2;
        let file_name = "test.txt".to_string();
        let file_size = 1024;
        let file_hash = vec![1u8, 2u8, 3u8];

        let transfer_id = manager.create_transfer(sender_id, recipient_id, file_name.clone(), file_size, file_hash.clone()).await;
        
        assert!(transfer_id > 0);
        
        if let Some(transfer) = manager.get_transfer(transfer_id).await {
            assert_eq!(transfer.sender_id, sender_id);
            assert_eq!(transfer.recipient_id, recipient_id);
            assert_eq!(transfer.file_name, file_name);
            assert_eq!(transfer.file_size, file_size);
            assert_eq!(transfer.file_hash, file_hash);
            assert!(matches!(transfer.status, TransferStatus::Pending));
        } else {
            panic!("Transfer not found");
        }
    }

    #[tokio::test]
    async fn test_accept_transfer() {
        let manager = FileTransferManager::new();
        let transfer_id = manager.create_transfer(1, 2, "test.txt".to_string(), 1024, vec![]).await;
        
        assert!(manager.accept_transfer(transfer_id).await);
        
        if let Some(transfer) = manager.get_transfer(transfer_id).await {
            assert!(matches!(transfer.status, TransferStatus::InProgress));
            assert!(transfer.accepted_at.is_some());
        }
    }
}