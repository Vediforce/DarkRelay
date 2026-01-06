use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn, error};
use bincode;

use darkrelayprotocol::federation::{
    RelayDM, RelayDMAck, RelayFileTransferRequest, RelayFileChunk, RelayFileAck,
    ServerId, PendingRelay, FEDERATION_MESSAGE_TTL_HOURS, FEDERATION_HOP_LIMIT,
};

pub struct MessageRelay {
    /// Pending messages to relay to remote servers (per server)
    pending_messages: Arc<Mutex<HashMap<ServerId, VecDeque<PendingRelay>>>>,
    /// Track DM IDs to prevent duplicates
    relayed_dms: Arc<Mutex<HashMap<u64, (ServerId, u64)>>>, // dm_id -> (origin_server, timestamp)
    /// Track file transfer IDs to prevent duplicates
    relayed_transfers: Arc<Mutex<HashMap<u64, (ServerId, u64)>>>, // transfer_id -> (origin_server, timestamp)
    /// Message statistics
    stats: Arc<Mutex<RelayStats>>,
}

#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    pub total_relayed: u64,
    pub total_delivered: u64,
    pub total_failed: u64,
    pub pending_count: u64,
    pub queue_size_bytes: u64,
}

impl MessageRelay {
    pub fn new() -> Self {
        Self {
            pending_messages: Arc::new(Mutex::new(HashMap::new())),
            relayed_dms: Arc::new(Mutex::new(HashMap::new())),
            relayed_transfers: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(RelayStats::default())),
        }
    }

    /// Queue a DM for relay to a remote server
    pub async fn queue_dm_for_relay(
        &self,
        target_server_id: ServerId,
        dm_id: u64,
        sender_server_id: ServerId,
        content: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<(), String> {
        // Check for duplicate
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        {
            let relayed = self.relayed_dms.lock().unwrap();
            if let Some((origin, timestamp)) = relayed.get(&dm_id) {
                if *origin == sender_server_id && now - timestamp < 300 {
                    debug!(dm_id, "skipping duplicate DM relay");
                    return Ok(());
                }
            }
        }

        let payload = bincode::serialize(&RelayDM {
            dm_id,
            sender_id: 0, // Will be filled by originating server
            sender_server_id,
            recipient_username: String::new(), // Will be filled
            content,
            nonce,
            timestamp: now,
            hop_count: 0,
        }).map_err(|e| e.to_string())?;

        self.queue_message(target_server_id, "dm", dm_id, payload).await;

        // Mark as relayed
        {
            let mut relayed = self.relayed_dms.lock().unwrap();
            relayed.insert(dm_id, (sender_server_id, now));
        }
        
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_relayed += 1;
            stats.pending_count += 1;
        }

        info!(dm_id, target_server_id, "DM queued for relay");
        Ok(())
    }

    /// Queue a file transfer request for relay
    pub async fn queue_file_transfer_request(
        &self,
        target_server_id: ServerId,
        transfer_id: u64,
        sender_id: u64,
        sender_server_id: ServerId,
        recipient_username: String,
        file_name: String,
        file_size: u64,
        file_hash: Vec<u8>,
    ) {
        let payload = bincode::serialize(&RelayFileTransferRequest {
            transfer_id,
            sender_id,
            sender_server_id,
            recipient_username,
            file_name,
            file_size,
            file_hash,
            hop_count: 0,
        }).expect("serialize file transfer request");

        self.queue_message(target_server_id, "file_request", transfer_id, payload).await;

        let mut stats = self.stats.lock().unwrap();
        stats.total_relayed += 1;
        stats.pending_count += 1;
    }

    /// Queue a file chunk for relay
    pub async fn queue_file_chunk(
        &self,
        target_server_id: ServerId,
        transfer_id: u64,
        chunk_index: u32,
        chunk_data: Vec<u8>,
        chunk_hash: Vec<u8>,
    ) {
        let payload = bincode::serialize(&RelayFileChunk {
            transfer_id,
            chunk_index,
            chunk_data,
            chunk_hash,
            hop_count: 0,
        }).expect("serialize file chunk");

        self.queue_message(target_server_id, "file_chunk", transfer_id, payload).await;

        let mut stats = self.stats.lock().unwrap();
        stats.total_relayed += 1;
        stats.pending_count += 1;
    }

    /// Queue a message for relay
    pub async fn queue_message(&self, target_server_id: ServerId, msg_type: &str, _msg_id: u64, payload: Vec<u8>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let pending = PendingRelay {
            message_type: msg_type.to_string(),
            target_server_id,
            payload,
            created_at: now,
            attempts: 0,
            next_retry: now,
        };

        let mut queue = self.pending_messages.lock().unwrap();
        let server_queue = queue.entry(target_server_id).or_insert_with(VecDeque::new);
        server_queue.push_back(pending);
    }

    /// Get pending messages for a specific server (for actual sending)
    pub async fn get_pending_for_server(&self, server_id: ServerId) -> Vec<PendingRelay> {
        let queue = self.pending_messages.lock().unwrap();
        queue.get(&server_id)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_else(Vec::new)
    }

    /// Mark a message as delivered (remove from queue)
    pub async fn mark_delivered(&self, server_id: ServerId, _msg_id: u64) {
        let mut queue = self.pending_messages.lock().unwrap();
        if let Some(server_queue) = queue.get_mut(&server_id) {
            server_queue.retain(|p| {
                // Simple matching by checking if this was a DM
                !matches!(p.message_type.as_str(), "dm" | "file_request" | "file_chunk")
            });
        }

        let mut stats = self.stats.lock().unwrap();
        stats.pending_count = stats.pending_count.saturating_sub(1);
        stats.total_delivered += 1;
    }

    /// Mark a message as failed (increment retry count)
    pub async fn mark_failed(&self, server_id: ServerId, _msg_id: u64, backoff_seconds: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut queue = self.pending_messages.lock().unwrap();
        if let Some(server_queue) = queue.get_mut(&server_id) {
            for pending in server_queue.iter_mut() {
                // For now, retry all pending messages
                pending.attempts += 1;
                pending.next_retry = now + backoff_seconds * pending.attempts as u64;
            }
        }

        let mut stats = self.stats.lock().unwrap();
        stats.pending_count = stats.pending_count.saturating_sub(1);
        stats.total_failed += 1;
    }

    pub async fn retry_pending_messages(&self) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            
            let mut queue = self.pending_messages.lock().unwrap();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            for (_server_id, server_queue) in queue.iter_mut() {
                for pending in server_queue.iter_mut() {
                    if pending.next_retry <= now && pending.attempts < 5 {
                        pending.attempts += 1;
                        // Calculate backoff with proper casting
                        let backoff_seconds = 60u64 * (2u64.pow(pending.attempts));
                        pending.next_retry = now + backoff_seconds;
                        
                        // TODO: Actually trigger sending here?
                        // The PeerManager usually handles the actual sending.
                    }
                }
            }
        }
    }

    /// Cleanup expired messages (TTL exceeded)
    pub async fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let ttl_secs = FEDERATION_MESSAGE_TTL_HOURS * 3600;
        let mut removed = 0;

        let mut queue = self.pending_messages.lock().unwrap();
        for server_queue in queue.values_mut() {
            let before_len = server_queue.len();
            server_queue.retain(|p| now - p.created_at < ttl_secs);
            removed += before_len - server_queue.len();
        }

        // Also cleanup old relay tracking entries
        {
            let mut relayed = self.relayed_dms.lock().unwrap();
            let cutoff = now - 3600; // 1 hour
            relayed.retain(|_, (_, ts)| *ts > cutoff);
        }

        {
            let mut transfers = self.relayed_transfers.lock().unwrap();
            let cutoff = now - 3600; // 1 hour
            transfers.retain(|_, (_, ts)| *ts > cutoff);
        }

        if removed > 0 {
            info!(count = removed, "cleaned up expired relay messages");
        }
    }

    /// Get relay statistics
    pub async fn get_stats(&self) -> RelayStats {
        let queue = self.pending_messages.lock().unwrap();
        let mut queue_size = 0;
        for server_queue in queue.values() {
            for pending in server_queue.iter() {
                queue_size += pending.payload.len();
            }
        }

        let mut stats = self.stats.lock().unwrap();
        stats.queue_size_bytes = queue_size as u64;
        stats.clone()
    }

    /// Clear all pending messages (for shutdown)
    pub async fn clear_all(&self) {
        let mut queue = self.pending_messages.lock().unwrap();
        queue.clear();
        
        let mut stats = self.stats.lock().unwrap();
        stats.pending_count = 0;
    }

    /// Check if we have pending messages for a server
    pub async fn has_pending_for_server(&self, server_id: ServerId) -> bool {
        let queue = self.pending_messages.lock().unwrap();
        queue.get(&server_id)
            .map(|q| !q.is_empty())
            .unwrap_or(false)
    }

    /// Get count of pending messages for all servers
    pub async fn pending_counts(&self) -> HashMap<ServerId, usize> {
        let queue = self.pending_messages.lock().unwrap();
        queue.iter()
            .map(|(sid, q)| (*sid, q.len()))
            .collect()
    }
}
