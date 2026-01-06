use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use tracing::{debug, info, warn, error};

use darkrelayprotocol::federation::{ServerIntro, ServerAck, FederationStatus, ServerId};

pub struct FederationHandshake {
    pending_handshakes: Arc<Mutex<HashMap<ServerId, PendingHandshake>>>,
    completed_secrets: Arc<Mutex<HashMap<ServerId, SharedSecret>>>,
}

struct PendingHandshake {
    server_id: ServerId,
    server_name: String,
    their_public_key: Vec<u8>,
    our_public_key: Vec<u8>,
    our_private_key: EphemeralSecret,
    created_at: u64,
}

impl FederationHandshake {
    pub fn new() -> Self {
        Self {
            pending_handshakes: Arc::new(Mutex::new(HashMap::new())),
            completed_secrets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate our half of the handshake for initiating connection
    pub async fn initiate_handshake(
        &self,
        server_id: ServerId,
        server_name: String,
    ) -> Result<(Vec<u8>, ServerIntro), String> {
        let private_key = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        let our_public = public_key.as_bytes().to_vec();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let intro = ServerIntro {
            server_id,
            server_name,
            server_version: "1.0.0".to_string(),
            public_key: our_public.clone(),
            timestamp,
            protocol_version: 1,
        };

        let pending = PendingHandshake {
            server_id,
            server_name: intro.server_name.clone(),
            their_public_key: Vec::new(),
            our_public_key: our_public.clone(),
            our_private_key: private_key,
            created_at: timestamp,
        };

        let mut pending_map = self.pending_handshakes.lock().await;
        pending_map.insert(server_id, pending);

        Ok((our_public, intro))
    }

    /// Complete handshake when we receive ServerAck
    pub async fn complete_handshake(
        &self,
        server_id: ServerId,
        ack: &ServerAck,
    ) -> Result<SharedSecret, String> {
        let mut pending_map = self.pending_handshakes.lock().await;
        
        let pending = match pending_map.remove(&server_id) {
            Some(p) => p,
            None => return Err("no pending handshake for this server".to_string()),
        };

        // Verify the server acknowledged with our public key
        if ack.public_key != pending.our_public_key {
            return Err("server sent wrong public key".to_string());
        }

        // Derive shared secret using their public key
        let their_public = {
            let mut bytes = [0u8; 32];
            if ack.public_key.len() != 32 {
                return Err("invalid public key length".to_string());
            }
            bytes.copy_from_slice(&ack.public_key);
            PublicKey::from(bytes)
        };

        let shared_secret = pending.our_private_key.diffie_hellman(&their_public);

        // Store the completed secret
        let mut secrets = self.completed_secrets.lock().await;
        secrets.insert(server_id, shared_secret.clone());

        info!(server_id, "federation handshake completed successfully");

        Ok(shared_secret)
    }

    /// Generate ServerAck for incoming connection
    pub async fn create_server_ack(
        &self,
        intro: &ServerIntro,
        server_id: ServerId,
        server_name: String,
    ) -> Result<ServerAck, String> {
        let private_key = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        let our_public = public_key.as_bytes().to_vec();

        // Store pending handshake to complete when we receive their ack
        let pending = PendingHandshake {
            server_id,
            server_name: intro.server_name.clone(),
            their_public_key: intro.public_key.clone(),
            our_public_key: our_public.clone(),
            our_private_key: private_key,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let mut pending_map = self.pending_handshakes.lock().await;
        pending_map.insert(server_id, pending);

        Ok(ServerAck {
            server_id,
            status: FederationStatus::Connected,
            server_name,
            server_version: "1.0.0".to_string(),
            public_key: our_public,
            protocol_version: 1,
        })
    }

    pub fn get_shared_secret(&self, server_id: ServerId) -> Option<SharedSecret> {
        futures::runtime::Handle::current().block_on(async {
            self.completed_secrets.lock().await.get(&server_id).cloned()
        })
    }

    pub async fn get_shared_secret_async(&self, server_id: ServerId) -> Option<SharedSecret> {
        let secrets = self.completed_secrets.lock().await;
        secrets.get(&server_id).cloned()
    }

    pub fn remove_secret(&self, server_id: ServerId) {
        futures::runtime::Handle::current().block_on(async {
            self.completed_secrets.lock().await.remove(&server_id);
        });
    }

    pub async fn cleanup_expired(&self, max_age_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut pending_map = self.pending_handshakes.lock().await;
        let expired: Vec<ServerId> = pending_map.iter()
            .filter(|(_, p)| now - p.created_at > max_age_secs)
            .map(|(id, _)| *id)
            .collect();

        for id in expired {
            pending_map.remove(&id);
            debug!(server_id = id, "removed expired federation handshake");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handshake_initiate() {
        let handshake = FederationHandshake::new();
        let result = handshake.initiate_handshake(1, "test-server".to_string()).await;
        
        assert!(result.is_ok());
        let (public_key, intro) = result.unwrap();
        assert_eq!(intro.server_id, 1);
        assert_eq!(intro.server_name, "test-server");
        assert_eq!(public_key.len(), 32);
    }
}
