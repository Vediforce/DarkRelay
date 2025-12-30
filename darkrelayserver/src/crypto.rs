use std::collections::HashMap;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;

use crate::channel::ClientId;

pub struct EcdhManager {
    secrets: HashMap<ClientId, SharedSecret>,
}

impl EcdhManager {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Generate ephemeral keypair, store secret, return public key.
    pub fn generate_keypair(&mut self, client_id: ClientId, client_public_key: &[u8]) -> Result<Vec<u8>, String> {
        if client_public_key.len() != 32 {
            return Err("invalid public key length".to_string());
        }

        let client_public = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(client_public_key);
            PublicKey::from(bytes)
        };

        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        
        let shared_secret = server_secret.diffie_hellman(&client_public);
        
        self.secrets.insert(client_id, shared_secret);
        
        Ok(server_public.as_bytes().to_vec())
    }

    pub fn get_shared_secret(&self, client_id: ClientId) -> Option<&SharedSecret> {
        self.secrets.get(&client_id)
    }

    pub fn remove(&mut self, client_id: ClientId) {
        self.secrets.remove(&client_id);
    }
}
