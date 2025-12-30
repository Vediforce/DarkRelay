use std::io;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

pub struct CryptoState {
    pub ecdh_secret: Option<SharedSecret>,
    channel_keys: std::collections::HashMap<String, [u8; 32]>,
    message_counter: u64,
}

impl CryptoState {
    pub fn new() -> Self {
        Self {
            ecdh_secret: None,
            channel_keys: std::collections::HashMap::new(),
            message_counter: 0,
        }
    }

    /// Generate ephemeral keypair and return public key.
    pub fn generate_keypair(&mut self) -> Vec<u8> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let public_bytes = public.as_bytes().to_vec();
        
        // Store the secret temporarily - we'll derive shared secret when we get server's key
        // For now, we'll use a different approach: return both
        // Actually, we need to store the secret until we receive server's public key
        // Let's use a thread-local or just regenerate... no, we need to keep it
        // Let me use a different approach: store in self
        
        // This is tricky because EphemeralSecret is not Clone/Copy
        // Let's store the shared secret after we compute it in complete_handshake
        
        // For now, just return the public key
        // We'll pass the secret to complete_handshake
        
        public_bytes
    }

    /// Complete ECDH handshake with server's public key.
    pub fn complete_handshake(&mut self, server_public_key: &[u8], client_secret: EphemeralSecret) -> Result<(), String> {
        if server_public_key.len() != 32 {
            return Err("invalid server public key length".to_string());
        }

        let server_public = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(server_public_key);
            PublicKey::from(bytes)
        };

        let shared_secret = client_secret.diffie_hellman(&server_public);
        self.ecdh_secret = Some(shared_secret);
        
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.ecdh_secret.is_some()
    }

    /// Derive channel key from password using PBKDF2.
    pub fn set_channel_key(&mut self, channel: &str, password: Option<&str>) {
        if let Some(pwd) = password {
            let salt = format!("darkrelay-channel-{}", channel);
            let key = pbkdf2_hmac_array::<Sha256, 32>(pwd.as_bytes(), salt.as_bytes(), 100_000);
            self.channel_keys.insert(channel.to_string(), key);
        }
    }

    /// Encrypt plaintext with ECDH shared secret + optional channel key.
    /// Returns (ciphertext, nonce).
    pub fn encrypt(&mut self, plaintext: &[u8], channel: Option<&str>) -> io::Result<(Vec<u8>, Vec<u8>)> {
        // Add padding
        let padded = darkrelayprotocol::crypto::add_padding(plaintext);

        // Generate nonce first before borrowing
        let nonce_bytes = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Now get shared secret
        let shared_secret = self.ecdh_secret.as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "ECDH not complete"))?;
        
        let cipher = Aes256Gcm::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        
        let mut ciphertext = cipher.encrypt(nonce, padded.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encryption failed: {:?}", e)))?;

        // Second layer: if channel key exists, encrypt again
        if let Some(ch) = channel {
            if let Some(channel_key) = self.channel_keys.get(ch) {
                let channel_cipher = Aes256Gcm::new_from_slice(channel_key)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
                
                // Use a different nonce for channel encryption
                let channel_nonce_bytes = self.next_nonce();
                let channel_nonce = Nonce::from_slice(&channel_nonce_bytes);
                
                ciphertext = channel_cipher.encrypt(channel_nonce, ciphertext.as_slice())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("channel encryption failed: {:?}", e)))?;
            }
        }

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypt ciphertext with ECDH shared secret + optional channel key.
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], channel: Option<&str>) -> io::Result<Vec<u8>> {
        let shared_secret = self.ecdh_secret.as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "ECDH not complete"))?;

        if nonce.len() != 12 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid nonce length"));
        }

        let data = ciphertext.to_vec();

        // If channel key exists, decrypt that layer first
        if let Some(ch) = channel {
            if let Some(_channel_key) = self.channel_keys.get(ch) {
                // TODO: Implement double-layer decryption
                // let _channel_cipher = Aes256Gcm::new_from_slice(channel_key)
                //     .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                
                // We need to derive/store the channel nonce too
                // For now, skip double encryption and just do ECDH layer
                // TODO: Implement proper double-layer decryption
            }
        }

        // Decrypt with ECDH shared secret
        let nonce_array = Nonce::from_slice(nonce);
        
        let cipher = Aes256Gcm::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        
        let padded = cipher.decrypt(nonce_array, data.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("decryption failed: {:?}", e)))?;

        // Remove padding
        darkrelayprotocol::crypto::remove_padding(&padded)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let counter = self.message_counter;
        self.message_counter += 1;
        
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    pub fn reset(&mut self) {
        self.ecdh_secret = None;
        self.channel_keys.clear();
        self.message_counter = 0;
    }
}

/// Helper to hold the ephemeral secret until handshake completes.
pub struct EcdhHandshake {
    secret: Option<EphemeralSecret>,
    public_key: Vec<u8>,
}

impl EcdhHandshake {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let public_key = public.as_bytes().to_vec();
        
        Self {
            secret: Some(secret),
            public_key,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn complete(mut self, server_public_key: &[u8]) -> Result<SharedSecret, String> {
        if server_public_key.len() != 32 {
            return Err("invalid server public key length".to_string());
        }

        let server_public = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(server_public_key);
            PublicKey::from(bytes)
        };

        let secret = self.secret.take()
            .ok_or_else(|| "handshake already completed".to_string())?;

        Ok(secret.diffie_hellman(&server_public))
    }
}
