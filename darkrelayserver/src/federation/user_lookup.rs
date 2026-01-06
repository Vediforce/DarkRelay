use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use darkrelayprotocol::federation::{
    FederatedUser, ResolveUser, UserNotFound, UserResolved, ServerId,
    FEDERATION_CACHE_TTL_SECS,
};

pub struct UserDirectory {
    local_users: Arc<Mutex<HashMap<String, u64>>>,  // username -> user_id
    cached_remote_users: Arc<Mutex<HashMap<String, FederatedUser>>>,  // "username@server_id" -> info
    next_request_id: Arc<Mutex<u64>>,
}

impl UserDirectory {
    pub fn new() -> Self {
        Self {
            local_users: Arc::new(Mutex::new(HashMap::new())),
            cached_remote_users: Arc::new(Mutex::new(HashMap::new())),
            next_request_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Register a local user
    pub async fn register_local_user(&self, username: &str, user_id: u64) {
        let mut users = self.local_users.lock().await;
        users.insert(username.to_lowercase(), user_id);
        debug!(username, user_id, "registered local user");
    }

    /// Look up a local user by username
    pub async fn find_local_user(&self, username: &str) -> Option<u64> {
        let users = self.local_users.lock().await;
        users.get(&username.to_lowercase()).copied()
    }

    /// Check if a username belongs to a remote server (contains @server_id or @servername)
    pub fn parse_federated_username(&self, full_username: &str) -> (String, Option<ServerId>, Option<String>) {
        if let Some(at_pos) = full_username.rfind('@') {
            let username = full_username[..at_pos].to_string();
            let server_part = &full_username[at_pos + 1..];

            // Try to parse as numeric server_id first
            if let Ok(server_id) = server_part.parse::<ServerId>() {
                return (username, Some(server_id), None);
            }

            // Otherwise it's a server name
            return (username, None, Some(server_part.to_string()));
        }
        (full_username.to_string(), None, None)
    }

    /// Check if this is a federated address (not on our server)
    pub async fn is_remote_user(&self, full_username: &str, our_server_id: ServerId) -> bool {
        let (username, server_id, _server_name) = self.parse_federated_username(full_username);
        
        // Check if it's just a local username (no @)
        if server_id.is_none() && _server_name.is_none() {
            // Check if user exists locally
            if self.find_local_user(&username).await.is_some() {
                return false;
            }
            // User doesn't exist locally, could be remote
            return true;
        }

        // Has server qualifier, check if it's our server
        if let Some(sid) = server_id {
            return sid != our_server_id;
        }

        // Server name qualifier - assume remote for now
        true
    }

    /// Cache a remote user lookup result
    pub async fn cache_remote_user(&self, user: FederatedUser) {
        let key = format!("{}@{}", user.username, user.server_id);
        let mut cache = self.cached_remote_users.lock().await;
        cache.insert(key, user);
        debug!(key = %key, "cached remote user");
    }

    /// Get cached remote user
    pub async fn get_cached_remote_user(&self, username: &str, server_id: ServerId) -> Option<FederatedUser> {
        let key = format!("{}@{}", username, server_id);
        let cache = self.cached_remote_users.lock().await;
        cache.get(&key).cloned()
    }

    /// Check if cached user is still valid (within TTL)
    pub async fn is_cache_valid(&self, username: &str, server_id: ServerId) -> bool {
        if let Some(user) = self.get_cached_remote_user(username, server_id).await {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            return now - user.last_seen < FEDERATION_CACHE_TTL_SECS;
        }
        false
    }

    /// Create a ResolveUser request for looking up a user on another server
    pub async fn create_resolve_request(&self, username: &str) -> ResolveUser {
        ResolveUser {
            username: username.to_string(),
        }
    }

    /// Process a UserResolved response
    pub async fn process_user_resolved(&self, response: &UserResolved) -> FederatedUser {
        let user = FederatedUser {
            local_id: Some(response.user_id),
            username: response.username.clone(),
            server_id: response.server_id,
            server_name: format!("server-{}", response.server_id),
            is_online: response.is_online,
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.cache_remote_user(user.clone()).await;
        user
    }

    /// Process a UserNotFound response
    pub async fn process_user_not_found(&self, username: &str, server_id: ServerId) {
        // Cache negative result briefly
        let key = format!("{}@{}", username, server_id);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let user = FederatedUser {
            local_id: None,
            username: username.to_string(),
            server_id,
            server_name: format!("server-{}", server_id),
            is_online: false,
            last_seen: now,
        };

        let mut cache = self.cached_remote_users.lock().await;
        cache.insert(key, user);
    }

    /// Update user online status from federation
    pub async fn update_remote_user_status(&self, username: &str, server_id: ServerId, is_online: bool) {
        if let Some(mut user) = self.get_cached_remote_user(username, server_id).await {
            user.is_online = is_online;
            user.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.cache_remote_user(user).await;
        }
    }

    /// Generate cache key for federated username
    pub fn cache_key(&self, username: &str, server_id: ServerId) -> String {
        format!("{}@{}", username, server_id)
    }

    /// Cleanup expired cache entries
    pub async fn cleanup_expired_cache(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut cache = self.cached_remote_users.lock().await;
        let expired: Vec<String> = cache.iter()
            .filter(|(_, user)| now - user.last_seen > FEDERATION_CACHE_TTL_SECS)
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired {
            cache.remove(&key);
        }

        if !expired.is_empty() {
            debug!(count = expired.len(), "cleaned up expired user cache entries");
        }
    }

    /// Get next request ID for tracking requests
    pub async fn next_request_id(&self) -> u64 {
        let mut id = self.next_request_id.lock().await;
        let current = *id;
        *id += 1;
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_user_registration() {
        let dir = UserDirectory::new();
        dir.register_local_user("alice", 1).await;
        
        assert_eq!(dir.find_local_user("alice").await, Some(1));
        assert_eq!(dir.find_local_user("ALICE").await, Some(1)); // case insensitive
        assert_eq!(dir.find_local_user("bob").await, None);
    }

    #[tokio::test]
    async fn test_parse_federated_username() {
        let dir = UserDirectory::new();
        
        // Local user
        let (username, server_id, server_name) = dir.parse_federated_username("alice");
        assert_eq!(username, "alice");
        assert!(server_id.is_none());
        assert!(server_name.is_none());

        // Federated with server ID
        let (username, server_id, server_name) = dir.parse_federated_username("bob@123");
        assert_eq!(username, "bob");
        assert_eq!(server_id, Some(123));
        assert!(server_name.is_none());

        // Federated with server name
        let (username, server_id, server_name) = dir.parse_federated_username("charlie@relay-node-1");
        assert_eq!(username, "charlie");
        assert!(server_id.is_none());
        assert_eq!(server_name, Some("relay-node-1".to_string()));
    }

    #[tokio::test]
    async fn test_remote_user_caching() {
        let dir = UserDirectory::new();
        
        let user = FederatedUser {
            local_id: Some(42),
            username: "bob".to_string(),
            server_id: 100,
            server_name: "test-server".to_string(),
            is_online: true,
            last_seen: 0,
        };

        dir.cache_remote_user(user).await;
        assert!(dir.is_cache_valid("bob", 100).await);
        
        let cached = dir.get_cached_remote_user("bob", 100).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().local_id, Some(42));
    }
}
