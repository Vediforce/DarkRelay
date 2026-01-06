use std::collections::HashMap;
use darkrelayprotocol::protocol::UserId;

/// Represents a federated user identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FederatedUserId {
    pub user_id: UserId,
    pub server_id: Option<u64>,  // None for local users
}

impl FederatedUserId {
    pub fn new(user_id: UserId, server_id: Option<u64>) -> Self {
        Self { user_id, server_id }
    }

    pub fn local(user_id: UserId) -> Self {
        Self { user_id, server_id: None }
    }

    pub fn federated(user_id: UserId, server_id: u64) -> Self {
        Self { user_id: user_id, server_id: Some(server_id) }
    }

    pub fn is_federated(&self) -> bool {
        self.server_id.is_some()
    }

    pub fn display_name(&self, username: &str) -> String {
        match self.server_id {
            Some(server_id) => format!("{}@{}", username, server_id),
            None => username.to_string(),
        }
    }
}

/// Parse a username that might be federated (e.g., "alice" or "bob@123")
pub fn parse_federated_username(input: &str) -> (String, Option<u64>) {
    if let Some(at_pos) = input.rfind('@') {
        let username = input[..at_pos].to_string();
        let server_part = &input[at_pos + 1..];
        
        if let Ok(server_id) = server_part.parse::<u64>() {
            return (username, Some(server_id));
        }
    }
    (input.to_string(), None)
}

#[derive(Debug, Clone)]
pub struct FederatedStoredDM {
    pub dm_id: u64,
    pub sender_id: UserId,
    pub sender_server_id: Option<u64>,
    pub sender_username: String,
    pub recipient_id: UserId,
    pub recipient_server_id: Option<u64>,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_read: bool,
}

pub struct DMHandler {
    conversations: HashMap<FederatedUserId, Vec<FederatedStoredDM>>,
    unread_counts: HashMap<FederatedUserId, usize>,
    active_conversation: Option<FederatedUserId>,
    // Track username by user_id for display
    usernames: HashMap<(UserId, Option<u64>), String>,
}

impl DMHandler {
    pub fn new() -> Self {
        Self {
            conversations: HashMap::new(),
            unread_counts: HashMap::new(), 
            active_conversation: None,
            usernames: HashMap::new(),
        }
    }

    pub fn add_dm(&mut self, dm: FederatedStoredDM) {
        let sender_key = FederatedUserId::new(dm.sender_id, dm.sender_server_id);
        
        // Track username
        self.usernames.insert(
            (dm.sender_id, dm.sender_server_id), 
            dm.sender_username.clone()
        );

        let conversation = self.conversations.entry(sender_key.clone()).or_insert_with(Vec::new);
        
        if !conversation.iter().any(|existing| existing.dm_id == dm.dm_id) {
            conversation.push(dm.clone());
        }
        
        if self.active_conversation.as_ref() != Some(&sender_key) {
            *self.unread_counts.entry(sender_key.clone()).or_insert(0) += 1;
        }
    }

    pub fn set_active_conversation(&mut self, user_id: FederatedUserId) {
        self.active_conversation = Some(user_id.clone());
        self.unread_counts.insert(user_id, 0);
    }

    pub fn clear_active_conversation(&mut self) {
        self.active_conversation = None;
    }

    pub fn get_conversations(&self) -> impl Iterator<Item = (&FederatedUserId, &Vec<FederatedStoredDM>)> {
        self.conversations.iter()
    }

    pub fn get_unread_count(&self, user_id: &FederatedUserId) -> usize {
        self.unread_counts.get(user_id).copied().unwrap_or(0)
    }

    pub fn get_total_unread_count(&self) -> usize {
        self.unread_counts.values().sum()
    }

    pub fn get_conversation(&self, user_id: &FederatedUserId) -> Option<&Vec<FederatedStoredDM>> {
        self.conversations.get(user_id)
    }

    pub fn get_username(&self, user_id: UserId, server_id: Option<u64>) -> Option<String> {
        self.usernames.get(&(user_id, server_id)).cloned()
    }

    pub fn add_history(&mut self, user_id: FederatedUserId, messages: Vec<FederatedStoredDM>) {
        let conversation = self.conversations.entry(user_id.clone()).or_insert_with(Vec::new);
        
        for message in messages {
            self.usernames.insert(
                (message.sender_id, message.sender_server_id),
                message.sender_username.clone()
            );
            
            if !conversation.iter().any(|existing| existing.dm_id == message.dm_id) {
                conversation.push(message);
            }
        }
        
        conversation.sort_by_key(|m| m.timestamp);
    }

    pub fn mark_dm_as_read(&mut self, dm_id: u64, recipient_id: UserId, recipient_server_id: Option<u64>) -> bool {
        let key = FederatedUserId::new(recipient_id, recipient_server_id);
        if let Some(conversation) = self.conversations.get_mut(&key) {
            for dm in conversation.iter_mut() {
                if dm.dm_id == dm_id {
                    dm.is_read = true;
                    return true;
                }
            }
        }
        false
    }

    /// Get a conversation key from a username (local or federated)
    pub fn get_conversation_key(&self, username: &str) -> Option<FederatedUserId> {
        let (username_only, server_id) = parse_federated_username(username);
        
        // Look up the user_id from username
        // This would need to be populated from server responses
        for ((user_id, srv_id), name) in &self.usernames {
            if name == &username_only && *srv_id == server_id {
                return Some(FederatedUserId::new(*user_id, *srv_id));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_federated_username() {
        assert_eq!(parse_federated_username("alice"), ("alice".to_string(), None));
        assert_eq!(parse_federated_username("bob@123"), ("bob".to_string(), Some(123)));
        assert_eq!(parse_federated_username("charlie@server-456"), ("charlie".to_string(), None)); // non-numeric server
    }

    #[test]
    fn test_federated_user_id_display() {
        let local = FederatedUserId::local(1);
        assert_eq!(local.display_name("alice"), "alice");

        let fed = FederatedUserId::federated(2, 100);
        assert_eq!(fed.display_name("bob"), "bob@100");
    }
}
