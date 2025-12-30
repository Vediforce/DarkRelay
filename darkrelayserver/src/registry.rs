use std::collections::HashMap;

use darkrelayprotocol::protocol::{ServerMessage, UserInfo};
use tokio::sync::mpsc;

use crate::channel::ClientId;

#[derive(Clone)]
pub struct ClientHandle {
    pub id: ClientId,
    pub user: Option<UserInfo>,
    pub current_channel: Option<String>,
    pub sender: mpsc::UnboundedSender<ServerMessage>,
}

pub struct Registry {
    clients: HashMap<ClientId, ClientHandle>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    pub fn register(&mut self, id: ClientId, sender: mpsc::UnboundedSender<ServerMessage>) {
        self.clients.insert(
            id,
            ClientHandle {
                id,
                user: None,
                current_channel: None,
                sender,
            },
        );
    }

    pub fn set_user(&mut self, id: ClientId, user: UserInfo) {
        if let Some(h) = self.clients.get_mut(&id) {
            h.user = Some(user);
        }
    }

    pub fn user(&self, id: ClientId) -> Option<UserInfo> {
        self.clients.get(&id).and_then(|h| h.user.clone())
    }

    pub fn set_channel(&mut self, id: ClientId, channel: Option<String>) {
        if let Some(h) = self.clients.get_mut(&id) {
            h.current_channel = channel;
        }
    }

    pub fn channel(&self, id: ClientId) -> Option<String> {
        self.clients
            .get(&id)
            .and_then(|h| h.current_channel.clone())
    }

    pub fn sender(&self, id: ClientId) -> Option<mpsc::UnboundedSender<ServerMessage>> {
        self.clients.get(&id).map(|h| h.sender.clone())
    }

    pub fn remove(&mut self, id: ClientId) {
        self.clients.remove(&id);
    }

    pub fn send(&self, id: ClientId, msg: ServerMessage) {
        if let Some(h) = self.clients.get(&id) {
            let _ = h.sender.send(msg);
        }
    }

    pub fn send_many(&self, ids: &[ClientId], msg: &ServerMessage) {
        for id in ids {
            self.send(*id, msg.clone());
        }
    }

    pub fn find_clients_by_user_id(&self, user_id: u64) -> Vec<ClientId> {
        self.clients
            .values()
            .filter_map(|h| {
                if let Some(ref user) = h.user {
                    if user.id == user_id {
                        return Some(h.id);
                    }
                }
                None
            })
            .collect()
    }
}
