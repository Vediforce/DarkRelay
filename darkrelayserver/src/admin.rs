use chrono::Utc;
use darkrelayprotocol::{
    channel::ChannelType,
    permissions::{has_permission, Permission, Role},
    protocol::{AdminInfo, ChannelId, LogEntry, UserId},
};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct AdminManager {
    channel_roles: HashMap<ChannelId, HashMap<UserId, Role>>,
    channel_types: HashMap<ChannelId, ChannelType>,
    logs: HashMap<ChannelId, Vec<LogEntry>>,
}

impl AdminManager {
    pub fn new() -> Self {
        Self {
            channel_roles: HashMap::new(),
            channel_types: HashMap::new(),
            logs: HashMap::new(),
        }
    }

    pub fn set_channel_creator(&mut self, channel_id: ChannelId, user_id: UserId) {
        self.channel_roles
            .entry(channel_id)
            .or_insert_with(HashMap::new)
            .insert(user_id, Role::Admin);
    }

    pub fn get_role(&self, channel_id: ChannelId, user_id: UserId) -> Role {
        self.channel_roles
            .get(&channel_id)
            .and_then(|roles| roles.get(&user_id))
            .copied()
            .unwrap_or(Role::User)
    }

    pub fn set_role(&mut self, channel_id: ChannelId, user_id: UserId, role: Role) {
        self.channel_roles
            .entry(channel_id)
            .or_insert_with(HashMap::new)
            .insert(user_id, role);
    }

    pub fn has_permission(&self, channel_id: ChannelId, user_id: UserId, permission: Permission) -> bool {
        let role = self.get_role(channel_id, user_id);
        has_permission(role, permission)
    }

    pub fn can_send_message(&self, channel_id: ChannelId, user_id: UserId) -> bool {
        let role = self.get_role(channel_id, user_id);
        let channel_type = self.get_channel_type(channel_id);

        match channel_type {
            ChannelType::Public | ChannelType::Private => {
                has_permission(role, Permission::SendMessage)
            }
            ChannelType::AdminOnly | ChannelType::ReadOnly => {
                role >= Role::Admin
            }
            ChannelType::Announcement => {
                role >= Role::SuperAdmin
            }
        }
    }

    pub fn list_admins(&self, channel_id: ChannelId, user_map: &HashMap<UserId, String>) -> Vec<AdminInfo> {
        if let Some(roles) = self.channel_roles.get(&channel_id) {
            roles
                .iter()
                .filter(|(_, role)| **role >= Role::Moderator)
                .filter_map(|(user_id, role)| {
                    user_map.get(user_id).map(|username| AdminInfo {
                        user_id: *user_id,
                        username: username.clone(),
                        role: *role,
                    })
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn set_channel_type(&mut self, channel_id: ChannelId, channel_type: ChannelType) {
        self.channel_types.insert(channel_id, channel_type);
    }

    pub fn get_channel_type(&self, channel_id: ChannelId) -> ChannelType {
        self.channel_types
            .get(&channel_id)
            .copied()
            .unwrap_or(ChannelType::Public)
    }

    pub fn log_action(
        &mut self,
        channel_id: ChannelId,
        user_id: UserId,
        username: String,
        action: String,
        target: String,
        details: String,
    ) {
        let entry = LogEntry {
            timestamp: Utc::now(),
            user_id,
            username,
            action,
            target,
            details,
        };

        self.logs
            .entry(channel_id)
            .or_insert_with(Vec::new)
            .push(entry);

        if let Some(logs) = self.logs.get_mut(&channel_id) {
            if logs.len() > 1000 {
                logs.drain(0..(logs.len() - 1000));
            }
        }
    }

    pub fn get_logs(&self, channel_id: ChannelId, limit: usize) -> Vec<LogEntry> {
        if let Some(logs) = self.logs.get(&channel_id) {
            logs.iter().rev().take(limit).cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn remove_channel(&mut self, channel_id: ChannelId) {
        self.channel_roles.remove(&channel_id);
        self.channel_types.remove(&channel_id);
        self.logs.remove(&channel_id);
    }
}
