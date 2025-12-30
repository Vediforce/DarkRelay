use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Role {
    User = 0,
    Moderator = 1,
    Admin = 2,
    SuperAdmin = 3,
}

impl Role {
    pub fn default_permissions(&self) -> HashSet<Permission> {
        match self {
            Role::User => {
                let mut perms = HashSet::new();
                perms.insert(Permission::SendMessage);
                perms
            }
            Role::Moderator => {
                let mut perms = HashSet::new();
                perms.insert(Permission::SendMessage);
                perms.insert(Permission::DeleteMessage);
                perms.insert(Permission::KickUser);
                perms.insert(Permission::MuteUser);
                perms
            }
            Role::Admin => {
                let mut perms = HashSet::new();
                perms.insert(Permission::SendMessage);
                perms.insert(Permission::DeleteMessage);
                perms.insert(Permission::KickUser);
                perms.insert(Permission::MuteUser);
                perms.insert(Permission::ManageChannel);
                perms.insert(Permission::BanUser);
                perms.insert(Permission::PromoteUser);
                perms.insert(Permission::ViewLogs);
                perms
            }
            Role::SuperAdmin => {
                let mut perms = HashSet::new();
                perms.insert(Permission::SendMessage);
                perms.insert(Permission::DeleteMessage);
                perms.insert(Permission::ManageChannel);
                perms.insert(Permission::BanUser);
                perms.insert(Permission::KickUser);
                perms.insert(Permission::MuteUser);
                perms.insert(Permission::PromoteUser);
                perms.insert(Permission::ViewLogs);
                perms.insert(Permission::ManageRoles);
                perms
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    SendMessage,
    DeleteMessage,
    ManageChannel,
    BanUser,
    KickUser,
    MuteUser,
    PromoteUser,
    ViewLogs,
    ManageRoles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermissions {
    pub role: Role,
    pub permissions: HashSet<Permission>,
}

impl RolePermissions {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            permissions: role.default_permissions(),
        }
    }

    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }
}

pub fn has_permission(role: Role, permission: Permission) -> bool {
    role.default_permissions().contains(&permission)
}
