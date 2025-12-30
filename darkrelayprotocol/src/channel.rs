use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ChannelType {
    Public = 0,
    Private = 1,
    AdminOnly = 2,
    ReadOnly = 3,
    Announcement = 4,
}

impl Default for ChannelType {
    fn default() -> Self {
        ChannelType::Public
    }
}

impl ChannelType {
    pub fn description(&self) -> &'static str {
        match self {
            ChannelType::Public => "Anyone can join (with password), all can send",
            ChannelType::Private => "Invite-only",
            ChannelType::AdminOnly => "All can see, only admins can send messages",
            ChannelType::ReadOnly => "All can read, only admins send",
            ChannelType::Announcement => "SuperAdmin broadcasts only",
        }
    }
}
