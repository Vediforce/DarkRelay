use chrono::{DateTime, Duration, Utc};
use darkrelayprotocol::protocol::{BanInfo, ChannelId, UserId};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Ban {
    pub user_id: UserId,
    pub username: String,
    pub banned_until: Option<DateTime<Utc>>,
    pub banned_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Default)]
pub struct BanManager {
    bans: HashMap<ChannelId, HashMap<UserId, Ban>>,
}

impl BanManager {
    pub fn new() -> Self {
        Self {
            bans: HashMap::new(),
        }
    }

    pub fn ban_user(
        &mut self,
        channel_id: ChannelId,
        user_id: UserId,
        username: String,
        banned_by: String,
        duration_seconds: Option<u64>,
        reason: Option<String>,
    ) -> Option<DateTime<Utc>> {
        let banned_until = duration_seconds.map(|secs| Utc::now() + Duration::seconds(secs as i64));

        let ban = Ban {
            user_id,
            username,
            banned_until,
            banned_by,
            reason,
        };

        self.bans
            .entry(channel_id)
            .or_insert_with(HashMap::new)
            .insert(user_id, ban);

        banned_until
    }

    pub fn unban_user(&mut self, channel_id: ChannelId, user_id: UserId) -> bool {
        if let Some(channel_bans) = self.bans.get_mut(&channel_id) {
            channel_bans.remove(&user_id).is_some()
        } else {
            false
        }
    }

    pub fn is_banned(&self, channel_id: ChannelId, user_id: UserId) -> bool {
        if let Some(channel_bans) = self.bans.get(&channel_id) {
            if let Some(ban) = channel_bans.get(&user_id) {
                match ban.banned_until {
                    Some(until) => until > Utc::now(),
                    None => true,
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn get_ban_info(&self, channel_id: ChannelId, user_id: UserId) -> Option<&Ban> {
        self.bans.get(&channel_id)?.get(&user_id)
    }

    pub fn list_bans(&self, channel_id: ChannelId) -> Vec<BanInfo> {
        if let Some(channel_bans) = self.bans.get(&channel_id) {
            channel_bans
                .values()
                .filter(|ban| match ban.banned_until {
                    Some(until) => until > Utc::now(),
                    None => true,
                })
                .map(|ban| BanInfo {
                    user_id: ban.user_id,
                    username: ban.username.clone(),
                    banned_until: ban.banned_until,
                    banned_by: ban.banned_by.clone(),
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        for channel_bans in self.bans.values_mut() {
            channel_bans.retain(|_, ban| {
                match ban.banned_until {
                    Some(until) => until > now,
                    None => true,
                }
            });
        }
    }
}
