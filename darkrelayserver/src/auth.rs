use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};

use darkrelayprotocol::protocol::{UserId, UserInfo};

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub user: UserInfo,

    /// Phase 1: stored in-memory as a string.
    pub password: String,
}

#[derive(Debug, Default)]
pub struct AuthService {
    users_by_name: HashMap<String, UserRecord>,
    next_user_id: UserId,
}

impl AuthService {
    pub fn new() -> Self {
        Self {
            users_by_name: HashMap::new(),
            next_user_id: 1,
        }
    }

    pub fn verify_special_key(&self, expected: &str, candidate: &str) -> bool {
        expected == candidate
    }

    pub fn register(&mut self, username: String) -> Result<(UserInfo, String), String> {
        let username = username.trim().to_string();
        if username.is_empty() {
            return Err("username cannot be empty".to_string());
        }

        if self.users_by_name.contains_key(&username) {
            return Err("username already exists".to_string());
        }

        let user_id = self.next_user_id;
        self.next_user_id += 1;

        let joined_at: DateTime<Utc> = Utc::now();
        let user = UserInfo {
            id: user_id,
            username: username.clone(),
            joined_at,
        };

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let password = format!("dr-{}-{}", nanos, user_id);

        self.users_by_name.insert(
            username,
            UserRecord {
                user: user.clone(),
                password: password.clone(),
            },
        );

        Ok((user, password))
    }

    pub fn login(&self, username: &str, password: &str) -> Result<UserInfo, String> {
        let rec = self
            .users_by_name
            .get(username)
            .ok_or_else(|| "user not found".to_string())?;

        if rec.password != password {
            return Err("invalid password".to_string());
        }

        Ok(rec.user.clone())
    }
}
