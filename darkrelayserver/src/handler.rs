use std::{
    io,
    sync::Arc,
    time::Duration,
};

use bincode;
use chrono::Utc;
use darkrelayprotocol::{
    permissions::Permission,
    protocol::{
        ChatMessage, ClientMessage, MessageMeta, ServerMessage,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{broadcast, mpsc},
    time,
};
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};

use crate::{AppState, channel::ClientId};

pub async fn handle_client(
    state: Arc<AppState>,
    client_id: ClientId,
    socket: TlsStream<tokio::net::TcpStream>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(socket);

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerMessage>();

    {
        let mut reg = state.registry.write().await;
        reg.register(client_id, out_tx);
    }

    let writer_state = Arc::clone(&state);
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if let Err(e) = write_frame(&mut writer, &msg).await {
                debug!(client_id, error = %e, "writer task exiting");
                break;
            }
        }
        let mut reg = writer_state.registry.write().await;
        reg.remove(client_id);
    });

    let challenge = ServerMessage::AuthChallenge {
        meta: server_meta(&state),
        message: "special auth key required".to_string(),
    };
    {
        let reg = state.registry.read().await;
        reg.send(client_id, challenge);
    }

    let mut special_authed = false;
    let mut user_authed = false;
    let mut ecdh_complete = false;

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!(client_id, "shutdown requested");
                break;
            }
            msg_res = read_frame::<ClientMessage, _>(&mut reader) => {
                let msg = match msg_res {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(client_id, error = %e, "read failed, disconnecting");
                        break;
                    }
                };

                match msg {
                    ClientMessage::Connect{..} => {
                        // no-op for now
                    }
                    ClientMessage::Auth{ key, .. } => {
                        let ok = {
                            let auth = state.auth.read().await;
                            auth.verify_special_key(&state.special_key, &key)
                        };

                        if !ok {
                            let failure = ServerMessage::AuthFailure { meta: server_meta(&state), reason: "invalid special key".to_string() };
                            let reg = state.registry.read().await;
                            reg.send(client_id, failure);
                            break;
                        }

                        special_authed = true;
                        let sys = ServerMessage::SystemMessage { meta: server_meta(&state), text: "special key accepted; send ECDH public key".to_string() };
                        let reg = state.registry.read().await;
                        reg.send(client_id, sys);
                    }

                    ClientMessage::EcdhPublicKey { public_key, .. } => {
                        if !special_authed {
                            send_protocol_error(&state, client_id, "special auth required").await;
                            continue;
                        }

                        let server_public_key = {
                            let mut ecdh = state.ecdh.write().await;
                            ecdh.generate_keypair(client_id, &public_key)
                        };

                        match server_public_key {
                            Ok(pub_key) => {
                                ecdh_complete = true;
                                let ack = ServerMessage::EcdhAck { meta: server_meta(&state), public_key: pub_key };
                                let reg = state.registry.read().await;
                                reg.send(client_id, ack);

                                let sys = ServerMessage::SystemMessage { meta: server_meta(&state), text: "encryption enabled; please login or register".to_string() };
                                let reg = state.registry.read().await;
                                reg.send(client_id, sys);
                            }
                            Err(reason) => {
                                send_protocol_error(&state, client_id, &reason).await;
                            }
                        }
                    }

                    ClientMessage::RegisterUser { username, .. } => {
                        if !special_authed {
                            send_protocol_error(&state, client_id, "special auth required").await;
                            continue;
                        }

                        let res = {
                            let mut auth = state.auth.write().await;
                            auth.register(username)
                        };

                        match res {
                            Ok((user, pw)) => {
                                {
                                    let mut reg = state.registry.write().await;
                                    reg.set_user(client_id, user.clone());
                                }
                                user_authed = true;

                                let msg = ServerMessage::AuthSuccess { meta: server_meta(&state), user, generated_password: Some(pw) };
                                let reg = state.registry.read().await;
                                reg.send(client_id, msg);

                                send_channel_list(&state, client_id).await;
                            }
                            Err(reason) => {
                                let msg = ServerMessage::AuthFailure { meta: server_meta(&state), reason };
                                let reg = state.registry.read().await;
                                reg.send(client_id, msg);
                            }
                        }
                    }

                    ClientMessage::Login { username, password, .. } => {
                        if !special_authed {
                            send_protocol_error(&state, client_id, "special auth required").await;
                            continue;
                        }

                        let res = {
                            let auth = state.auth.read().await;
                            auth.login(&username, &password)
                        };

                        match res {
                            Ok(user) => {
                                {
                                    let mut reg = state.registry.write().await;
                                    reg.set_user(client_id, user.clone());
                                }
                                user_authed = true;

                                let msg = ServerMessage::AuthSuccess { meta: server_meta(&state), user, generated_password: None };
                                let reg = state.registry.read().await;
                                reg.send(client_id, msg);

                                send_channel_list(&state, client_id).await;
                            }
                            Err(reason) => {
                                let msg = ServerMessage::AuthFailure { meta: server_meta(&state), reason };
                                let reg = state.registry.read().await;
                                reg.send(client_id, msg);
                            }
                        }
                    }

                    ClientMessage::ListChannels{..} => {
                        if !user_authed {
                            send_protocol_error(&state, client_id, "login/register required").await;
                            continue;
                        }

                        send_channel_list(&state, client_id).await;
                    }

                    ClientMessage::JoinChannel { name, password, .. } => {
                        if !user_authed {
                            send_protocol_error(&state, client_id, "login/register required").await;
                            continue;
                        }

                        let prev_channel = {
                            let reg = state.registry.read().await;
                            reg.channel(client_id)
                        };

                        if let Some(prev) = prev_channel {
                            {
                                let mut channels = state.channels.write().await;
                                channels.leave(client_id, &prev);
                            }

                            if let Some(user) = {
                                let reg = state.registry.read().await;
                                reg.user(client_id)
                            } {
                                broadcast_user_left(&state, client_id, &prev, user).await;
                            }
                        }

                        let channel_exists = {
                            let channels = state.channels.read().await;
                            channels.get_channel_id(&name).is_some()
                        };

                        let channel_id = if !channel_exists {
                            let channel_id = {
                                let mut channels = state.channels.write().await;
                                channels.ensure_channel(&name, password.is_none(), password.clone(), Some(client_id))
                            };

                            {
                                let mut admin = state.admin.write().await;
                                admin.set_channel_creator(channel_id, client_id);
                            }
                            channel_id
                        } else {
                            let channels = state.channels.read().await;
                            channels.get_channel_id(&name).unwrap()
                        };

                        let is_banned = {
                            let bans = state.bans.read().await;
                            bans.is_banned(channel_id, client_id)
                        };

                        if is_banned {
                            let reason = {
                                let bans = state.bans.read().await;
                                let ban_info = bans.get_ban_info(channel_id, client_id);
                                match ban_info.and_then(|b| b.banned_until) {
                                    Some(until) => format!("Banned until {}", until.format("%Y-%m-%d %H:%M:%S UTC")),
                                    None => "Permanently banned from channel".to_string(),
                                }
                            };

                            let msg = ServerMessage::JoinFailure { meta: server_meta(&state), channel: name, reason };
                            let reg = state.registry.read().await;
                            reg.send(client_id, msg);
                            continue;
                        }

                        let join_res = {
                            let mut channels = state.channels.write().await;
                            channels.join(client_id, &name, password)
                        };

                        match join_res {
                            Ok(channel_info_base) => {
                                let (role, channel_type) = {
                                    let admin = state.admin.read().await;
                                    (admin.get_role(channel_id, client_id), admin.get_channel_type(channel_id))
                                };

                                let channel_info = {
                                    let channels = state.channels.read().await;
                                    let ch = channels.get_channel_id(&name);
                                    if let Some(ch_id) = ch {
                                        darkrelayprotocol::protocol::ChannelInfo {
                                            id: ch_id,
                                            name: name.clone(),
                                            is_public: channel_info_base.is_public,
                                            channel_type,
                                            user_role: Some(role),
                                        }
                                    } else {
                                        channel_info_base
                                    }
                                };

                                {
                                    let mut reg = state.registry.write().await;
                                    reg.set_channel(client_id, Some(channel_info.name.clone()));
                                }

                                let msg = ServerMessage::JoinSuccess { meta: server_meta(&state), channel: channel_info.clone() };
                                let reg = state.registry.read().await;
                                reg.send(client_id, msg);

                                let history = {
                                    let channels = state.channels.read().await;
                                    channels.history(&channel_info.name, 50)
                                };

                                let hist_msg = ServerMessage::HistoryChunk { meta: server_meta(&state), channel: channel_info.name.clone(), messages: history };
                                let reg = state.registry.read().await;
                                reg.send(client_id, hist_msg);

                                broadcast_user_joined(&state, client_id, &channel_info.name).await;
                            }
                            Err(reason) => {
                                let msg = ServerMessage::JoinFailure { meta: server_meta(&state), channel: name, reason };
                                let reg = state.registry.read().await;
                                reg.send(client_id, msg);
                            }
                        }
                    }

                    ClientMessage::SendMessage { channel, content, metadata, .. } => {
                        if !user_authed {
                            send_protocol_error(&state, client_id, "login/register required").await;
                            continue;
                        }

                        let (user, current_channel) = {
                            let reg = state.registry.read().await;
                            (reg.user(client_id), reg.channel(client_id))
                        };

                        let Some(user) = user else {
                            send_protocol_error(&state, client_id, "user missing").await;
                            continue;
                        };

                        if current_channel.as_deref() != Some(channel.as_str()) {
                            send_protocol_error(&state, client_id, "not joined to channel").await;
                            continue;
                        }

                        let channel_id = {
                            let channels = state.channels.read().await;
                            channels.get_channel_id(&channel)
                        };

                        if let Some(ch_id) = channel_id {
                            let can_send = {
                                let admin = state.admin.read().await;
                                admin.can_send_message(ch_id, client_id)
                            };

                            if !can_send {
                                send_admin_error(&state, client_id, "You lack permission to send messages in this channel").await;
                                continue;
                            }
                        }

                        // Extract nonce from metadata if present
                        let nonce = metadata.iter()
                            .find(|(k, _)| k == "nonce")
                            .and_then(|(_, v)| hex::decode(v).ok());

                        // Server stores encrypted content as-is, never attempts to decrypt
                        info!(
                            client_id,
                            user = user.username,
                            channel = &channel,
                            size = content.len(),
                            encrypted = ecdh_complete,
                            "message received (content encrypted, not logged)"
                        );

                        let msg = ChatMessage {
                            id: 0,
                            user_id: user.id,
                            username: user.username.clone(),
                            content,
                            timestamp: Utc::now(),
                            nonce,
                            metadata,
                        };

                        let stored = {
                            let mut channels = state.channels.write().await;
                            channels.add_message(&channel, msg)
                        };

                        match stored {
                            Ok(stored) => {
                                broadcast_message(&state, &channel, stored).await;
                            }
                            Err(reason) => {
                                send_protocol_error(&state, client_id, &reason).await;
                            }
                        }
                    }

                    ClientMessage::GetHistory { channel, limit, .. } => {
                        if !user_authed {
                            send_protocol_error(&state, client_id, "login/register required").await;
                            continue;
                        }

                        let messages = {
                            let channels = state.channels.read().await;
                            channels.history(&channel, limit as usize)
                        };

                        let msg = ServerMessage::HistoryChunk { meta: server_meta(&state), channel, messages };
                        let reg = state.registry.read().await;
                        reg.send(client_id, msg);
                    }

                    ClientMessage::DeleteMessage { channel, message_id, .. } => {
                        handle_delete_message(&state, client_id, user_authed, &channel, message_id).await;
                    }

                    ClientMessage::PromoteUser { channel, username, role, .. } => {
                        handle_promote_user(&state, client_id, user_authed, &channel, &username, role).await;
                    }

                    ClientMessage::DemoteUser { channel, username, .. } => {
                        handle_demote_user(&state, client_id, user_authed, &channel, &username).await;
                    }

                    ClientMessage::BanUser { channel, username, duration_seconds, reason, .. } => {
                        handle_ban_user(&state, client_id, user_authed, &channel, &username, duration_seconds, reason).await;
                    }

                    ClientMessage::UnbanUser { channel, username, .. } => {
                        handle_unban_user(&state, client_id, user_authed, &channel, &username).await;
                    }

                    ClientMessage::KickUser { channel, username, reason, .. } => {
                        handle_kick_user(&state, client_id, user_authed, &channel, &username, reason).await;
                    }

                    ClientMessage::ListAdmins { channel, .. } => {
                        handle_list_admins(&state, client_id, user_authed, &channel).await;
                    }

                    ClientMessage::ListBans { channel, .. } => {
                        handle_list_bans(&state, client_id, user_authed, &channel).await;
                    }

                    ClientMessage::ViewLogs { channel, limit, .. } => {
                        handle_view_logs(&state, client_id, user_authed, &channel, limit).await;
                    }

                    ClientMessage::ChangeChannelType { channel, channel_type, .. } => {
                        handle_change_channel_type(&state, client_id, user_authed, &channel, channel_type).await;
                    }

                    ClientMessage::DeleteChannel { channel, .. } => {
                        handle_delete_channel(&state, client_id, user_authed, &channel).await;
                    }

                    ClientMessage::Disconnect{..} => {
                        info!(client_id, "client disconnect requested");
                        break;
                    }
                }
            }
        }
    }

    cleanup_disconnect(&state, client_id).await;

    let _ = time::timeout(Duration::from_secs(2), writer_task).await;
    Ok(())
}

async fn cleanup_disconnect(state: &Arc<AppState>, client_id: ClientId) {
    let (user, channel) = {
        let reg = state.registry.read().await;
        (reg.user(client_id), reg.channel(client_id))
    };

    if let Some(ch) = &channel {
        {
            let mut channels = state.channels.write().await;
            channels.leave(client_id, ch);
        }
        if let Some(user) = user {
            broadcast_user_left(state, client_id, ch, user).await;
        }
    }

    {
        let mut ecdh = state.ecdh.write().await;
        ecdh.remove(client_id);
    }

    let mut reg = state.registry.write().await;
    reg.remove(client_id);

    info!(client_id, "client disconnected");
}

async fn send_channel_list(state: &Arc<AppState>, client_id: ClientId) {
    let channels = {
        let channels = state.channels.read().await;
        channels.list_public()
    };

    let msg = ServerMessage::ChannelList {
        meta: server_meta(state),
        channels,
    };

    let reg = state.registry.read().await;
    reg.send(client_id, msg);
}

async fn broadcast_message(state: &Arc<AppState>, channel: &str, message: ChatMessage) {
    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::MessageReceived {
        meta: server_meta(state),
        channel: channel.to_string(),
        message,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn broadcast_user_joined(state: &Arc<AppState>, client_id: ClientId, channel: &str) {
    let user = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(user) = user else {
        return;
    };

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::UserJoined {
        meta: server_meta(state),
        channel: channel.to_string(),
        user,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn broadcast_user_left(state: &Arc<AppState>, client_id: ClientId, channel: &str, user: darkrelayprotocol::protocol::UserInfo) {
    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::UserLeft {
        meta: server_meta(state),
        channel: channel.to_string(),
        user,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);

    debug!(client_id, channel, "broadcast user left");
}

async fn send_protocol_error(state: &Arc<AppState>, client_id: ClientId, text: &str) {
    let msg = ServerMessage::ProtocolError {
        meta: server_meta(state),
        text: text.to_string(),
    };

    let reg = state.registry.read().await;
    reg.send(client_id, msg);
}

async fn send_admin_error(state: &Arc<AppState>, client_id: ClientId, reason: &str) {
    let msg = ServerMessage::AdminError {
        meta: server_meta(state),
        reason: reason.to_string(),
    };

    let reg = state.registry.read().await;
    reg.send(client_id, msg);
}

fn server_meta(state: &Arc<AppState>) -> MessageMeta {
    MessageMeta::new(state.next_server_msg_id(), Utc::now())
}

async fn handle_delete_message(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
    message_id: u64,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::DeleteMessage)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: DeleteMessage").await;
        return;
    }

    let deleted = {
        let mut channels = state.channels.write().await;
        channels.delete_message(channel, message_id)
    };

    if !deleted {
        send_admin_error(state, client_id, "Message not found").await;
        return;
    }

    let admin_username = {
        let reg = state.registry.read().await;
        reg.user(client_id).map(|u| u.username.clone()).unwrap_or_default()
    };

    {
        let mut admin = state.admin.write().await;
        admin.log_action(
            ch_id,
            client_id,
            admin_username.clone(),
            "delete_message".to_string(),
            format!("message_{}", message_id),
            "Message deleted".to_string(),
        );
    }

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::MessageDeleted {
        meta: server_meta(state),
        channel: channel.to_string(),
        message_id,
        deleted_by: admin_username,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn handle_promote_user(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
    username: &str,
    role: darkrelayprotocol::permissions::Role,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::PromoteUser)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: PromoteUser").await;
        return;
    }

    let target_id = {
        let auth = state.auth.read().await;
        auth.find_user_by_username(username).map(|u| u.id)
    };

    let Some(target_user_id) = target_id else {
        send_admin_error(state, client_id, "User not found").await;
        return;
    };

    {
        let mut admin = state.admin.write().await;
        admin.set_role(ch_id, target_user_id, role);
    }

    let admin_username = {
        let reg = state.registry.read().await;
        reg.user(client_id).map(|u| u.username.clone()).unwrap_or_default()
    };

    {
        let mut admin = state.admin.write().await;
        admin.log_action(
            ch_id,
            client_id,
            admin_username.clone(),
            "promote_user".to_string(),
            username.to_string(),
            format!("Promoted to {:?}", role),
        );
    }

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::UserPromoted {
        meta: server_meta(state),
        channel: channel.to_string(),
        user_id: target_user_id,
        username: username.to_string(),
        new_role: role,
        promoted_by: admin_username,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn handle_demote_user(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
    username: &str,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::PromoteUser)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: PromoteUser").await;
        return;
    }

    let target_id = {
        let auth = state.auth.read().await;
        auth.find_user_by_username(username).map(|u| u.id)
    };

    let Some(target_user_id) = target_id else {
        send_admin_error(state, client_id, "User not found").await;
        return;
    };

    {
        let mut admin = state.admin.write().await;
        admin.set_role(ch_id, target_user_id, darkrelayprotocol::permissions::Role::User);
    }

    let admin_username = {
        let reg = state.registry.read().await;
        reg.user(client_id).map(|u| u.username.clone()).unwrap_or_default()
    };

    {
        let mut admin = state.admin.write().await;
        admin.log_action(
            ch_id,
            client_id,
            admin_username.clone(),
            "demote_user".to_string(),
            username.to_string(),
            "Demoted to User".to_string(),
        );
    }

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::UserDemoted {
        meta: server_meta(state),
        channel: channel.to_string(),
        user_id: target_user_id,
        username: username.to_string(),
        demoted_by: admin_username,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn handle_ban_user(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
    username: &str,
    duration_seconds: Option<u64>,
    reason: Option<String>,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::BanUser)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: BanUser").await;
        return;
    }

    let target_user = {
        let auth = state.auth.read().await;
        auth.find_user_by_username(username)
    };

    let Some(target) = target_user else {
        send_admin_error(state, client_id, "User not found").await;
        return;
    };

    let admin_username = {
        let reg = state.registry.read().await;
        reg.user(client_id).map(|u| u.username.clone()).unwrap_or_default()
    };

    let banned_until = {
        let mut bans = state.bans.write().await;
        bans.ban_user(
            ch_id,
            target.id,
            target.username.clone(),
            admin_username.clone(),
            duration_seconds,
            reason.clone(),
        )
    };

    {
        let mut admin = state.admin.write().await;
        let details = match duration_seconds {
            Some(secs) => format!("Banned for {} seconds", secs),
            None => "Permanently banned".to_string(),
        };
        admin.log_action(
            ch_id,
            client_id,
            admin_username.clone(),
            "ban_user".to_string(),
            username.to_string(),
            details,
        );
    }

    let target_client_ids: Vec<ClientId> = {
        let reg = state.registry.read().await;
        reg.find_clients_by_user_id(target.id)
    };

    for target_client_id in target_client_ids {
        let current_channel = {
            let reg = state.registry.read().await;
            reg.channel(target_client_id)
        };

        if current_channel.as_deref() == Some(channel) {
            {
                let mut channels = state.channels.write().await;
                channels.leave(target_client_id, channel);
            }

            let kick_msg = ServerMessage::SystemMessage {
                meta: server_meta(state),
                text: format!("You have been banned from this channel. Reason: {}", reason.clone().unwrap_or_default()),
            };

            {
                let reg = state.registry.read().await;
                reg.send(target_client_id, kick_msg);
            }
        }
    }

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::UserBanned {
        meta: server_meta(state),
        channel: channel.to_string(),
        user_id: target.id,
        username: username.to_string(),
        banned_until,
        banned_by: admin_username,
        reason,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn handle_unban_user(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
    username: &str,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::BanUser)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: BanUser").await;
        return;
    }

    let target_id = {
        let auth = state.auth.read().await;
        auth.find_user_by_username(username).map(|u| u.id)
    };

    let Some(target_user_id) = target_id else {
        send_admin_error(state, client_id, "User not found").await;
        return;
    };

    let unbanned = {
        let mut bans = state.bans.write().await;
        bans.unban_user(ch_id, target_user_id)
    };

    if !unbanned {
        send_admin_error(state, client_id, "User is not banned").await;
        return;
    }

    let admin_username = {
        let reg = state.registry.read().await;
        reg.user(client_id).map(|u| u.username.clone()).unwrap_or_default()
    };

    {
        let mut admin = state.admin.write().await;
        admin.log_action(
            ch_id,
            client_id,
            admin_username.clone(),
            "unban_user".to_string(),
            username.to_string(),
            "Unbanned".to_string(),
        );
    }

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::UserUnbanned {
        meta: server_meta(state),
        channel: channel.to_string(),
        username: username.to_string(),
        unbanned_by: admin_username,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn handle_kick_user(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
    username: &str,
    reason: Option<String>,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::KickUser)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: KickUser").await;
        return;
    }

    let target_user = {
        let auth = state.auth.read().await;
        auth.find_user_by_username(username)
    };

    let Some(target) = target_user else {
        send_admin_error(state, client_id, "User not found").await;
        return;
    };

    let admin_username = {
        let reg = state.registry.read().await;
        reg.user(client_id).map(|u| u.username.clone()).unwrap_or_default()
    };

    {
        let mut admin = state.admin.write().await;
        admin.log_action(
            ch_id,
            client_id,
            admin_username.clone(),
            "kick_user".to_string(),
            username.to_string(),
            reason.clone().unwrap_or_default(),
        );
    }

    let target_client_ids: Vec<ClientId> = {
        let reg = state.registry.read().await;
        reg.find_clients_by_user_id(target.id)
    };

    for target_client_id in target_client_ids {
        let current_channel = {
            let reg = state.registry.read().await;
            reg.channel(target_client_id)
        };

        if current_channel.as_deref() == Some(channel) {
            {
                let mut channels = state.channels.write().await;
                channels.leave(target_client_id, channel);
            }

            let kick_msg = ServerMessage::SystemMessage {
                meta: server_meta(state),
                text: format!("You have been kicked from this channel. Reason: {}", reason.clone().unwrap_or_default()),
            };

            {
                let reg = state.registry.read().await;
                reg.send(target_client_id, kick_msg);
            }
        }
    }

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::UserKicked {
        meta: server_meta(state),
        channel: channel.to_string(),
        user_id: target.id,
        username: username.to_string(),
        kicked_by: admin_username,
        reason,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn handle_list_admins(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let user_map = {
        let auth = state.auth.read().await;
        auth.get_all_users_map()
    };

    let admins = {
        let admin = state.admin.read().await;
        admin.list_admins(ch_id, &user_map)
    };

    let msg = ServerMessage::AdminList {
        meta: server_meta(state),
        channel: channel.to_string(),
        admins,
    };

    let reg = state.registry.read().await;
    reg.send(client_id, msg);
}

async fn handle_list_bans(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::ViewLogs)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: ViewLogs").await;
        return;
    }

    let bans = {
        let bans = state.bans.read().await;
        bans.list_bans(ch_id)
    };

    let msg = ServerMessage::BanList {
        meta: server_meta(state),
        channel: channel.to_string(),
        bans,
    };

    let reg = state.registry.read().await;
    reg.send(client_id, msg);
}

async fn handle_view_logs(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
    limit: u32,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::ViewLogs)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: ViewLogs").await;
        return;
    }

    let logs = {
        let admin = state.admin.read().await;
        admin.get_logs(ch_id, limit as usize)
    };

    let msg = ServerMessage::LogList {
        meta: server_meta(state),
        channel: channel.to_string(),
        logs,
    };

    let reg = state.registry.read().await;
    reg.send(client_id, msg);
}

async fn handle_change_channel_type(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
    channel_type: darkrelayprotocol::channel::ChannelType,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let has_permission = {
        let admin = state.admin.read().await;
        admin.has_permission(ch_id, client_id, Permission::ManageChannel)
    };

    if !has_permission {
        send_admin_error(state, client_id, "You lack permission: ManageChannel").await;
        return;
    }

    {
        let mut admin = state.admin.write().await;
        admin.set_channel_type(ch_id, channel_type);
    }

    let admin_username = {
        let reg = state.registry.read().await;
        reg.user(client_id).map(|u| u.username.clone()).unwrap_or_default()
    };

    {
        let mut admin = state.admin.write().await;
        admin.log_action(
            ch_id,
            client_id,
            admin_username.clone(),
            "change_channel_type".to_string(),
            channel.to_string(),
            format!("Changed to {:?}", channel_type),
        );
    }

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::ChannelTypeChanged {
        meta: server_meta(state),
        channel: channel.to_string(),
        new_type: channel_type,
        changed_by: admin_username,
    };

    let reg = state.registry.read().await;
    reg.send_many(&members, &msg);
}

async fn handle_delete_channel(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    channel: &str,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let channel_id = {
        let channels = state.channels.read().await;
        channels.get_channel_id(channel)
    };

    let Some(ch_id) = channel_id else {
        send_admin_error(state, client_id, "Channel not found").await;
        return;
    };

    let role = {
        let admin = state.admin.read().await;
        admin.get_role(ch_id, client_id)
    };

    if role != darkrelayprotocol::permissions::Role::SuperAdmin {
        send_admin_error(state, client_id, "Only SuperAdmin can delete channels").await;
        return;
    }

    let admin_username = {
        let reg = state.registry.read().await;
        reg.user(client_id).map(|u| u.username.clone()).unwrap_or_default()
    };

    let members = {
        let channels = state.channels.read().await;
        channels.members(channel)
    };

    let msg = ServerMessage::ChannelDeleted {
        meta: server_meta(state),
        channel: channel.to_string(),
        deleted_by: admin_username.clone(),
    };

    {
        let reg = state.registry.read().await;
        reg.send_many(&members, &msg);
    }

    for member_id in &members {
        let reg = state.registry.read().await;
        if let Some(ch) = reg.channel(*member_id) {
            if ch == channel {
                drop(reg);
                let mut reg = state.registry.write().await;
                reg.set_channel(*member_id, None);
            }
        }
    }

    {
        let mut channels = state.channels.write().await;
        channels.delete_channel(channel);
    }

    {
        let mut admin = state.admin.write().await;
        admin.remove_channel(ch_id);
    }

    info!(client_id, channel, deleted_by = admin_username, "channel deleted");
}

async fn read_frame<T: DeserializeOwned, R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<T> {
    let len = reader.read_u32().await?;
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    bincode::deserialize::<T>(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn write_frame<T: Serialize, W: AsyncWrite + Unpin>(writer: &mut W, msg: &T) -> io::Result<()> {
    let data = bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let len: u32 = data
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;

    writer.write_u32(len).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}
