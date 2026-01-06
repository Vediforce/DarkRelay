use std::{
    io,
    sync::Arc,
    time::Duration,
};

use bincode;
use chrono::Utc;
use darkrelayprotocol::{
    federation::ServerFederationMessage,
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

                    // DM Handling
                    ClientMessage::DMSend { recipient_id, content, nonce, .. } => {
                        handle_dm_send(&state, client_id, user_authed, recipient_id, content, nonce).await;
                    }

                    ClientMessage::DMSendFederated { recipient_username, content, nonce, .. } => {
                        handle_dm_send_federated(&state, client_id, user_authed, recipient_username, content, nonce).await;
                    }

                    ClientMessage::DMHistory { other_user_id, limit, .. } => {
                        handle_dm_history(&state, client_id, user_authed, other_user_id, limit).await;
                    }

                    ClientMessage::DMHistoryFederated { other_username, limit, .. } => {
                        // For now, treat as local - federation history is a Phase 5+ feature
                        handle_dm_history(&state, client_id, user_authed, 0, limit).await;
                    }

                    ClientMessage::DMReadReceipt { dm_id, .. } => {
                        handle_dm_read_receipt(&state, client_id, user_authed, dm_id).await;
                    }

                    // File Transfer Handling
                    ClientMessage::FileTransferRequest { recipient_id, file_name, file_size, file_hash, .. } => {
                        handle_file_transfer_request(&state, client_id, user_authed, recipient_id, file_name, file_size, file_hash).await;
                    }

                    ClientMessage::FileTransferRequestFederated { recipient_username, file_name, file_size, file_hash, .. } => {
                        handle_file_transfer_request_federated(&state, client_id, user_authed, recipient_username, file_name, file_size, file_hash).await;
                    }

                    ClientMessage::FileTransferAccept { transfer_id, .. } => {
                        handle_file_transfer_accept(&state, client_id, user_authed, transfer_id).await;
                    }

                    ClientMessage::FileTransferDecline { transfer_id, .. } => {
                        handle_file_transfer_decline(&state, client_id, user_authed, transfer_id).await;
                    }

                    ClientMessage::FileTransferChunk { transfer_id, chunk_index, chunk_data, .. } => {
                        handle_file_transfer_chunk(&state, client_id, user_authed, transfer_id, chunk_index, chunk_data).await;
                    }

                    ClientMessage::FileTransferCancel { transfer_id, .. } => {
                        handle_file_transfer_cancel(&state, client_id, user_authed, transfer_id).await;
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

// DM Handling Functions

async fn handle_dm_send(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    recipient_id: u64,
    content: Vec<u8>,
    nonce: Vec<u8>,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(sender) = sender else {
        send_protocol_error(state, client_id, "user not found").await;
        return;
    };

    // Store DM
    let (dm_id, timestamp) = {
        let mut dm_manager = state.dm_manager.write().await;
        dm_manager.store_dm(sender.id, recipient_id, content.clone(), nonce.clone()).await
    };

    // Deliver to recipient if online
    let recipient_clients = {
        let reg = state.registry.read().await;
        reg.find_clients_by_user_id(recipient_id)
    };

    for recipient_client_id in recipient_clients {
        let dm_msg = ServerMessage::DMReceived {
            meta: server_meta(state),
            dm_id,
            sender_id: sender.id,
            sender_server_id: None,
            sender_username: sender.username.clone(),
            content: content.clone(),
            nonce: nonce.clone(),
            recipient_id,
        };

        let reg = state.registry.read().await;
        reg.send(recipient_client_id, dm_msg);
    }

    debug!(client_id, recipient_id, dm_id, "DM sent");
}

async fn handle_dm_send_federated(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    recipient_username: String,
    content: Vec<u8>,
    nonce: Vec<u8>,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(sender) = sender else {
        send_protocol_error(state, client_id, "user not found").await;
        return;
    };

    // Parse the federated username
    let user_dir = state.federation_user_dir.read().await;
    let (username, server_id, server_name) = user_dir.parse_federated_username(&recipient_username);
    
    if server_id.is_none() && server_name.is_none() {
        // No server specified, try to find locally
        drop(user_dir);
        handle_dm_send(state, client_id, user_authed, 0, content, nonce).await;
        return;
    }

    let target_server_id = server_id.unwrap_or(0);
    let target_server_name = server_name.unwrap_or_default();

    // Check if we have a cached lookup
    if let Some(server_id) = server_id {
        if user_dir.is_cache_valid(&username, server_id).await {
            // We have cached info, try to relay
            let cached = user_dir.get_cached_remote_user(&username, server_id).await;
            if let Some(user) = cached {
                if user.local_id.is_some() {
                    // User exists locally but with different server ID - inconsistency
                    send_protocol_error(state, client_id, "user found locally but with different server ID").await;
                    return;
                }
            }
        }
    }

    // Create relay message
    let dm_id = state.next_server_msg_id();

    // Queue for relay
    {
        let mut relay = state.federation_relay.write().await;
        let _ = relay.queue_dm_for_relay(
            target_server_id,
            dm_id,
            state.server_id,
            content,
            nonce,
        ).await;
    }

    // Send to peer if connected
    if state.federation_peers.read().await.is_connected(target_server_id) {
        let relay_msg = darkrelayprotocol::federation::ServerFederationMessage::RelayDM(
            darkrelayprotocol::federation::RelayDM {
                dm_id,
                sender_id: sender.id,
                sender_server_id: state.server_id,
                recipient_username: username,
                content,
                nonce,
                timestamp: chrono::Utc::now().timestamp() as u64,
                hop_count: 0,
            }
        );

        if let Err(e) = state.federation_peers.write().await.send_to_peer(target_server_id, &relay_msg).await {
            warn!(server_id = target_server_id, error = %e, "failed to send relay DM");
        }
    } else {
        // Queue for later delivery
        warn!(server_id = target_server_id, "peer not connected, DM queued for later");
    }

    // Confirm to sender
    let confirm = ServerMessage::DMDeliveryConfirmed {
        meta: server_meta(state),
        dm_id,
        delivered: false,
        error_message: Some("queued for delivery".to_string()),
    };

    let reg = state.registry.read().await;
    reg.send(client_id, confirm);

    debug!(client_id, %recipient_username, dm_id, "federated DM queued");
}

async fn handle_dm_history(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    other_user_id: u64,
    limit: u16,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(sender) = sender else {
        send_protocol_error(state, client_id, "user not found").await;
        return;
    };

    let history = {
        let dm_manager = state.dm_manager.read().await;
        dm_manager.get_history_for_user(sender.id, other_user_id, limit as u32).await
    };

    let msg = ServerMessage::DMHistory {
        meta: server_meta(state),
        messages: history,
    };

    let reg = state.registry.read().await;
    reg.send(client_id, msg);
}

async fn handle_dm_read_receipt(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    dm_id: u64,
) {
    if !user_authed {
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(user) = sender else {
        return;
    };

    let mut dm_manager = state.dm_manager.write().await;
    dm_manager.mark_dm_as_read(dm_id, user.id).await;
}

async fn handle_file_transfer_request(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    recipient_id: u64,
    file_name: String,
    file_size: u64,
    file_hash: Vec<u8>,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(sender) = sender else {
        send_protocol_error(state, client_id, "user not found").await;
        return;
    };

    let transfer_id = {
        let mut ft_manager = state.file_transfer.write().await;
        ft_manager.create_transfer(sender.id, recipient_id, file_name.clone(), file_size, file_hash.clone()).await
    };

    // Create file transfer proposal for recipient
    let proposal = ServerMessage::FileTransferProposal {
        meta: server_meta(state),
        transfer_id,
        sender_id: sender.id,
        sender_server_id: None,
        sender_username: sender.username.clone(),
        file_name,
        file_size,
    };

    // Send to all client instances of the recipient
    let recipient_clients = {
        let reg = state.registry.read().await;
        reg.find_clients_by_user_id(recipient_id)
    };

    for recipient_client_id in recipient_clients {
        let reg = state.registry.read().await;
        reg.send(recipient_client_id, proposal.clone());
    }

    debug!(client_id, recipient_id, transfer_id, "file transfer request sent");
}

async fn handle_file_transfer_request_federated(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    recipient_username: String,
    file_name: String,
    file_size: u64,
    file_hash: Vec<u8>,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(sender) = sender else {
        send_protocol_error(state, client_id, "user not found").await;
        return;
    };

    // Parse federated username
    let user_dir = state.federation_user_dir.read().await;
    let (username, server_id, _server_name) = user_dir.parse_federated_username(&recipient_username);
    
    let Some(target_server_id) = server_id else {
        send_protocol_error(state, client_id, "invalid federated username format").await;
        return;
    };

    let transfer_id = state.next_server_msg_id();

    // Create file transfer request for relay
    let request = darkrelayprotocol::federation::RelayFileTransferRequest {
        transfer_id,
        sender_id: sender.id,
        sender_server_id: state.server_id,
        recipient_username: username,
        file_name,
        file_size,
        file_hash,
        hop_count: 0,
    };

    // Queue for relay
    {
        let mut relay = state.federation_relay.write().await;
        relay.queue_file_transfer_request(
            target_server_id,
            transfer_id,
            sender.id,
            state.server_id,
            username,
            file_name.clone(),
            file_size,
            file_hash,
        ).await;
    }

    // Send to peer if connected
    if state.federation_peers.read().await.is_connected(target_server_id) {
        let relay_msg = darkrelayprotocol::federation::ServerFederationMessage::RelayFileTransferRequest(request);

        if let Err(e) = state.federation_peers.write().await.send_to_peer(target_server_id, &relay_msg).await {
            warn!(server_id = target_server_id, error = %e, "failed to send file transfer request");
        }
    }

    debug!(client_id, %recipient_username, transfer_id, "federated file transfer requested");
}

async fn handle_file_transfer_accept(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    transfer_id: u64,
) {
    if !user_authed {
        send_protocol_error(state, client_id, "login/register required").await;
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(user) = sender else {
        return;
    };

    let transfer = {
        let ft_manager = state.file_transfer.read().await;
        ft_manager.get_transfer(transfer_id).await
    };

    if let Some(transfer) = transfer {
        if transfer.recipient_id != user.id {
            return;
        }

        let mut ft_manager = state.file_transfer.write().await;
        ft_manager.accept_transfer(transfer_id).await;

        // Notify sender
        let status_msg = ServerMessage::FileTransferStatus {
            meta: server_meta(state),
            transfer_id,
            status: darkrelayprotocol::protocol::TransferStatus::InProgress,
            progress_percent: 0,
        };

        let sender_clients = {
            let reg = state.registry.read().await;
            reg.find_clients_by_user_id(transfer.sender_id)
        };

        for sender_client_id in sender_clients {
            let reg = state.registry.read().await;
            reg.send(sender_client_id, status_msg.clone());
        }
    }
}

async fn handle_file_transfer_decline(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    transfer_id: u64,
) {
    if !user_authed {
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(user) = sender else {
        return;
    };

    let transfer = {
        let ft_manager = state.file_transfer.read().await;
        ft_manager.get_transfer(transfer_id).await
    };

    if let Some(transfer) = transfer {
        if transfer.recipient_id != user.id {
            return;
        }

        let mut ft_manager = state.file_transfer.write().await;
        ft_manager.decline_transfer(transfer_id).await;
    }
}

async fn handle_file_transfer_chunk(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    transfer_id: u64,
    chunk_index: u32,
    chunk_data: Vec<u8>,
) {
    if !user_authed {
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(user) = sender else {
        return;
    };

    let transfer = {
        let ft_manager = state.file_transfer.read().await;
        ft_manager.get_transfer(transfer_id).await
    };

    if let Some(transfer) = transfer {
        if transfer.sender_id != user.id {
            return;
        }

        // Store chunk
        let mut ft_manager = state.file_transfer.write().await;
        ft_manager.add_chunk(transfer_id, chunk_index, chunk_data.clone(), Vec::new()).await;

        // Calculate progress
        let (status, progress) = {
            let ft_manager = state.file_transfer.read().await;
            ft_manager.get_progress(transfer_id).await.unwrap_or((darkrelayprotocol::protocol::TransferStatus::InProgress, 0))
        };

        // Send ACK to sender
        let ack = ServerMessage::FileTransferChunkAck {
            meta: server_meta(state),
            transfer_id,
            chunk_index,
        };

        let reg = state.registry.read().await;
        reg.send(client_id, ack);

        // Send progress update
        let progress_msg = ServerMessage::FileTransferStatus {
            meta: server_meta(state),
            transfer_id,
            status,
            progress_percent: progress,
        };

        let reg = state.registry.read().await;
        reg.send(client_id, progress_msg);
    }
}

async fn handle_file_transfer_cancel(
    state: &Arc<AppState>,
    client_id: ClientId,
    user_authed: bool,
    transfer_id: u64,
) {
    if !user_authed {
        return;
    }

    let sender = {
        let reg = state.registry.read().await;
        reg.user(client_id)
    };

    let Some(user) = sender else {
        return;
    };

    let transfer = {
        let ft_manager = state.file_transfer.read().await;
        ft_manager.get_transfer(transfer_id).await
    };

    if let Some(transfer) = transfer {
        let mut ft_manager = state.file_transfer.write().await;
        ft_manager.fail_transfer(transfer_id).await;
    }
}
