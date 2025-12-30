use std::{
    io,
    sync::Arc,
    time::Duration,
};

use bincode;
use chrono::Utc;
use darkrelayprotocol::protocol::{
    ChatMessage, ClientMessage, MessageMeta, ServerMessage,
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

                        let join_res = {
                            let mut channels = state.channels.write().await;
                            channels.join(client_id, &name, password)
                        };

                        match join_res {
                            Ok(channel_info) => {
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

fn server_meta(state: &Arc<AppState>) -> MessageMeta {
    MessageMeta::new(state.next_server_msg_id(), Utc::now())
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
