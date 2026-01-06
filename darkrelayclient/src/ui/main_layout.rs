use std::{
    io,
    time::Duration,
};

use chrono::Local;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    style::{Color, Print, Stylize},
    terminal,
};

use darkrelayprotocol::protocol::{ClientMessage, ServerMessage};

use crate::{
    connection::Connection,
    state::ClientState,
    ui::{clear, toast, TerminalSession, ToastKind},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Channels,
    Input,
}

pub async fn run(
    terminal: &mut TerminalSession,
    state: &mut ClientState,
    conn: &mut Connection,
) -> io::Result<()> {
    let mut focus = Focus::Input;
    let mut input = String::new();
    let mut selected_channel_idx: usize = 0;

    loop {
        while let Some(msg) = conn.try_recv() {
            handle_server_message(terminal, state, msg)?;
        }

        if state.channels.is_empty() {
            selected_channel_idx = 0;
        } else if selected_channel_idx >= state.channels.len() {
            selected_channel_idx = state.channels.len() - 1;
        }

        if event::poll(Duration::from_millis(25))? {
            let ev = event::read()?;
            if let Event::Key(key) = ev {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    request_disconnect(state, conn)?;
                    return Ok(());
                }

                match key.code {
                    KeyCode::Esc => {
                        request_disconnect(state, conn)?;
                        return Ok(());
                    }
                    KeyCode::Left => focus = Focus::Channels,
                    KeyCode::Right => focus = Focus::Input,
                    KeyCode::Up => {
                        if focus == Focus::Channels {
                            selected_channel_idx = selected_channel_idx.saturating_sub(1);
                        }
                    }
                    KeyCode::Down => {
                        if focus == Focus::Channels && selected_channel_idx + 1 < state.channels.len() {
                            selected_channel_idx += 1;
                        }
                    }
                    KeyCode::Enter => match focus {
                        Focus::Input => {
                            let line = input.trim().to_string();
                            input.clear();
                            if !line.is_empty() {
                                handle_input_line(terminal, state, conn, &line)?;
                            }
                        }
                        Focus::Channels => {
                            if let Some(ch) = state.channels.get(selected_channel_idx).cloned() {
                                let meta = state.next_meta();
                                conn.send(ClientMessage::JoinChannel {
                                    meta,
                                    name: ch.name.clone(),
                                    password: None,
                                })?;
                            }
                        }
                    },
                    KeyCode::Backspace => {
                        if focus == Focus::Input {
                            input.pop();
                        }
                    }
                    KeyCode::Char(ch) => {
                        if focus == Focus::Input {
                            input.push(ch);
                        }
                    }
                    _ => {}
                }
            }
        }

        draw(terminal, state, focus, &input, selected_channel_idx)?;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
}

fn request_disconnect(state: &mut ClientState, conn: &mut Connection) -> io::Result<()> {
    let _ = conn.send(ClientMessage::Disconnect {
        meta: state.next_meta(),
    });
    Ok(())
}

fn handle_input_line(
    terminal: &mut TerminalSession,
    state: &mut ClientState,
    conn: &mut Connection,
    line: &str,
) -> io::Result<()> {
    if line.starts_with('/') {
        return handle_command(terminal, state, conn, line);
    }

    let Some(channel) = state.current_channel.clone() else {
        toast(terminal, "Join a channel first (/join general)", ToastKind::Error)?;
        return Ok(());
    };

    // Encrypt the message if ECDH is complete
    let (content, metadata) = if state.crypto.is_ready() {
        let (ciphertext, nonce) = state.crypto.encrypt(line.as_bytes(), Some(&channel))?;
        let nonce_hex = hex::encode(&nonce);
        (ciphertext, vec![("nonce".to_string(), nonce_hex)])
    } else {
        (line.as_bytes().to_vec(), Vec::new())
    };

    conn.send(ClientMessage::SendMessage {
        meta: state.next_meta(),
        channel,
        content,
        metadata,
    })?;

    Ok(())
}

fn handle_command(
    terminal: &mut TerminalSession,
    state: &mut ClientState,
    conn: &mut Connection,
    line: &str,
) -> io::Result<()> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.as_slice() {
        ["/quit"] | ["/exit"] => {
            request_disconnect(state, conn)?;
            return Ok(());
        }
        ["/help"] => {
            toast(
                terminal,
                "Commands: /list, /join, /create, /dm, /promote, /demote, /ban, /kick, /delete, /quit",
                ToastKind::Info,
            )?;
        }
        ["/list"] => {
            conn.send(ClientMessage::ListChannels {
                meta: state.next_meta(),
            })?;
        }
        ["/join", name] | ["/create", name] => {
            conn.send(ClientMessage::JoinChannel {
                meta: state.next_meta(),
                name: (*name).to_string(),
                password: None,
            })?;
        }
        ["/join", name, password] | ["/create", name, password] => {
            conn.send(ClientMessage::JoinChannel {
                meta: state.next_meta(),
                name: (*name).to_string(),
                password: Some((*password).to_string()),
            })?;
        }
        ["/dm", username, rest @ ..] => {
            // Switch to DM view and send a message
            let message = rest.join(" ");
            if message.is_empty() {
                toast(terminal, &format!("Opening DM with {}", username), ToastKind::Info)?;
                // TODO: Switch view to DM
            } else {
                // Send DM - for now just show toast
                toast(terminal, "DM feature in development - message not sent", ToastKind::Info)?;
            }
        }
        ["/promote", username, role_str] => {
            let Some(channel) = state.current_channel.clone() else {
                toast(terminal, "Must be in a channel", ToastKind::Error)?;
                return Ok(());
            };
            
            use darkrelayprotocol::permissions::Role;
            let role = match *role_str {
                "admin" => Role::Admin,
                "moderator" | "mod" => Role::Moderator,
                _ => {
                    toast(terminal, "Invalid role. Use: admin, moderator", ToastKind::Error)?;
                    return Ok(());
                }
            };
            
            conn.send(ClientMessage::PromoteUser {
                meta: state.next_meta(),
                channel,
                username: (*username).to_string(),
                role,
            })?;
        }
        ["/demote", username] => {
            let Some(channel) = state.current_channel.clone() else {
                toast(terminal, "Must be in a channel", ToastKind::Error)?;
                return Ok(());
            };
            
            conn.send(ClientMessage::DemoteUser {
                meta: state.next_meta(),
                channel,
                username: (*username).to_string(),
            })?;
        }
        ["/ban", username, rest @ ..] => {
            let Some(channel) = state.current_channel.clone() else {
                toast(terminal, "Must be in a channel", ToastKind::Error)?;
                return Ok(());
            };
            
            let reason = if rest.is_empty() { None } else { Some(rest.join(" ")) };
            
            conn.send(ClientMessage::BanUser {
                meta: state.next_meta(),
                channel,
                username: (*username).to_string(),
                duration_seconds: None,
                reason,
            })?;
        }
        ["/kick", username, rest @ ..] => {
            let Some(channel) = state.current_channel.clone() else {
                toast(terminal, "Must be in a channel", ToastKind::Error)?;
                return Ok(());
            };
            
            let reason = if rest.is_empty() { None } else { Some(rest.join(" ")) };
            
            conn.send(ClientMessage::KickUser {
                meta: state.next_meta(),
                channel,
                username: (*username).to_string(),
                reason,
            })?;
        }
        ["/delete", message_id_str] => {
            let Some(channel) = state.current_channel.clone() else {
                toast(terminal, "Must be in a channel", ToastKind::Error)?;
                return Ok(());
            };
            
            let message_id: u64 = match message_id_str.parse() {
                Ok(id) => id,
                Err(_) => {
                    toast(terminal, "Invalid message ID", ToastKind::Error)?;
                    return Ok(());
                }
            };
            
            conn.send(ClientMessage::DeleteMessage {
                meta: state.next_meta(),
                channel,
                message_id,
            })?;
        }
        _ => {
            toast(terminal, "Unknown command. Try /help", ToastKind::Error)?;
        }
    }

    Ok(())
}

fn handle_server_message(
    terminal: &mut TerminalSession,
    state: &mut ClientState,
    msg: ServerMessage,
) -> io::Result<()> {
    match msg {
        ServerMessage::ChannelList { channels, .. } => {
            state.channels = channels;
        }
        ServerMessage::JoinSuccess { channel, .. } => {
            state.current_channel = Some(channel.name.clone());
            toast(terminal, &format!("Joined #{}", channel.name), ToastKind::Info)?;
        }
        ServerMessage::JoinFailure { channel, reason, .. } => {
            toast(terminal, &format!("Join #{channel} failed: {reason}"), ToastKind::Error)?;
        }
        ServerMessage::HistoryChunk { channel, messages, .. } => {
            for m in messages {
                state.push_message(&channel, m);
            }
        }
        ServerMessage::MessageReceived { channel, message, .. } => {
            state.push_message(&channel, message);
        }
        ServerMessage::UserJoined { channel, user, .. } => {
            toast(terminal, &format!("{} joined #{}", user.username, channel), ToastKind::Info)?;
        }
        ServerMessage::UserLeft { channel, user, .. } => {
            toast(terminal, &format!("{} left #{}", user.username, channel), ToastKind::Info)?;
        }
        ServerMessage::SystemMessage { text, .. } => {
            toast(terminal, &text, ToastKind::Info)?;
        }
        ServerMessage::ProtocolError { text, .. } => {
            toast(terminal, &text, ToastKind::Error)?;
        }
        ServerMessage::MessageDeleted { channel, message_id, deleted_by, .. } => {
            state.remove_message(&channel, message_id);
            toast(terminal, &format!("Message deleted by {}", deleted_by), ToastKind::Info)?;
        }
        ServerMessage::UserPromoted { channel, username, new_role, promoted_by, .. } => {
            toast(terminal, &format!("{} promoted to {:?} by {} in #{}", username, new_role, promoted_by, channel), ToastKind::Info)?;
        }
        ServerMessage::UserDemoted { channel, username, demoted_by, .. } => {
            toast(terminal, &format!("{} demoted to User by {} in #{}", username, demoted_by, channel), ToastKind::Info)?;
        }
        ServerMessage::UserBanned { channel, username, banned_by, reason, .. } => {
            let reason_text = reason.unwrap_or_default();
            toast(terminal, &format!("{} banned from #{} by {}: {}", username, channel, banned_by, reason_text), ToastKind::Info)?;
        }
        ServerMessage::UserUnbanned { channel, username, unbanned_by, .. } => {
            toast(terminal, &format!("{} unbanned from #{} by {}", username, channel, unbanned_by), ToastKind::Info)?;
        }
        ServerMessage::UserKicked { channel, username, kicked_by, reason, .. } => {
            let reason_text = reason.unwrap_or_default();
            toast(terminal, &format!("{} kicked from #{} by {}: {}", username, channel, kicked_by, reason_text), ToastKind::Info)?;
        }
        ServerMessage::AdminList { admins, .. } => {
            let admin_names: Vec<_> = admins.iter().map(|a| format!("{} ({:?})", a.username, a.role)).collect();
            toast(terminal, &format!("Admins: {}", admin_names.join(", ")), ToastKind::Info)?;
        }
        ServerMessage::BanList { bans, .. } => {
            if bans.is_empty() {
                toast(terminal, "No bans in this channel", ToastKind::Info)?;
            } else {
                let ban_info: Vec<_> = bans.iter().map(|b| {
                    match b.banned_until {
                        Some(until) => format!("{} (until {})", b.username, until.format("%Y-%m-%d %H:%M")),
                        None => format!("{} (permanent)", b.username),
                    }
                }).collect();
                toast(terminal, &format!("Bans: {}", ban_info.join(", ")), ToastKind::Info)?;
            }
        }
        ServerMessage::LogList { logs, .. } => {
            for log in logs.iter().take(5) {
                toast(terminal, &format!("[{}] {} by {}: {}", log.timestamp.format("%H:%M:%S"), log.action, log.username, log.details), ToastKind::Info)?;
            }
        }
        ServerMessage::ChannelTypeChanged { channel, new_type, changed_by, .. } => {
            toast(terminal, &format!("#{} channel type changed to {:?} by {}", channel, new_type, changed_by), ToastKind::Info)?;
        }
        ServerMessage::ChannelDeleted { channel, deleted_by, .. } => {
            toast(terminal, &format!("Channel #{} deleted by {}", channel, deleted_by), ToastKind::Error)?;
            if state.current_channel.as_deref() == Some(channel.as_str()) {
                state.current_channel = None;
            }
        }
        ServerMessage::AdminError { reason, .. } => {
            toast(terminal, &format!("Admin error: {}", reason), ToastKind::Error)?;
        }
        ServerMessage::AuthChallenge { .. }
        | ServerMessage::AuthSuccess { .. }
        | ServerMessage::AuthFailure { .. }
        | ServerMessage::EcdhAck { .. } => {
            // handled earlier
        }
        ServerMessage::DMReceived { dm_id, sender_id, sender_server_id, sender_username, content, nonce, recipient_id, .. } => {
            use crate::dm_handler::FederatedStoredDM;
            use chrono::Utc;
            
            // Store the DM
            let dm = FederatedStoredDM {
                dm_id,
                sender_id,
                sender_server_id,
                sender_username: sender_username.clone(),
                recipient_id,
                recipient_server_id: None, // We are local
                content: content.clone(),
                nonce: nonce.clone(),
                timestamp: Utc::now(),
                is_read: false,
            };
            
            state.dm_conversations
                .entry(sender_id)
                .or_insert_with(Vec::new)
                .push(dm);
            
            // Increment unread count
            *state.unread_dms.entry(sender_id).or_insert(0) += 1;
            
            toast(terminal, &format!("New DM from {}", sender_username), ToastKind::Info)?;
        }
        ServerMessage::DMHistory { messages, .. } => {
            use crate::dm_handler::FederatedStoredDM;
            
            for msg in messages {
                let dm = FederatedStoredDM {
                    dm_id: msg.dm_id,
                    sender_id: msg.sender_id,
                    sender_server_id: None, // Local server
                    sender_username: format!("User {}", msg.sender_id),
                    recipient_id: msg.recipient_id,
                    recipient_server_id: None,
                    content: msg.content.clone(),
                    nonce: msg.nonce.clone(),
                    timestamp: msg.timestamp,
                    is_read: msg.is_read,
                };
                
                let other_user = if dm.sender_id == state.user.as_ref().map(|u| u.id).unwrap_or(0) {
                    dm.recipient_id
                } else {
                    dm.sender_id
                };
                
                state.dm_conversations
                    .entry(other_user)
                    .or_insert_with(Vec::new)
                    .push(dm);
            }
            
            toast(terminal, "DM history loaded", ToastKind::Info)?;
        }
        ServerMessage::DMReadReceipt { dm_id, .. } => {
            toast(terminal, &format!("DM {} read", dm_id), ToastKind::Info)?;
        }
        ServerMessage::DMDeliveryConfirmed { dm_id, delivered, error_message, .. } => {
            if delivered {
                toast(terminal, &format!("DM {} delivered", dm_id), ToastKind::Info)?;
            } else {
                toast(terminal, &format!("DM {} failed: {}", dm_id, error_message.unwrap_or_default()), ToastKind::Error)?;
            }
        }
        ServerMessage::FileTransferProposal { transfer_id, sender_id, sender_username, file_name, file_size, .. } => {
            use crate::state::{PendingFileTransfer, FileTransferStatus};
            
            let transfer = PendingFileTransfer {
                transfer_id,
                file_name: file_name.clone(),
                file_size,
                sender_id: Some(sender_id),
                sender_username: Some(sender_username.clone()),
                is_incoming: true,
                progress: 0,
                status: FileTransferStatus::Pending,
            };
            
            state.file_transfers.insert(transfer_id, transfer);
            
            toast(terminal, &format!("File transfer from {}: {} ({} bytes)", sender_username, file_name, file_size), ToastKind::Info)?;
        }
        ServerMessage::FileTransferAcceptanceRequired { transfer_id, .. } => {
            toast(terminal, &format!("File transfer {} waiting for acceptance", transfer_id), ToastKind::Info)?;
        }
        ServerMessage::FileTransferChunkAck { transfer_id, chunk_index, .. } => {
            if let Some(transfer) = state.file_transfers.get_mut(&transfer_id) {
                // Update progress (simplified)
                transfer.progress = chunk_index;
            }
        }
        ServerMessage::FileTransferStatus { transfer_id, status, progress_percent, .. } => {
            use darkrelayprotocol::protocol::TransferStatus;
            use crate::state::FileTransferStatus as ClientStatus;
            
            if let Some(transfer) = state.file_transfers.get_mut(&transfer_id) {
                transfer.progress = progress_percent;
                transfer.status = match status {
                    TransferStatus::Pending => ClientStatus::Pending,
                    TransferStatus::InProgress => ClientStatus::InProgress,
                    TransferStatus::Completed => ClientStatus::Completed,
                    TransferStatus::Failed => ClientStatus::Failed,
                    TransferStatus::Declined => ClientStatus::Declined,
                };
                
                if matches!(transfer.status, ClientStatus::Completed) {
                    toast(terminal, &format!("File transfer {} completed", transfer_id), ToastKind::Info)?;
                } else if matches!(transfer.status, ClientStatus::Failed) {
                    toast(terminal, &format!("File transfer {} failed", transfer_id), ToastKind::Error)?;
                }
            }
        }
        ServerMessage::FileTransferReady { transfer_id, .. } => {
            toast(terminal, &format!("File transfer {} ready", transfer_id), ToastKind::Info)?;
        }
        ServerMessage::FileTransferDeliveryConfirmed { transfer_id, delivered, error_message, .. } => {
            if delivered {
                toast(terminal, &format!("File transfer {} delivered", transfer_id), ToastKind::Info)?;
            } else {
                toast(terminal, &format!("File transfer {} failed: {}", transfer_id, error_message.unwrap_or_default()), ToastKind::Error)?;
            }
        }
    }

    Ok(())
}

fn draw(
    terminal: &mut TerminalSession,
    state: &ClientState,
    focus: Focus,
    input: &str,
    selected_channel_idx: usize,
) -> io::Result<()> {
    clear(terminal)?;

    let (cols, rows) = terminal::size()?;
    let cols_usize = cols as usize;
    let rows_usize = rows as usize;

    let channels_w = 20usize.min(cols_usize.saturating_sub(1));
    let info_w = 22usize.min(cols_usize.saturating_sub(channels_w + 1));
    let messages_w = cols_usize.saturating_sub(channels_w + info_w + 2);

    let encryption_indicator = if state.crypto.is_ready() {
        "🔒"
    } else {
        ""
    };
    
    let header = format!(
        "DarkRelay {} | Connected: {} @ {}",
        encryption_indicator,
        state
            .user
            .as_ref()
            .map(|u| u.username.as_str())
            .unwrap_or("<guest>"),
        state.server_addr
    );

    execute!(
        terminal.stdout(),
        cursor::MoveTo(0, 0),
        Print(pad(&header, cols_usize).with(Color::White).on(Color::DarkBlue)),
    )?;

    // Vertical separators
    for y in 1..rows_usize.saturating_sub(2) {
        execute!(
            terminal.stdout(),
            cursor::MoveTo(channels_w as u16, y as u16),
            Print("│".with(Color::DarkGrey)),
            cursor::MoveTo((channels_w + messages_w + 1) as u16, y as u16),
            Print("│".with(Color::DarkGrey)),
        )?;
    }

    let channels_title = if focus == Focus::Channels {
        " Channels ".with(Color::Black).on(Color::Grey)
    } else {
        " Channels ".with(Color::Grey)
    };

    execute!(
        terminal.stdout(),
        cursor::MoveTo(1, 1),
        Print(channels_title)
    )?;

    for (i, ch) in state
        .channels
        .iter()
        .enumerate()
        .take(rows_usize.saturating_sub(5))
    {
        let y = 3 + i;
        let prefix = if Some(&ch.name) == state.current_channel.as_ref() {
            "#"
        } else {
            " "
        };

        let label = pad(&format!("{prefix} {}", ch.name), channels_w.saturating_sub(2));

        let styled = if i == selected_channel_idx {
            label.with(Color::Yellow)
        } else {
            label.with(Color::White)
        };

        execute!(
            terminal.stdout(),
            cursor::MoveTo(1, y as u16),
            Print(styled)
        )?;
    }

    let messages_title = format!(
        " Messages ({}) ",
        state
            .current_channel
            .as_deref()
            .unwrap_or("no-channel")
    );

    execute!(
        terminal.stdout(),
        cursor::MoveTo((channels_w + 2) as u16, 1),
        Print(messages_title.with(Color::Grey)),
    )?;

    // Messages area
    let msgs = state.messages_for_current();
    let max_lines = rows_usize.saturating_sub(6);
    let start = msgs.len().saturating_sub(max_lines);

    for (i, m) in msgs.iter().skip(start).enumerate() {
        let y = 3 + i;
        let ts = m.timestamp.with_timezone(&Local).format("%H:%M:%S");
        
        // Try to decrypt the message if nonce is present
        let content_str = if let Some(ref nonce) = m.nonce {
            match state.crypto.decrypt(&m.content, nonce, state.current_channel.as_deref()) {
                Ok(plaintext) => String::from_utf8_lossy(&plaintext).to_string(),
                Err(_) => "[decryption failed]".to_string(),
            }
        } else {
            String::from_utf8_lossy(&m.content).to_string()
        };
        
        let line = format!("[{}] <{}>: {}", ts, m.username, content_str);

        let is_self = state.user.as_ref().map(|u| u.id) == Some(m.user_id);
        let styled = if is_self {
            truncate(&line, messages_w).with(Color::Cyan)
        } else {
            truncate(&line, messages_w).with(Color::White)
        };

        execute!(
            terminal.stdout(),
            cursor::MoveTo((channels_w + 2) as u16, y as u16),
            Print(styled)
        )?;
    }

    // Info pane
    if cols_usize >= 120 {
        execute!(
            terminal.stdout(),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 1),
            Print(" Info ".with(Color::Grey)),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 3),
            Print("Commands:".with(Color::White)),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 4),
            Print("/help".with(Color::DarkGrey)),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 5),
            Print("/list".with(Color::DarkGrey)),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 6),
            Print("/join <name>".with(Color::DarkGrey)),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 7),
            Print("/dm <user>".with(Color::DarkGrey)),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 8),
            Print("/promote".with(Color::DarkGrey)),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 9),
            Print("/ban <user>".with(Color::DarkGrey)),
            cursor::MoveTo((channels_w + messages_w + 3) as u16, 10),
            Print("/quit".with(Color::DarkGrey)),
        )?;
    }

    // Input
    let input_y = rows.saturating_sub(2);
    let input_prefix = if focus == Focus::Input { "> " } else { "  " };
    let input_line = format!("{}{}", input_prefix, input);
    execute!(
        terminal.stdout(),
        cursor::MoveTo(0, input_y),
        Print(pad(&input_line, cols_usize).with(Color::Black).on(Color::Grey)),
        cursor::MoveTo((input_prefix.len() + input.len()) as u16, input_y),
    )?;

    terminal.draw_toast()?;
    Ok(())
}

fn pad(s: &str, width: usize) -> String {
    if s.len() >= width {
        truncate(s, width)
    } else {
        format!("{s}{}", " ".repeat(width - s.len()))
    }
}

fn truncate(s: &str, width: usize) -> String {
    if s.len() <= width {
        s.to_string()
    } else {
        s.chars().take(width).collect()
    }
}
