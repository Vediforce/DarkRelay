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
                            if let Some(ch) = state.channels.get(selected_channel_idx) {
                                conn.send(ClientMessage::JoinChannel {
                                    meta: state.next_meta(),
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

    conn.send(ClientMessage::SendMessage {
        meta: state.next_meta(),
        channel,
        content: line.as_bytes().to_vec(),
        metadata: Vec::new(),
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
                "Commands: /list, /join <name> [password], /create <name> [password], /quit",
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
        ServerMessage::AuthChallenge { .. }
        | ServerMessage::AuthSuccess { .. }
        | ServerMessage::AuthFailure { .. } => {
            // handled earlier
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

    let header = format!(
        "DarkRelay | Connected: {} @ {}",
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
        let content = String::from_utf8_lossy(&m.content);
        let line = format!("[{}] <{}>: {}", ts, m.username, content);

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
    execute!(
        terminal.stdout(),
        cursor::MoveTo((channels_w + messages_w + 3) as u16, 1),
        Print(" Info ".with(Color::Grey)),
        cursor::MoveTo((channels_w + messages_w + 3) as u16, 3),
        Print("/help".with(Color::DarkGrey)),
        cursor::MoveTo((channels_w + messages_w + 3) as u16, 4),
        Print("/list".with(Color::DarkGrey)),
        cursor::MoveTo((channels_w + messages_w + 3) as u16, 5),
        Print("/join <name>".with(Color::DarkGrey)),
        cursor::MoveTo((channels_w + messages_w + 3) as u16, 6),
        Print("/quit".with(Color::DarkGrey)),
    )?;

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
