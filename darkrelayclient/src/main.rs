mod connection;
mod state;
mod ui;
mod crypto;

use std::{
    env,
    io,
    time::Duration,
};

use chrono::Utc;
use darkrelayprotocol::protocol::{ClientMessage, MessageMeta, ServerMessage};
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::{
    connection::Connection,
    state::{AuthMode, ClientState},
};

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,darkrelayclient=debug"));
    let layer = fmt::layer().with_target(true);
    tracing_subscriber::registry().with(filter).with(layer).init();
}

#[tokio::main]
async fn main() -> io::Result<()> {
    init_tracing();

    let special_key = env::var("DARKRELAY_SPECIAL_KEY").unwrap_or_else(|_| "darkrelay-dev-key".to_string());

    let mut terminal = ui::TerminalSession::new()?;

    loop {
        let Some(dialog) = ui::auth_dialog::run(&mut terminal).await? else {
            return Ok(());
        };

        let server_addr = format!("{}:8080", dialog.server_ip);

        let connection = match Connection::connect(&server_addr, Duration::from_secs(5)).await {
            Ok(c) => c,
            Err(e) => {
                ui::show_error_dialog(&mut terminal, &format!("Connection failed: {e}"))?;
                continue;
            }
        };

        let mut state = ClientState::new(server_addr.clone());
        let mut conn = connection;

        if let Err(e) = handshake_special_key(&mut terminal, &mut state, &mut conn, &special_key).await {
            error!(error = %e, "special key handshake failed");
            ui::show_error_dialog(&mut terminal, &format!("Auth failed: {e}"))?;
            continue;
        }

        if let Err(e) = handshake_ecdh(&mut terminal, &mut state, &mut conn).await {
            error!(error = %e, "ECDH handshake failed");
            ui::show_error_dialog(&mut terminal, &format!("Encryption setup failed: {e}"))?;
            continue;
        }

        let auth_res = match dialog.mode {
            AuthMode::Register => {
                let meta = state.next_meta();
                authenticate_with_spinner(
                    &mut terminal,
                    &mut state,
                    &mut conn,
                    ClientMessage::RegisterUser {
                        meta,
                        username: dialog.username,
                    },
                )
                .await
            }
            AuthMode::Login => {
                let meta = state.next_meta();
                authenticate_with_spinner(
                    &mut terminal,
                    &mut state,
                    &mut conn,
                    ClientMessage::Login {
                        meta,
                        username: dialog.username,
                        password: dialog.password,
                    },
                )
                .await
            }
        };

        if let Err(e) = auth_res {
            ui::show_error_dialog(&mut terminal, &format!("Auth failed: {e}"))?;
            continue;
        }

        info!(user = state.user.as_ref().map(|u| u.username.as_str()).unwrap_or("<none>"), "authenticated");

        // Some servers already send ChannelList after auth; request one anyway.
        conn.send(ClientMessage::ListChannels {
            meta: state.next_meta(),
        })?;

        if let Err(e) = ui::main_layout::run(&mut terminal, &mut state, &mut conn).await {
            ui::show_error_dialog(&mut terminal, &format!("Runtime error: {e}"))?;
        }

        // If main layout returns, restart the auth dialog.
        state.reset();
    }
}

async fn handshake_special_key(
    terminal: &mut ui::TerminalSession,
    state: &mut ClientState,
    conn: &mut Connection,
    special_key: &str,
) -> io::Result<()> {
    let first = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server did not challenge"))??;

    match first {
        Some(ServerMessage::AuthChallenge { .. }) => {
            conn.send(ClientMessage::Auth {
                meta: state.next_meta(),
                key: special_key.to_string(),
            })?;
        }
        Some(other) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected AuthChallenge, got {other:?}"),
            ));
        }
        None => {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "server closed"));
        }
    }

    // Next message can be SystemMessage or AuthFailure.
    let resp = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "auth response timeout"))??;

    if let Some(ServerMessage::AuthFailure { reason, .. }) = resp {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }

    ui::toast(terminal, "Special key accepted", ui::ToastKind::Info)?;
    Ok(())
}

async fn handshake_ecdh(
    terminal: &mut ui::TerminalSession,
    state: &mut ClientState,
    conn: &mut Connection,
) -> io::Result<()> {
    let handshake = crypto::EcdhHandshake::new();
    
    conn.send(ClientMessage::EcdhPublicKey {
        meta: state.next_meta(),
        public_key: handshake.public_key().to_vec(),
    })?;

    let resp = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ECDH response timeout"))??;

    match resp {
        Some(ServerMessage::EcdhAck { public_key, .. }) => {
            let shared_secret = handshake.complete(&public_key)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            
            // Store the shared secret in crypto state
            state.crypto.ecdh_secret = Some(shared_secret);
            
            ui::toast(terminal, "🔒 Encryption enabled", ui::ToastKind::Info)?;
            Ok(())
        }
        Some(ServerMessage::ProtocolError { text, .. }) => {
            Err(io::Error::new(io::ErrorKind::Other, text))
        }
        Some(other) => {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected EcdhAck, got {:?}", other),
            ))
        }
        None => {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "server closed"))
        }
    }
}

async fn authenticate_with_spinner(
    terminal: &mut ui::TerminalSession,
    state: &mut ClientState,
    conn: &mut Connection,
    request: ClientMessage,
) -> io::Result<()> {
    conn.send(request)?;

    let frames = ["|", "/", "-", "\\"];
    let mut idx = 0usize;

    loop {
        ui::auth_dialog::draw_processing(terminal, frames[idx % frames.len()])?;
        idx += 1;

        match tokio::time::timeout(Duration::from_millis(120), conn.recv()).await {
            Ok(Ok(Some(ServerMessage::AuthSuccess { user, generated_password, .. }))) => {
                state.user = Some(user);
                if let Some(pw) = generated_password {
                    state.generated_password = Some(pw.clone());
                    ui::toast(terminal, &format!("Registered. Password: {pw}"), ui::ToastKind::Info)?;
                }
                return Ok(());
            }
            Ok(Ok(Some(ServerMessage::AuthFailure { reason, .. }))) => {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
            }
            Ok(Ok(Some(other))) => {
                // Ignore noise and keep waiting.
                tracing::debug!(?other, "auth waiting");
            }
            Ok(Ok(None)) => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "server closed"));
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_) => {
                // tick spinner (timeout)
            }
        }
    }
}

#[allow(dead_code)]
fn meta(id: u64) -> MessageMeta {
    MessageMeta::new(id, Utc::now())
}
