use std::{
    io,
    io::Write,
    time::Duration,
};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    style::{Color, Print, Stylize},
    terminal,
};

use crate::{
    state::AuthMode,
    ui::{clear, TerminalSession},
};

pub struct AuthDialogOutput {
    pub server_ip: String,
    pub username: String,
    pub password: String,
    pub mode: AuthMode,
}

#[derive(Clone, Copy, Debug)]
enum Field {
    Server,
    Username,
    Password,
    Buttons,
}

#[derive(Clone, Copy, Debug)]
enum Button {
    Login,
    Register,
    Exit,
}

pub async fn run(terminal: &mut TerminalSession) -> io::Result<Option<AuthDialogOutput>> {
    let mut server_ip = "127.0.0.1".to_string();
    let mut username = String::new();
    let mut password = String::new();

    let mut field = Field::Server;
    let mut button = Button::Login;

    loop {
        draw(terminal, &server_ip, &username, &password, field, button, None)?;

        if event::poll(Duration::from_millis(50))? {
            let ev = event::read()?;
            if let Event::Key(key) = ev {
                if handle_key(
                    key,
                    &mut server_ip,
                    &mut username,
                    &mut password,
                    &mut field,
                    &mut button,
                )? {
                    match button {
                        Button::Exit => return Ok(None),
                        Button::Login => {
                            return Ok(Some(AuthDialogOutput {
                                server_ip,
                                username,
                                password,
                                mode: AuthMode::Login,
                            }));
                        }
                        Button::Register => {
                            return Ok(Some(AuthDialogOutput {
                                server_ip,
                                username,
                                password: String::new(),
                                mode: AuthMode::Register,
                            }));
                        }
                    }
                }
            }
        }
    }
}

pub fn draw_processing(terminal: &mut TerminalSession, spinner: &str) -> io::Result<()> {
    clear(terminal)?;

    let (cols, rows) = terminal::size()?;
    let x = cols / 2;
    let y = rows / 2;

    execute!(
        terminal.stdout(),
        cursor::MoveTo(x.saturating_sub(10), y),
        Print(format!("Authenticating... {spinner}").with(Color::Cyan)),
    )?;

    terminal.draw_toast()?;
    Ok(())
}

fn handle_key(
    key: KeyEvent,
    server_ip: &mut String,
    username: &mut String,
    password: &mut String,
    field: &mut Field,
    button: &mut Button,
) -> io::Result<bool> {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        *button = Button::Exit;
        return Ok(true);
    }

    match key.code {
        KeyCode::Tab => {
            *field = match field {
                Field::Server => Field::Username,
                Field::Username => Field::Password,
                Field::Password => Field::Buttons,
                Field::Buttons => Field::Server,
            };
        }
        KeyCode::BackTab => {
            *field = match field {
                Field::Server => Field::Buttons,
                Field::Username => Field::Server,
                Field::Password => Field::Username,
                Field::Buttons => Field::Password,
            };
        }
        KeyCode::Left => {
            if matches!(field, Field::Buttons) {
                *button = match button {
                    Button::Login => Button::Exit,
                    Button::Register => Button::Login,
                    Button::Exit => Button::Register,
                };
            }
        }
        KeyCode::Right => {
            if matches!(field, Field::Buttons) {
                *button = match button {
                    Button::Login => Button::Register,
                    Button::Register => Button::Exit,
                    Button::Exit => Button::Login,
                };
            }
        }
        KeyCode::Enter => {
            if matches!(field, Field::Buttons) {
                return Ok(true);
            }
            *field = match field {
                Field::Server => Field::Username,
                Field::Username => Field::Password,
                Field::Password => Field::Buttons,
                Field::Buttons => Field::Buttons,
            };
        }
        KeyCode::Esc => {
            *button = Button::Exit;
            return Ok(true);
        }
        KeyCode::Char(ch) => {
            match field {
                Field::Server => push_char(server_ip, ch),
                Field::Username => push_char(username, ch),
                Field::Password => push_char(password, ch),
                Field::Buttons => {}
            };
        }
        KeyCode::Backspace => match field {
            Field::Server => pop_char(server_ip),
            Field::Username => pop_char(username),
            Field::Password => pop_char(password),
            Field::Buttons => {}
        },
        _ => {}
    }

    Ok(false)
}

fn push_char(s: &mut String, ch: char) {
    if !ch.is_control() {
        s.push(ch);
    }
}

fn pop_char(s: &mut String) {
    s.pop();
}

fn draw(
    terminal: &mut TerminalSession,
    server_ip: &str,
    username: &str,
    password: &str,
    field: Field,
    button: Button,
    error: Option<&str>,
) -> io::Result<()> {
    clear(terminal)?;

    execute!(
        terminal.stdout(),
        cursor::MoveTo(2, 1),
        Print("DarkRelay v1.0".with(Color::White).bold()),
    )?;

    execute!(
        terminal.stdout(),
        cursor::MoveTo(2, 3),
        Print("Server IP:".with(Color::Grey)),
        cursor::MoveTo(14, 3),
        Print(style_field(server_ip, matches!(field, Field::Server))),
    )?;

    execute!(
        terminal.stdout(),
        cursor::MoveTo(2, 5),
        Print("Username:".with(Color::Grey)),
        cursor::MoveTo(14, 5),
        Print(style_field(username, matches!(field, Field::Username))),
    )?;

    let masked = "*".repeat(password.chars().count());
    execute!(
        terminal.stdout(),
        cursor::MoveTo(2, 7),
        Print("Password:".with(Color::Grey)),
        cursor::MoveTo(14, 7),
        Print(style_field(&masked, matches!(field, Field::Password))),
    )?;

    let login = style_button("Login", button == Button::Login, matches!(field, Field::Buttons));
    let register = style_button(
        "Register",
        button == Button::Register,
        matches!(field, Field::Buttons),
    );
    let exit = style_button("Exit", button == Button::Exit, matches!(field, Field::Buttons));

    execute!(
        terminal.stdout(),
        cursor::MoveTo(2, 10),
        Print(login),
        cursor::MoveTo(12, 10),
        Print(register),
        cursor::MoveTo(25, 10),
        Print(exit),
    )?;

    if let Some(err) = error {
        execute!(
            terminal.stdout(),
            cursor::MoveTo(2, 12),
            Print(err.with(Color::Red)),
        )?;
    }

    terminal.draw_toast()?;
    terminal.stdout().flush()?;
    Ok(())
}

fn style_field(text: &str, active: bool) -> String {
    if active {
        format!("> {text}")
    } else {
        format!("  {text}")
    }
}

fn style_button(label: &str, selected: bool, active: bool) -> String {
    if active {
        if selected {
            format!("[{}]", label)
        } else {
            format!(" {} ", label)
        }
    } else {
        format!(" {} ", label)
    }
}
