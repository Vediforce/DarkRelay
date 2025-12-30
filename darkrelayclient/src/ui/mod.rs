pub mod auth_dialog;
pub mod main_layout;

use std::{
    io::{self, Stdout, Write},
    time::{Duration, Instant},
};

use crossterm::{
    cursor,
    event,
    execute,
    style::{self, Color, Print, Stylize},
    terminal::{self, ClearType},
};

pub struct TerminalSession {
    stdout: Stdout,
    toast: Option<ToastState>,
}

struct ToastState {
    text: String,
    kind: ToastKind,
    created_at: Instant,
    ttl: Duration,
}

#[derive(Debug, Clone, Copy)]
pub enum ToastKind {
    Info,
    Error,
}

impl TerminalSession {
    pub fn new() -> io::Result<Self> {
        let mut stdout = io::stdout();
        terminal::enable_raw_mode()?;
        execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide)?;

        Ok(Self {
            stdout,
            toast: None,
        })
    }

    pub fn stdout(&mut self) -> &mut Stdout {
        &mut self.stdout
    }

    pub fn set_toast(&mut self, kind: ToastKind, text: String) {
        self.toast = Some(ToastState {
            text,
            kind,
            created_at: Instant::now(),
            ttl: Duration::from_secs(3),
        });
    }

    pub fn draw_toast(&mut self) -> io::Result<()> {
        let Some(toast) = &self.toast else {
            return Ok(());
        };

        if toast.created_at.elapsed() > toast.ttl {
            self.toast = None;
            return Ok(());
        }

        let (cols, _) = terminal::size()?;
        let text = match toast.kind {
            ToastKind::Info => toast.text.clone(),
            ToastKind::Error => toast.text.clone(),
        };

        let width = text.len().min(cols as usize);
        let x = cols.saturating_sub(width as u16 + 2);

        let styled = match toast.kind {
            ToastKind::Info => text.with(Color::Cyan),
            ToastKind::Error => text.with(Color::Red),
        };

        execute!(
            self.stdout,
            cursor::MoveTo(x, 0),
            style::SetBackgroundColor(Color::Black),
            Print(styled),
            style::ResetColor
        )?;

        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = execute!(self.stdout, cursor::Show, terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

pub fn toast(terminal: &mut TerminalSession, text: &str, kind: ToastKind) -> io::Result<()> {
    terminal.set_toast(kind, text.to_string());
    Ok(())
}

pub fn clear(terminal: &mut TerminalSession) -> io::Result<()> {
    execute!(terminal.stdout, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    Ok(())
}

pub fn show_error_dialog(terminal: &mut TerminalSession, text: &str) -> io::Result<()> {
    clear(terminal)?;

    let (cols, rows) = terminal::size()?;
    let y = rows / 2;

    execute!(terminal.stdout, cursor::MoveTo(2, y), Print(text.with(Color::Red)))?;
    execute!(
        terminal.stdout,
        cursor::MoveTo(2, y.saturating_add(2)),
        Print("Press any key to continue...".with(Color::DarkGrey))
    )?;
    terminal.stdout.flush()?;

    loop {
        if event::poll(Duration::from_millis(250))? {
            let _ = event::read()?;
            break;
        }
    }

    Ok(())
}
