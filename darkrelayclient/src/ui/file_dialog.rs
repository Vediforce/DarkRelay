use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Gauge, Paragraph, Wrap},
    Frame,
};

#[derive(Clone)]
pub struct FileTransferDialog {
    pub transfer_id: u64,
    pub file_name: String,
    pub file_size: u64,
    pub sender_id: Option<u64>,
    pub recipient_id: Option<u64>,
    pub progress: u32,
    pub status: FileTransferStatus,
}

#[derive(Clone)]
pub enum FileTransferStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
    Declined,
}

impl FileTransferDialog {
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(match self.status {
                FileTransferStatus::Completed => Style::default().fg(Color::Green),
                FileTransferStatus::Failed => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Cyan),
            })
            .title("File Transfer");

        let inner = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(inner);

        let title = if let Some(sender_id) = self.sender_id {
            format!("Incoming file from User {}", sender_id)
        } else if let Some(recipient_id) = self.recipient_id {
            format!("Outgoing file to User {}", recipient_id)
        } else {
            "File Transfer".to_string()
        };

        let file_info = format!("{} ({:.2} MB)", 
            self.file_name, 
            self.file_size as f64 / (1024.0 * 1024.0)
        );

        let title_paragraph = Paragraph::new(title);
        f.render_widget(title_paragraph, chunks[0]);

        let file_info_paragraph = Paragraph::new(file_info);
        f.render_widget(file_info_paragraph, chunks[1]);

        let progress_gauge = Gauge::default()
            .percent(self.progress.min(100) as u16)
            .label(format!("{}%", self.progress.min(100)));
        f.render_widget(progress_gauge, chunks[2]);
    }
}