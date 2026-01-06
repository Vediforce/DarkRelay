use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use darkrelayprotocol::protocol::StoredDM;

pub struct DMView {
    pub conversation: Vec<StoredDM>,
    pub scrolled_to_bottom: bool,
    pub user_id: u64,
}

impl DMView {
    pub fn new(user_id: u64) -> Self {
        Self {
            conversation: Vec::new(),
            scrolled_to_bottom: true,
            user_id,
        }
    }

    pub fn add_message(&mut self, dm: StoredDM) {
        self.conversation.push(dm);
        self.scrolled_to_bottom = true;
    }

    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(3)].as_ref())
            .split(area);

        // DM conversation area
        let messages: Vec<ListItem> = self
            .conversation
            .iter()
            .map(|dm| {
                let timestamp = dm.timestamp.format("%H:%M").to_string();
                let (sender_label, style) = if dm.sender_id == self.user_id {
                    ("You", Style::default().fg(Color::Green))
                } else {
                    ("Them", Style::default().fg(Color::Blue))
                };

                let content = format!("[{}] {}: {} {}", 
                    timestamp, 
                    sender_label,
                    "[ENCRYPTED MESSAGE]",
                    if dm.is_read { "✓" } else { ""
                });
                
                ListItem::new(content).style(style)
            })
            .collect();

        let messages_list = List::new(messages)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue))
                    .title("Direct Messages"),
            )
            .highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");

        let mut state = ratatui::widgets::ListState::default();
        state.select(if self.conversation.is_empty() { None } else { Some(self.conversation.len() - 1) });
        
        f.render_stateful_widget(messages_list, chunks[0], &mut state);

        // Input area
        let input = Paragraph::new("Type your message... (Commands: /file, /quit)");
        f.render_widget(input, chunks[1]);
    }
}

pub fn draw_dm_sidebar<B: Backend>(f: &mut Frame<B>, active_conversations: &[(u64, usize)], area: Rect) {
    let items: Vec<ListItem> = active_conversations
        .iter()
        .map(|(user_id, unread_count)| {
            let unread_text = if *unread_count > 0 {
                format!(" [NEW: {}]", unread_count)
            } else {
                String::new()
            };
            ListItem::new(format!("@User {}{}", user_id, unread_text)).style(
                Style::default().fg(if *unread_count > 0 {
                    Color::Red
                } else {
                    Color::White
                }),
            )
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title("DM Conversations"),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_widget(list, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ratatui::backend::TestBackend;

    #[test]
    fn test_dm_view_creation() {
        let dm_view = DMView::new(1);
        assert!(dm_view.conversation.is_empty());
        assert_eq!(dm_view.user_id, 1);
    }

    #[test]
    fn test_add_message_to_dm_view() {
        let mut dm_view = DMView::new(1);
        let dm = StoredDM {
            dm_id: 1,
            sender_id: 1,
            recipient_id: 2,
            content: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            timestamp: Utc::now(),
            is_read: false,
        };
        
        dm_view.add_message(dm);
        assert_eq!(dm_view.conversation.len(), 1);
        assert!(dm_view.scrolled_to_bottom);
    }
}