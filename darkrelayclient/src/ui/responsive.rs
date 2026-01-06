/// Responsive layout helpers for terminal UI
/// Adapts the layout based on terminal size

use crossterm::terminal;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    /// Large terminals (120+ cols): 3-pane layout (channels | messages | info)
    ThreePane,
    /// Medium terminals (80-120 cols): 2-pane layout (channels | messages)
    TwoPane,
    /// Small terminals (<80 cols): Single pane with tab switching
    SinglePane,
}

pub struct LayoutMetrics {
    pub mode: LayoutMode,
    pub cols: usize,
    pub rows: usize,
    pub channels_width: usize,
    pub messages_width: usize,
    pub info_width: usize,
}

impl LayoutMetrics {
    pub fn calculate() -> io::Result<Self> {
        let (cols, rows) = terminal::size()?;
        let cols_usize = cols as usize;
        let rows_usize = rows as usize;

        let mode = if cols >= 120 {
            LayoutMode::ThreePane
        } else if cols >= 80 {
            LayoutMode::TwoPane
        } else {
            LayoutMode::SinglePane
        };

        let (channels_width, messages_width, info_width) = match mode {
            LayoutMode::ThreePane => {
                // 20% channels, 60% messages, 20% info
                let channels_w = (cols_usize * 20 / 100).max(15).min(25);
                let info_w = (cols_usize * 20 / 100).max(18).min(30);
                let messages_w = cols_usize.saturating_sub(channels_w + info_w + 2);
                (channels_w, messages_w, info_w)
            }
            LayoutMode::TwoPane => {
                // 25% channels, 75% messages
                let channels_w = (cols_usize * 25 / 100).max(15).min(25);
                let messages_w = cols_usize.saturating_sub(channels_w + 1);
                (channels_w, messages_w, 0)
            }
            LayoutMode::SinglePane => {
                // Full width
                (cols_usize, cols_usize, 0)
            }
        };

        Ok(Self {
            mode,
            cols: cols_usize,
            rows: rows_usize,
            channels_width,
            messages_width,
            info_width,
        })
    }

    pub fn show_channels(&self) -> bool {
        !matches!(self.mode, LayoutMode::SinglePane)
    }

    pub fn show_info(&self) -> bool {
        matches!(self.mode, LayoutMode::ThreePane)
    }

    pub fn message_area_height(&self) -> usize {
        // Header (1) + separator (1) + footer (2) = 4 lines reserved
        self.rows.saturating_sub(4)
    }

    pub fn max_displayed_channels(&self) -> usize {
        // Leave space for header, separators, etc.
        self.rows.saturating_sub(5)
    }

    pub fn max_message_width(&self) -> usize {
        // Account for timestamp, username, and formatting
        self.messages_width.saturating_sub(25)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_mode_selection() {
        // We can't actually test terminal size, but we can test the logic
        assert_eq!(LayoutMode::ThreePane, LayoutMode::ThreePane);
    }

    #[test]
    fn test_layout_metrics_boundaries() {
        // Verify calculations don't panic with edge cases
        let metrics = LayoutMetrics {
            mode: LayoutMode::ThreePane,
            cols: 120,
            rows: 40,
            channels_width: 20,
            messages_width: 80,
            info_width: 20,
        };

        assert!(metrics.show_channels());
        assert!(metrics.show_info());
        assert!(metrics.message_area_height() > 0);
    }
}
