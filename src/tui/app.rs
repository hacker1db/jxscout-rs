//! TUI state and key handling, kept free of terminal I/O so it can be unit
//! tested.

use std::collections::VecDeque;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;

use crate::events::{AssetKind, Event};
use crate::pipeline::StatsSnapshot;
use crate::store::{AssetRow, FindingRow};

/// Max log lines kept in memory.
pub const LOG_CAP: usize = 2000;
/// Rows moved by PgUp/PgDn.
pub const PAGE: isize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Assets,
    Findings,
    Logs,
}

impl Focus {
    fn next(self, logs_visible: bool) -> Self {
        match (self, logs_visible) {
            (Self::Assets, _) => Self::Findings,
            (Self::Findings, true) => Self::Logs,
            (Self::Findings, false) | (Self::Logs, _) => Self::Assets,
        }
    }
}

/// What the event loop should do after a key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    /// The selected asset changed; reload its findings from the DB.
    ReloadFindings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetItem {
    pub url: String,
    pub kind: AssetKind,
    pub path: String,
    pub findings: usize,
}

impl From<AssetRow> for AssetItem {
    fn from(r: AssetRow) -> Self {
        Self {
            url: r.url,
            kind: r.kind,
            path: r.path,
            findings: 0,
        }
    }
}

/// Static info shown in the header (the active project is always visible,
/// which answers the "which project am I in?" confusion from upstream #27).
#[derive(Debug, Clone, Default)]
pub struct HeaderInfo {
    pub project: String,
    pub project_dir: String,
    pub listen: Option<String>,
}

pub struct App {
    pub header: HeaderInfo,
    pub assets: Vec<AssetItem>,
    pub findings: Vec<FindingRow>,
    pub logs: VecDeque<String>,
    pub stats: StatsSnapshot,
    pub focus: Focus,
    pub filter: String,
    pub filter_mode: bool,
    pub show_help: bool,
    pub help_scroll: u16,
    pub show_logs: bool,
    pub assets_state: ListState,
    pub findings_state: ListState,
    pub logs_state: ListState,
    /// Keep the log view pinned to the newest line until the user scrolls.
    pub follow_logs: bool,
}

/// Move a list selection by `delta`, clamped to `0..len`.
pub fn move_selection(state: &mut ListState, len: usize, delta: isize) {
    if len == 0 {
        state.select(None);
        return;
    }
    let cur = state.selected().unwrap_or(0) as isize;
    let next = (cur + delta).clamp(0, len as isize - 1);
    state.select(Some(next as usize));
}

impl App {
    pub fn new(header: HeaderInfo) -> Self {
        Self {
            header,
            assets: Vec::new(),
            findings: Vec::new(),
            logs: VecDeque::new(),
            stats: StatsSnapshot::default(),
            focus: Focus::Assets,
            filter: String::new(),
            filter_mode: false,
            show_help: false,
            help_scroll: 0,
            show_logs: true,
            assets_state: ListState::default(),
            findings_state: ListState::default(),
            logs_state: ListState::default(),
            follow_logs: true,
        }
    }

    /// Indices into `assets` that match the filter (case-insensitive).
    pub fn visible_assets(&self) -> Vec<usize> {
        let needle = self.filter.to_ascii_lowercase();
        self.assets
            .iter()
            .enumerate()
            .filter(|(_, a)| needle.is_empty() || a.url.to_ascii_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn selected_asset(&self) -> Option<&AssetItem> {
        let visible = self.visible_assets();
        self.assets_state
            .selected()
            .and_then(|i| visible.get(i))
            .map(|&i| &self.assets[i])
    }

    pub fn push_log(&mut self, line: String) {
        if self.logs.len() == LOG_CAP {
            self.logs.pop_front();
        }
        self.logs.push_back(line);
        if self.follow_logs {
            self.logs_state.select(Some(self.logs.len() - 1));
        }
    }

    /// Apply a pipeline event. Returns `true` if the selected asset's
    /// findings should be reloaded.
    pub fn on_event(&mut self, event: Event) -> bool {
        match event {
            Event::Log { level, message } => {
                self.push_log(format!("{level:>5} {message}"));
                false
            }
            Event::AssetSaved { url, kind, path } => {
                let selected_url = self.selected_asset().map(|a| a.url.clone());
                if let Some(a) = self.assets.iter_mut().find(|a| a.url == url) {
                    a.kind = kind;
                    a.path = path;
                } else {
                    self.assets.insert(
                        0,
                        AssetItem {
                            url,
                            kind,
                            path,
                            findings: 0,
                        },
                    );
                    // Keep the same asset selected when a new one is prepended.
                    if let Some(sel) = selected_url {
                        let visible = self.visible_assets();
                        let pos = visible.iter().position(|&i| self.assets[i].url == sel);
                        self.assets_state.select(pos);
                    }
                }
                if self.assets_state.selected().is_none() && !self.assets.is_empty() {
                    self.assets_state.select(Some(0));
                    return true;
                }
                false
            }
            Event::Analyzed { url, findings } => {
                if let Some(a) = self.assets.iter_mut().find(|a| a.url == url) {
                    a.findings = findings;
                }
                self.selected_asset().is_some_and(|a| a.url == url)
            }
            Event::ChunksDiscovered { .. } | Event::SourceMapReversed { .. } => false,
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        if self.filter_mode {
            return self.on_filter_key(key);
        }
        if self.show_help {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => self.show_help = false,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1)
                }
                KeyCode::PageDown => {
                    self.help_scroll = self.help_scroll.saturating_add(PAGE as u16)
                }
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(PAGE as u16),
                KeyCode::Home | KeyCode::Char('g') => self.help_scroll = 0,
                _ => {}
            }
            return Action::None;
        }
        let delta = match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('?') => {
                self.show_help = true;
                self.help_scroll = 0;
                return Action::None;
            }
            KeyCode::Char('/') => {
                self.filter_mode = true;
                return Action::None;
            }
            KeyCode::Char('l') => {
                self.show_logs = !self.show_logs;
                if !self.show_logs && self.focus == Focus::Logs {
                    self.focus = Focus::Assets;
                }
                return Action::None;
            }
            KeyCode::Tab => {
                self.focus = self.focus.next(self.show_logs);
                return Action::None;
            }
            KeyCode::Down | KeyCode::Char('j') => 1,
            KeyCode::Up | KeyCode::Char('k') => -1,
            KeyCode::PageDown => PAGE,
            KeyCode::PageUp => -PAGE,
            KeyCode::Home | KeyCode::Char('g') => isize::MIN / 2,
            KeyCode::End | KeyCode::Char('G') => isize::MAX / 2,
            _ => return Action::None,
        };
        self.scroll(delta)
    }

    fn scroll(&mut self, delta: isize) -> Action {
        match self.focus {
            Focus::Assets => {
                let before = self.assets_state.selected();
                let len = self.visible_assets().len();
                move_selection(&mut self.assets_state, len, delta);
                if self.assets_state.selected() != before {
                    return Action::ReloadFindings;
                }
            }
            Focus::Findings => {
                move_selection(&mut self.findings_state, self.findings.len(), delta);
            }
            Focus::Logs => {
                move_selection(&mut self.logs_state, self.logs.len(), delta);
                // Re-pin to the bottom when the user scrolls back to the end.
                self.follow_logs =
                    self.logs_state.selected() == Some(self.logs.len().saturating_sub(1));
            }
        }
        Action::None
    }

    fn on_filter_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.filter_mode = false;
                return Action::None;
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(c) => self.filter.push(c),
            _ => return Action::None,
        }
        // The filtered list changed: select its first row.
        let has_rows = !self.visible_assets().is_empty();
        self.assets_state.select(has_rows.then_some(0));
        Action::ReloadFindings
    }

    /// Replace the findings list (after a reload from the DB).
    pub fn set_findings(&mut self, findings: Vec<FindingRow>) {
        self.findings = findings;
        self.findings_state
            .select((!self.findings.is_empty()).then_some(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventKind;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    fn saved(app: &mut App, url: &str) {
        app.on_event(Event::AssetSaved {
            url: url.into(),
            kind: AssetKind::Js,
            path: "p".into(),
        });
    }

    #[test]
    fn navigation_is_clamped_and_scrolls() {
        let mut app = App::new(HeaderInfo::default());
        for i in 0..30 {
            saved(&mut app, &format!("https://a.test/{i}.js"));
        }
        assert_eq!(
            app.assets_state.selected(),
            Some(29),
            "selection follows the first asset"
        );
        app.on_key(key(KeyCode::Home));
        assert_eq!(app.assets_state.selected(), Some(0));
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.assets_state.selected(), Some(0));
        app.on_key(key(KeyCode::PageDown));
        assert_eq!(app.assets_state.selected(), Some(10));
        assert_eq!(app.on_key(key(KeyCode::End)), Action::ReloadFindings);
        assert_eq!(app.assets_state.selected(), Some(29));
    }

    #[test]
    fn filter_narrows_the_list() {
        let mut app = App::new(HeaderInfo::default());
        saved(&mut app, "https://a.test/main.js");
        saved(&mut app, "https://b.test/vendor.js");
        app.on_key(key(KeyCode::Char('/')));
        for c in "vendor".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.visible_assets().len(), 1);
        assert_eq!(
            app.selected_asset().unwrap().url,
            "https://b.test/vendor.js"
        );
    }

    /// Regression for upstream #18: the help/options view scrolls.
    #[test]
    fn help_popup_scrolls() {
        let mut app = App::new(HeaderInfo::default());
        app.on_key(key(KeyCode::Char('?')));
        assert!(app.show_help);
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::PageDown));
        assert_eq!(app.help_scroll, 11);
        app.on_key(key(KeyCode::Esc));
        assert!(!app.show_help);
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), Action::Quit);
    }

    #[test]
    fn logs_follow_until_scrolled() {
        let mut app = App::new(HeaderInfo::default());
        for i in 0..5 {
            app.push_log(format!("line {i}"));
        }
        assert_eq!(app.logs_state.selected(), Some(4));
        app.focus = Focus::Logs;
        app.on_key(key(KeyCode::Up));
        assert!(!app.follow_logs);
        app.push_log("new".into());
        assert_eq!(app.logs_state.selected(), Some(3));
    }
}
