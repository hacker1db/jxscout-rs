//! Rendering. Layouts adapt to the terminal size so the UI stays usable on
//! small terminals (≥ 40×12) instead of cutting content off (R-91, #18).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, Paragraph, Wrap};

use super::app::{App, Focus};
use crate::events::AssetKind;
use crate::text::clean;

pub const HELP: &str = "\
jxscout-rs — keys

  ↑/k  ↓/j      move selection
  PgUp / PgDn   move by a page
  g/Home G/End  first / last
  Tab           switch pane (assets → findings → logs)
  /             filter assets by URL (Enter/Esc to finish)
  l             toggle the log pane
  ?             toggle this help (scroll it with ↑↓ PgUp PgDn)
  q / Esc       quit (Ctrl-C works too)

Panes
  Assets    every HTML/JS file saved for the project, newest first.
            The number in brackets is the finding count.
  Findings  AST analysis results for the selected asset:
            category, line:column, and value.
  Logs      the same lines as the log file.

Ingest
  POST captured traffic to /ingest (see README), or run
  `jxscout-rs ingest-urls` / `ingest-har` in another terminal
  against the same project.

Files
  Assets are saved under the project directory shown in the
  header; open it in your editor. Reversed source maps live in
  <host>/(sourcemaps)/.
";

fn pane_block(title: String, focused: bool) -> Block<'static> {
    let style = if focused {
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    Block::bordered().title(title).border_style(style)
}

fn kind_tag(kind: AssetKind) -> Span<'static> {
    match kind {
        AssetKind::Html => Span::styled("html", Style::new().fg(Color::Magenta)),
        AssetKind::Js => Span::styled("js  ", Style::new().fg(Color::Yellow)),
        AssetKind::Source => Span::styled("src ", Style::new().fg(Color::Green)),
    }
}

/// A rectangle of `w`×`h` (clamped) centered in `area`.
fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

pub fn draw(f: &mut Frame<'_>, app: &mut App) {
    let area = f.area();
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(f, app, header);
    draw_footer(f, app, footer);

    // Small terminals: show only the focused pane.
    let tiny = body.height < 12 || body.width < 60;
    let logs_visible = app.show_logs && !tiny;
    let (main, logs) = if logs_visible {
        let [m, l] =
            Layout::vertical([Constraint::Percentage(68), Constraint::Percentage(32)]).areas(body);
        (m, Some(l))
    } else {
        (body, None)
    };

    if tiny {
        match app.focus {
            Focus::Assets => draw_assets(f, app, main),
            Focus::Findings => draw_findings(f, app, main),
            Focus::Logs => draw_logs(f, app, main),
        }
    } else {
        let split = if main.width >= 110 {
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        } else {
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
        };
        let [a, b] = split.areas(main);
        draw_assets(f, app, a);
        draw_findings(f, app, b);
        if let Some(l) = logs {
            draw_logs(f, app, l);
        }
    }

    if app.show_help {
        let popup = centered(area, 70, area.height.saturating_sub(2).max(6));
        // Clamp scrolling to the wrapped content so PgDn/End can't scroll
        // into blank space (Codex M3 #9).
        let inner_w = popup.width.saturating_sub(2).max(1) as usize;
        let inner_h = popup.height.saturating_sub(2) as usize;
        let content_lines: usize = HELP
            .lines()
            .map(|l| l.chars().count().max(1).div_ceil(inner_w))
            .sum();
        let max_scroll = content_lines.saturating_sub(inner_h) as u16;
        app.help_scroll = app.help_scroll.min(max_scroll);
        f.render_widget(Clear, popup);
        let p = Paragraph::new(HELP)
            .block(pane_block(
                " help (↑↓ to scroll, Esc to close) ".into(),
                true,
            ))
            .wrap(Wrap { trim: false })
            .scroll((app.help_scroll, 0));
        f.render_widget(p, popup);
    }
}

fn draw_header(f: &mut Frame<'_>, app: &App, area: Rect) {
    let s = &app.stats;
    let mut spans = vec![
        Span::styled(" jxscout-rs ", Style::new().bold().black().on_cyan()),
        Span::raw(" project: "),
        Span::styled(app.header.project.clone(), Style::new().bold()),
    ];
    if let Some(l) = &app.header.listen {
        spans.push(Span::raw(format!("  ingest: {l}")));
    }
    if let Some(t) = &app.header.token {
        spans.push(Span::styled(
            format!("  token: {t}"),
            Style::new().fg(Color::Yellow),
        ));
    }
    spans.push(Span::raw(format!(
        "  saved {} · findings {} · chunks {} · maps {} · errors {}",
        s.saved, s.findings, s.chunks, s.sourcemaps, s.errors
    )));
    spans.push(Span::styled(
        format!("  {}", app.header.project_dir),
        Style::new().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_footer(f: &mut Frame<'_>, app: &App, area: Rect) {
    let line = if app.filter_mode {
        Line::from(vec![
            Span::styled(" filter: ", Style::new().bold()),
            Span::raw(app.filter.clone()),
            Span::styled("▏", Style::new().fg(Color::Cyan)),
        ])
    } else {
        Line::from(Span::styled(
            " q quit · ↑↓ jk move · PgUp/PgDn · Tab pane · / filter · l logs · ? help",
            Style::new().fg(Color::DarkGray),
        ))
    };
    f.render_widget(Paragraph::new(line), area);
}

fn draw_assets(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    let visible = app.visible_assets();
    let items: Vec<ListItem<'_>> = visible
        .iter()
        .map(|&i| {
            let a = &app.assets[i];
            ListItem::new(Line::from(vec![
                kind_tag(a.kind),
                Span::raw(" "),
                Span::styled(
                    format!("[{:>3}] ", a.findings),
                    Style::new().fg(Color::Cyan),
                ),
                Span::raw(clean(&a.url).into_owned()),
            ]))
        })
        .collect();
    let title = if app.filter.is_empty() {
        format!(" assets ({}) ", visible.len())
    } else {
        format!(
            " assets ({}/{}) filter: {} ",
            visible.len(),
            app.assets.len(),
            app.filter
        )
    };
    let list = List::new(items)
        .block(pane_block(title, app.focus == Focus::Assets))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, area, &mut app.assets_state);
}

fn draw_findings(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    let items: Vec<ListItem<'_>> = app
        .findings
        .iter()
        .map(|fd| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    clean(&fd.category).into_owned(),
                    Style::new().fg(Color::Green),
                ),
                Span::styled(
                    format!(" {}:{} ", fd.line, fd.column),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::raw(clean(&fd.value.replace('\n', "⏎")).into_owned()),
            ]))
        })
        .collect();
    let title = match app.selected_asset() {
        Some(a) => format!(" findings ({}) — {} ", app.findings.len(), clean(&a.path)),
        None => " findings ".to_string(),
    };
    let list = List::new(items)
        .block(pane_block(title, app.focus == Focus::Findings))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, area, &mut app.findings_state);
}

fn draw_logs(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    let items: Vec<ListItem<'_>> = app.logs.iter().map(|l| ListItem::new(l.as_str())).collect();
    let list = List::new(items)
        .block(pane_block(
            format!(" logs ({}) ", app.logs.len()),
            app.focus == Focus::Logs,
        ))
        .highlight_style(Style::new().fg(Color::Cyan));
    f.render_stateful_widget(list, area, &mut app.logs_state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;
    use crate::store::FindingRow;
    use crate::tui::app::HeaderInfo;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn app_with_data() -> App {
        let mut app = App::new(HeaderInfo {
            project: "demo".into(),
            project_dir: "/tmp/demo".into(),
            listen: Some("127.0.0.1:3333".into()),
            token: None,
        });
        for i in 0..50 {
            app.on_event(Event::AssetSaved {
                url: format!("https://app.test/static/js/{i}.js"),
                kind: AssetKind::Js,
                path: format!("app.test/static/js/{i}.js"),
            });
        }
        app.set_findings(vec![FindingRow {
            asset_url: "u".into(),
            rule_id: "events".into(),
            category: "Client Behavior/Events/postMessage".into(),
            value: "w.postMessage(x)".into(),
            line: 3,
            column: 5,
        }]);
        app
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..h {
            for x in 0..w {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn renders_wide_layout() {
        let mut app = app_with_data();
        let screen = render(&mut app, 140, 40);
        assert!(screen.contains("project: demo"));
        assert!(screen.contains("assets (50)"));
        assert!(screen.contains("postMessage"));
        assert!(screen.contains("logs"));
    }

    /// Regression for upstream #18: tiny terminals still show the selection
    /// and keep it in view after scrolling to the end.
    #[test]
    fn small_terminal_keeps_selection_visible() {
        let mut app = app_with_data();
        app.assets_state.select(Some(0));
        let screen = render(&mut app, 40, 12);
        assert!(screen.contains("assets"));
        assert!(!screen.contains(" logs "), "logs hidden when tiny");
        app.assets_state.select(Some(49));
        let screen = render(&mut app, 40, 12);
        assert!(screen.contains("▶"), "selected row rendered:\n{screen}");
    }

    #[test]
    fn help_popup_renders_scrolled() {
        let mut app = app_with_data();
        app.show_help = true;
        let top = render(&mut app, 80, 14);
        assert!(top.contains("jxscout-rs — keys"));
        app.help_scroll = 12;
        let scrolled = render(&mut app, 80, 14);
        assert!(!scrolled.contains("jxscout-rs — keys"));
        assert!(scrolled.contains("Panes") || scrolled.contains("Assets"));
        // End clamps to the last page instead of a blank popup.
        app.help_scroll = u16::MAX;
        let end = render(&mut app, 40, 12);
        assert!(app.help_scroll < u16::MAX);
        assert!(end.contains("(sourcemaps)"), "last line visible:\n{end}");
    }
}
