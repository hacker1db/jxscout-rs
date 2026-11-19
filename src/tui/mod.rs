//! The terminal UI (SPEC R-90, R-91).
//!
//! `app` holds state and key handling (pure, unit-tested); `ui` renders it.
//! [`run`] is the async event loop that glues keyboard input, pipeline
//! events, and a periodic stats refresh together with `tokio::select!`.

pub mod app;
pub mod ui;

use std::time::Duration;

use crossterm::event::{Event as TermEvent, EventStream, KeyEventKind};
use futures::StreamExt;
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;

use crate::pipeline::Pipeline;
use app::{Action, App, AssetItem, HeaderInfo};

/// (Re)load the asset list, keeping the same asset selected by URL so a
/// reordered snapshot can't silently switch the findings pane to another
/// asset.
fn load_assets(pipeline: &Pipeline, app: &mut App) {
    let selected_url = app.selected_asset().map(|a| a.url.clone());
    match pipeline.db().assets_with_counts(10_000) {
        Ok(rows) => {
            app.assets = rows
                .into_iter()
                .map(|(r, findings)| AssetItem {
                    findings,
                    ..AssetItem::from(r)
                })
                .collect();
        }
        Err(e) => app.push_log(format!("ERROR loading assets: {e}")),
    }
    app.select_url(selected_url.as_deref());
}

fn reload_findings(pipeline: &Pipeline, app: &mut App) {
    let url = app.selected_asset().map(|a| a.url.clone());
    let findings = match url {
        Some(u) => pipeline.db().findings(Some(&u), None).unwrap_or_default(),
        None => Vec::new(),
    };
    app.set_findings(findings);
}

/// Run the TUI until the user quits or `shutdown` fires. The terminal is
/// restored on exit and on panic (ratatui installs a panic hook).
pub async fn run(
    pipeline: Pipeline,
    header: HeaderInfo,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let mut app = App::new(header);
    // Subscribe before loading so no event falls in the gap.
    let mut events = pipeline.events().subscribe();
    load_assets(&pipeline, &mut app);
    reload_findings(&pipeline, &mut app);

    let mut terminal = ratatui::init();
    let mut keys = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(500));

    let result: anyhow::Result<()> = async {
        loop {
            terminal.draw(|f| ui::draw(f, &mut app))?;
            tokio::select! {
                maybe_key = keys.next() => match maybe_key {
                    Some(Ok(TermEvent::Key(k))) if k.kind == KeyEventKind::Press => {
                        match app.on_key(k) {
                            Action::Quit => break,
                            Action::ReloadFindings => reload_findings(&pipeline, &mut app),
                            Action::None => {}
                        }
                    }
                    Some(Ok(_)) => {} // resize etc.: just redraw
                    Some(Err(e)) => return Err(e.into()),
                    None => break,
                },
                ev = events.recv() => match ev {
                    Ok(ev) => if app.on_event(ev) { reload_findings(&pipeline, &mut app) },
                    // We fell behind a burst of events: resync from the DB.
                    Err(RecvError::Lagged(_)) => {
                        load_assets(&pipeline, &mut app);
                        reload_findings(&pipeline, &mut app);
                    }
                    Err(RecvError::Closed) => break,
                },
                _ = tick.tick() => app.stats = pipeline.stats(),
                _ = shutdown.cancelled() => break,
            }
        }
        Ok(())
    }
    .await;

    ratatui::restore();
    result
}
