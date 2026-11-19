//! Progress events.
//!
//! The pipeline publishes [`Event`]s on a [`tokio::sync::broadcast`] channel.
//! The TUI subscribes to render live progress; tests subscribe to assert
//! what happened. Log lines are bridged in via [`LogLayer`], a small
//! `tracing` layer, so the TUI's log pane shows the same lines as the log file.

use std::fmt::Write as _;

use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event as TracingEvent, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// What kind of asset was saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetKind {
    Html,
    Js,
    /// A file reconstructed from a source map's `sourcesContent`.
    Source,
}

impl AssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Js => "js",
            Self::Source => "source",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "html" => Some(Self::Html),
            "js" => Some(Self::Js),
            "source" => Some(Self::Source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A log line (bridged from `tracing`).
    Log { level: Level, message: String },
    /// An asset was written to disk.
    AssetSaved {
        url: String,
        kind: AssetKind,
        path: String,
    },
    /// AST analysis finished for an asset.
    Analyzed { url: String, findings: usize },
    /// Chunk discovery scheduled `count` new URLs from `url`.
    ChunksDiscovered { url: String, count: usize },
    /// A source map was found and `sources` files were reconstructed.
    SourceMapReversed {
        js_url: String,
        map_url: String,
        sources: usize,
    },
}

/// Cheap-to-clone handle for publishing events.
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish an event. Having no subscribers is fine, so the error is ignored.
    pub fn emit(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

/// A `tracing` layer that republishes formatted log events on an [`EventBus`].
pub struct LogLayer {
    bus: EventBus,
}

impl LogLayer {
    pub fn new(bus: EventBus) -> Self {
        Self { bus }
    }
}

/// Collects an event's fields into a single `message key=value …` string.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &TracingEvent<'_>, _ctx: Context<'_, S>) {
        let mut v = MessageVisitor::default();
        event.record(&mut v);
        self.bus.emit(Event::Log {
            level: *event.metadata().level(),
            message: format!("{}{}", v.message, v.fields),
        });
    }
}
