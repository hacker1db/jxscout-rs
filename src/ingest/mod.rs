//! Ingest sources (SPEC R-10..R-14).
//!
//! Everything that feeds the pipeline implements [`IngestSource`]. The
//! trait uses `async fn`, which has been allowed in traits since Rust 1.75.
//! Such traits can't be used as `dyn IngestSource` (the returned futures
//! have different types per implementation), so callers use generics:
//! `fn run_source(s: impl IngestSource)`. Making a dyn-compatible version is
//! one of the exercises in `CHALLENGES.md`.

pub mod har;
pub mod server;
pub mod urls;

use std::future::Future;

use crate::pipeline::Pipeline;

/// Summary returned when a source finishes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IngestReport {
    /// Items handed to the pipeline.
    pub submitted: usize,
    /// Items rejected before reaching the pipeline (bad URL, bad entry …).
    pub rejected: usize,
}

/// A source of captured traffic.
pub trait IngestSource {
    /// Human-readable name for logs.
    fn name(&self) -> &'static str;

    /// Feed items into `pipeline` until the source is exhausted (or, for
    /// servers, until shutdown). Implementations call
    /// [`Pipeline::submit`] and do not wait for processing to finish.
    fn run(self, pipeline: Pipeline) -> impl Future<Output = anyhow::Result<IngestReport>> + Send;
}
