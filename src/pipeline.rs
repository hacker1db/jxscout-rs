//! The processing pipeline (SPEC R-40..R-43, R-54).
//!
//! ```text
//!  Captured ──► scope check ──► (fetch if no body) ──► classify
//!                                                       │
//!                     ┌─────────────── HTML ────────────┴──────────── JS ──────────────┐
//!                     ▼                                                                ▼
//!          save page, record relations,                     beautify ► save ► analyze (rules)
//!          spawn <script src> as Referred,                    │                     │
//!          analyze inline scripts                        chunk discovery       source maps
//!                                                        (spawn as Chunk)    (reverse + save)
//! ```
//!
//! Every stage reports errors with the URL and keeps going (R-43): a bad
//! file never stops the pipeline. Work fans out as tokio tasks tracked by a
//! [`TaskTracker`], so `ingest-urls` can wait for the whole tree to finish.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;
use url::Url;

use crate::config::Config;
use crate::events::{AssetKind, Event, EventBus};
use crate::js::{self, chunks, html, sourcemap};
use crate::model::{AuthContext, Captured, CapturedResponse, Headers, Origin};
use crate::net::{FetchContext, Fetcher, Purpose};
use crate::rules::{self, Finding, Registry};
use crate::store::{AssetRow, AssetStore, Db, paths};

/// Counters shown in the TUI and printed after `ingest-*` commands.
#[derive(Debug, Default)]
pub struct Stats {
    pub received: AtomicUsize,
    pub out_of_scope: AtomicUsize,
    pub saved: AtomicUsize,
    pub unchanged: AtomicUsize,
    pub errors: AtomicUsize,
    pub findings: AtomicUsize,
    pub chunks: AtomicUsize,
    pub sourcemaps: AtomicUsize,
}

/// A plain copy of [`Stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct StatsSnapshot {
    pub received: usize,
    pub out_of_scope: usize,
    pub saved: usize,
    pub unchanged: usize,
    pub errors: usize,
    pub findings: usize,
    pub chunks: usize,
    pub sourcemaps: usize,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        let l = |a: &AtomicUsize| a.load(Ordering::Relaxed);
        StatsSnapshot {
            received: l(&self.received),
            out_of_scope: l(&self.out_of_scope),
            saved: l(&self.saved),
            unchanged: l(&self.unchanged),
            errors: l(&self.errors),
            findings: l(&self.findings),
            chunks: l(&self.chunks),
            sourcemaps: l(&self.sourcemaps),
        }
    }
}

fn bump(a: &AtomicUsize, n: usize) {
    a.fetch_add(n, Ordering::Relaxed);
}

/// Max queued + in-progress items before [`Pipeline::submit`] refuses.
pub const MAX_PENDING: usize = 20_000;

/// Cheap-to-clone handle to the pipeline.
#[derive(Clone)]
pub struct Pipeline {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: Config,
    fetcher: Fetcher,
    store: AssetStore,
    db: Db,
    rules: Registry,
    events: EventBus,
    /// URLs already handled this session (derived items only).
    seen: Mutex<HashSet<String>>,
    tracker: TaskTracker,
    /// Items submitted but not finished (bounded admission).
    pending: Arc<AtomicUsize>,
    /// Bounds CPU-heavy parse/analyze work.
    cpu: Semaphore,
    stats: Stats,
}

/// Where the SQLite database for a project lives: next to, not inside, the
/// project folder so it doesn't clutter the tree you open in your editor.
pub fn db_path(output_dir: &Path, project: &str) -> PathBuf {
    output_dir.join(".jxscout-rs").join(format!("{project}.db"))
}

impl Pipeline {
    pub fn new(cfg: Config, events: EventBus) -> anyhow::Result<Self> {
        Self::with_rules(cfg, events, Registry::default())
    }

    pub fn with_rules(cfg: Config, events: EventBus, rules: Registry) -> anyhow::Result<Self> {
        let store = AssetStore::new(&cfg.output_dir, &cfg.project)
            .with_context(|| format!("creating project dir in {}", cfg.output_dir.display()))?;
        let db_file = db_path(&cfg.output_dir, &cfg.project);
        std::fs::create_dir_all(db_file.parent().expect("db path has a parent"))?;
        let db = Db::open(&db_file).with_context(|| format!("opening {}", db_file.display()))?;
        let fetcher = Fetcher::new(
            cfg.fetch.clone(),
            Arc::new(cfg.scope.clone()),
            cfg.download_referred_js,
        )?;
        let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                fetcher,
                store,
                db,
                rules,
                events,
                seen: Mutex::new(HashSet::new()),
                tracker: TaskTracker::new(),
                pending: Arc::new(AtomicUsize::new(0)),
                cpu: Semaphore::new(cpus),
                stats: Stats::default(),
            }),
        })
    }

    pub fn config(&self) -> &Config {
        &self.inner.cfg
    }
    pub fn db(&self) -> &Db {
        &self.inner.db
    }
    pub fn store(&self) -> &AssetStore {
        &self.inner.store
    }
    pub fn events(&self) -> &EventBus {
        &self.inner.events
    }
    pub fn stats(&self) -> StatsSnapshot {
        self.inner.stats.snapshot()
    }

    /// Queue an item; returns immediately. Returns `false` (and drops the
    /// item) when [`MAX_PENDING`] items are already queued, so a flood of
    /// ingest requests or a huge chunk fan-out can't exhaust memory.
    pub fn submit(&self, item: Captured) -> bool {
        let pending = Arc::clone(&self.inner.pending);
        if pending.fetch_add(1, Ordering::AcqRel) >= MAX_PENDING {
            pending.fetch_sub(1, Ordering::AcqRel);
            tracing::warn!(url = %item.request.url, "pipeline overloaded, dropping item");
            return false;
        }
        let this = self.clone();
        self.inner.tracker.spawn(async move {
            this.process(item).await;
            pending.fetch_sub(1, Ordering::AcqRel);
        });
        true
    }

    /// Like [`submit`](Self::submit) but waits for queue space instead of
    /// dropping: backpressure for file-based sources.
    pub async fn submit_wait(&self, item: Captured) {
        while self.inner.pending.load(Ordering::Acquire) >= MAX_PENDING {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        self.submit(item);
    }

    /// Items queued or in progress.
    pub fn pending(&self) -> usize {
        self.inner.pending.load(Ordering::Acquire)
    }

    /// Wait until every submitted item and everything it spawned is done.
    ///
    /// Meant for a single owner (the CLI command or a test) between
    /// batches; concurrent callers could reopen the tracker early.
    pub async fn wait_idle(&self) {
        self.inner.tracker.close();
        self.inner.tracker.wait().await;
        self.inner.tracker.reopen();
    }

    /// Process one item to completion (children are spawned, not awaited).
    pub async fn process(&self, item: Captured) {
        let url = item.request.url.clone();
        let derived = !item.origin.is_captured();
        if let Err(e) = self.process_inner(item).await {
            bump(&self.inner.stats.errors, 1);
            tracing::warn!(%url, "processing failed: {e:#}");
            // Release the claim so a later discovery can retry this URL.
            if derived {
                self.unmark_seen(&url);
            }
        }
    }

    /// Returns `false` if `url` was already seen this session.
    fn mark_seen(&self, url: &Url) -> bool {
        let mut seen = self.inner.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.insert(url.as_str().to_string())
    }

    fn unmark_seen(&self, url: &Url) {
        let mut seen = self.inner.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.remove(url.as_str());
    }

    async fn process_inner(&self, item: Captured) -> anyhow::Result<()> {
        let inner = &self.inner;
        bump(&inner.stats.received, 1);
        let url = item.request.url.clone();

        if item.origin.is_captured() {
            let decision = inner.cfg.scope.check(&url);
            if !decision.is_in() {
                bump(&inner.stats.out_of_scope, 1);
                // R-24 / upstream #9: say *which* request and *why*.
                tracing::debug!(
                    %url,
                    host = url.host_str().unwrap_or_default(),
                    origin = item.origin.as_str(),
                    "request is not in scope: {decision}"
                );
                return Ok(());
            }
        }
        if item.depth > inner.cfg.discovery.max_depth {
            tracing::debug!(%url, depth = item.depth, "max discovery depth reached");
            return Ok(());
        }
        if !item.origin.is_captured() && !self.mark_seen(&url) {
            return Ok(());
        }
        // Chunk names are content-hashed: one we stored in an earlier run
        // doesn't need downloading again (R-35).
        if item.origin == Origin::Chunk && inner.db.asset_hash(url.as_str())?.is_some() {
            tracing::debug!(%url, "chunk already stored, skipping download");
            return Ok(());
        }

        // Credentials ride along from the first captured request (R-60).
        let auth = item.auth.clone().or_else(|| {
            let h = item
                .request
                .headers
                .filtered(&inner.cfg.fetch.forward_headers);
            (!h.0.is_empty()).then(|| AuthContext {
                origin: url.origin(),
                headers: h,
            })
        });

        // `final_url` is where the bytes really came from (after redirects);
        // relative references resolve against it. `url` stays the DB key.
        let (response, final_url) = match item.response {
            Some(r) => (r, url.clone()),
            None => {
                let purpose = match item.origin {
                    Origin::Referred => Purpose::Referred,
                    Origin::Chunk => Purpose::Chunk,
                    _ => Purpose::Captured,
                };
                let ctx = FetchContext::new(purpose)
                    .with_parent(item.parent.as_ref())
                    .with_auth(auth.as_ref());
                let r = inner
                    .fetcher
                    .get(&url, &ctx)
                    .await
                    .with_context(|| format!("fetching {url}"))?;
                (
                    CapturedResponse {
                        status: r.status,
                        headers: r.headers,
                        body: r.body,
                    },
                    r.url,
                )
            }
        };

        if !(200..300).contains(&response.status) {
            tracing::debug!(%url, status = response.status, "skipping non-2xx response");
            return Ok(());
        }

        let ctx = ItemCtx {
            url: &url,
            base: &final_url,
            origin: item.origin,
            depth: item.depth,
            parent: item.parent.as_ref(),
            auth: auth.as_ref(),
        };
        match classify(&url, &response.headers, &response.body) {
            Some(AssetKind::Html) if matches!(item.origin, Origin::Chunk | Origin::Referred) => {
                // Asked for JS, got HTML: almost always a login redirect
                // (upstream #31). Don't save it as JS.
                tracing::warn!(
                    %url,
                    "expected JavaScript but got HTML (auth required? check cookies / --forward-auth)"
                );
            }
            Some(AssetKind::Html) => self.handle_html(&ctx, &response).await?,
            Some(AssetKind::Js) => {
                let text = String::from_utf8_lossy(&response.body).into_owned();
                let asset = JsAsset {
                    db_url: url.to_string(),
                    base: final_url.clone(),
                    rel_path: paths::asset_path(&url, AssetKind::Js),
                    text,
                    headers: response.headers.clone(),
                    find_sourcemaps: true,
                };
                self.handle_js(&ctx, asset).await?;
            }
            Some(AssetKind::Source) | None => {
                tracing::debug!(%url, content_type = ?response.headers.content_type(), "ignoring non HTML/JS asset");
            }
        }
        Ok(())
    }

    async fn handle_html(&self, cx: &ItemCtx<'_>, resp: &CapturedResponse) -> anyhow::Result<()> {
        let inner = &self.inner;
        let text = String::from_utf8_lossy(&resp.body).into_owned();
        let rel = paths::asset_path(cx.url, AssetKind::Html);
        self.save(cx, AssetKind::Html, &rel, text.as_bytes())
            .await?;

        let scripts = html::extract(cx.base, &text);
        for script in scripts.external {
            inner.db.add_relation(cx.url.as_str(), script.as_str())?;
            self.spawn_child(script, Origin::Referred, cx);
        }
        for (i, body) in scripts.inline.into_iter().enumerate() {
            let asset = JsAsset {
                db_url: format!("{}#inline-{}", cx.url, i + 1),
                base: cx.base.clone(),
                rel_path: paths::inline_script_path(cx.url, i + 1),
                text: body,
                headers: Headers::new(),
                find_sourcemaps: false,
            };
            if let Err(e) = self.handle_js(cx, asset).await {
                tracing::warn!(url = %cx.url, "inline script {} failed: {e:#}", i + 1);
            }
        }
        Ok(())
    }

    fn spawn_child(&self, url: Url, origin: Origin, cx: &ItemCtx<'_>) {
        let mut child = Captured::url_only(url, origin);
        child.depth = cx.depth + 1;
        child.parent = Some(cx.base.clone());
        child.auth = cx.auth.cloned();
        self.submit(child);
    }

    async fn save(
        &self,
        cx: &ItemCtx<'_>,
        kind: AssetKind,
        rel: &Path,
        bytes: &[u8],
    ) -> anyhow::Result<PathBuf> {
        self.save_as(cx.url.as_str(), cx, kind, rel, bytes).await
    }

    async fn save_as(
        &self,
        db_url: &str,
        cx: &ItemCtx<'_>,
        kind: AssetKind,
        rel: &Path,
        bytes: &[u8],
    ) -> anyhow::Result<PathBuf> {
        let inner = &self.inner;
        // File I/O is blocking: keep it off the async worker threads.
        let used = {
            let store = inner.store.clone();
            let (rel, data) = (rel.to_path_buf(), bytes.to_vec());
            tokio::task::spawn_blocking(move || store.write(&rel, &data))
                .await
                .map_err(|e| anyhow::anyhow!("write task failed: {e}"))?
        }
        .with_context(|| format!("saving {db_url} to {}", rel.display()))?;
        inner.db.upsert_asset(&AssetRow {
            url: db_url.to_string(),
            kind,
            path: used.to_string_lossy().into_owned(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
            origin: cx.origin.as_str().to_string(),
            parent_url: cx.parent.map(|p| p.to_string()),
        })?;
        bump(&inner.stats.saved, 1);
        tracing::info!(url = db_url, path = %used.display(), "saved {}", kind.as_str());
        inner.events.emit(Event::AssetSaved {
            url: db_url.to_string(),
            kind,
            path: used.to_string_lossy().into_owned(),
        });
        Ok(used)
    }

    async fn handle_js(&self, cx: &ItemCtx<'_>, asset: JsAsset) -> anyhow::Result<()> {
        let inner = &self.inner;
        // R-35: skip unchanged files we already processed in an earlier run.
        let hash = sha256_hex(asset.text.as_bytes());
        if inner.db.asset_hash(&asset.db_url)?.as_deref() == Some(hash.as_str()) {
            bump(&inner.stats.unchanged, 1);
            tracing::debug!(url = %asset.db_url, "unchanged since last run, skipping");
            return Ok(());
        }

        // Parsing is CPU-bound: run it on the blocking pool, bounded by a
        // semaphore. A panic inside oxc surfaces as a JoinError instead of
        // taking down the worker (R-43).
        let analysis = {
            let _permit = inner.cpu.acquire().await.expect("semaphore never closed");
            let text = asset.text.clone();
            let base = asset.base.clone();
            let this = self.clone();
            tokio::task::spawn_blocking(move || this.analyze_js(&text, &base))
                .await
                .map_err(|e| anyhow::anyhow!("analysis task panicked: {e}"))?
        };

        if let Some(err) = &analysis.parse_error {
            // R-42 / upstream #19: keep the original text and carry on.
            tracing::warn!(url = %asset.db_url, "could not parse JavaScript, saved unformatted: {err}");
        }
        let content = analysis.beautified.as_deref().unwrap_or(&asset.text);
        // Store the hash of the *original* text so "unchanged" detection
        // compares like with like.
        self.save_as(
            &asset.db_url,
            cx,
            AssetKind::Js,
            &asset.rel_path,
            content.as_bytes(),
        )
        .await?;
        inner.db.upsert_asset_hash(&asset.db_url, &hash)?;

        if inner.cfg.discovery.analyze {
            inner
                .db
                .replace_findings(&asset.db_url, &analysis.findings)?;
            bump(&inner.stats.findings, analysis.findings.len());
            inner.events.emit(Event::Analyzed {
                url: asset.db_url.clone(),
                findings: analysis.findings.len(),
            });
        }

        if inner.cfg.discovery.chunks && !analysis.chunks.urls.is_empty() {
            let n = analysis.chunks.urls.len();
            bump(&inner.stats.chunks, n);
            tracing::info!(
                url = %asset.db_url,
                bruteforced = analysis.chunks.bruteforced,
                "discovered {n} chunk(s)"
            );
            inner.events.emit(Event::ChunksDiscovered {
                url: asset.db_url.clone(),
                count: n,
            });
            for chunk in analysis.chunks.urls {
                self.spawn_child(chunk, Origin::Chunk, cx);
            }
        }

        if inner.cfg.discovery.sourcemaps && asset.find_sourcemaps {
            self.find_sourcemap(cx, &asset).await;
        }
        Ok(())
    }

    /// Beautify, run rules, find chunks. Synchronous; called on the blocking pool.
    fn analyze_js(&self, text: &str, base: &Url) -> JsAnalysis {
        let cfg = &self.inner.cfg.discovery;
        let (beautified, parse_error) = match js::beautify(text) {
            Ok(b) => (Some(b), None),
            Err(e) => (None, Some(e.message)),
        };
        let mut out = JsAnalysis {
            beautified,
            parse_error,
            ..JsAnalysis::default()
        };
        // Analyze the text we save, so line numbers match the file on disk.
        let Some(code) = out.beautified.as_deref() else {
            return out;
        };
        let alloc = oxc_allocator::Allocator::default();
        let Ok(program) = js::parse(&alloc, code) else {
            return out;
        };
        if cfg.analyze {
            out.findings = rules::analyze(code, &program, &self.inner.rules);
        }
        if cfg.chunks {
            out.chunks = chunks::discover(
                &program,
                base,
                chunks::Limits {
                    bruteforce: cfg.bruteforce_limit,
                    max_urls: cfg.max_chunks_per_script,
                },
            );
        }
        out
    }

    /// Try every source-map candidate; the first that validates wins (R-71).
    async fn find_sourcemap(&self, cx: &ItemCtx<'_>, asset: &JsAsset) {
        let inner = &self.inner;
        let js_url = &asset.base;
        for candidate in sourcemap::candidates(js_url, &asset.headers, &asset.text) {
            let (map_url, bytes) = match candidate {
                sourcemap::Candidate::Inline { bytes } => (format!("{js_url}#inline-map"), bytes),
                sourcemap::Candidate::Remote { url, why } => {
                    let ctx = FetchContext::new(Purpose::SourceMap)
                        .with_parent(Some(js_url))
                        .with_auth(cx.auth);
                    match inner.fetcher.get(&url, &ctx).await {
                        Ok(r) if r.is_success() => (url.to_string(), r.body),
                        Ok(r) => {
                            tracing::debug!(%url, status = r.status, why, "source map candidate rejected");
                            continue;
                        }
                        Err(e) => {
                            tracing::debug!(%url, why, "source map candidate failed: {e}");
                            continue;
                        }
                    }
                }
            };
            match sourcemap::reverse(&bytes, inner.cfg.discovery.max_sourcemap_sources) {
                Ok(rev) => {
                    let written = self.write_sources(js_url, &rev);
                    if !rev.missing_content.is_empty() {
                        tracing::info!(
                            map = %map_url,
                            "{} source(s) listed without sourcesContent",
                            rev.missing_content.len()
                        );
                    }
                    if let Err(e) = inner.db.record_sourcemap(&asset.db_url, &map_url, written) {
                        tracing::warn!("recording source map: {e}");
                    }
                    bump(&inner.stats.sourcemaps, 1);
                    tracing::info!(js = %js_url, map = %map_url, "reversed {written} source file(s)");
                    inner.events.emit(Event::SourceMapReversed {
                        js_url: asset.db_url.clone(),
                        map_url,
                        sources: written,
                    });
                    return;
                }
                Err(e) => tracing::debug!(map = %map_url, "not a valid source map: {e}"),
            }
        }
        tracing::debug!(js = %js_url, "no source map found");
    }

    fn write_sources(&self, js_url: &Url, rev: &sourcemap::Reversed) -> usize {
        let mut written = 0;
        for src in &rev.sources {
            let Some(rel) = paths::sourcemap_source_path(js_url, &src.name) else {
                continue;
            };
            match self.inner.store.write(&rel, src.content.as_bytes()) {
                Ok(_) => written += 1,
                Err(e) => tracing::warn!(source = %src.name, "could not write source: {e}"),
            }
        }
        written
    }
}

/// Per-item context passed down the handlers.
struct ItemCtx<'a> {
    /// The requested URL (database key, file path).
    url: &'a Url,
    /// The final URL after redirects (base for relative references).
    base: &'a Url,
    origin: Origin,
    depth: u32,
    parent: Option<&'a Url>,
    auth: Option<&'a AuthContext>,
}

/// A script to process (external file or inline `<script>`).
struct JsAsset {
    /// Key in the database (`<page>#inline-N` for inline scripts).
    db_url: String,
    /// URL that relative chunk / map references resolve against.
    base: Url,
    rel_path: PathBuf,
    text: String,
    headers: Headers,
    find_sourcemaps: bool,
}

#[derive(Default)]
struct JsAnalysis {
    beautified: Option<String>,
    parse_error: Option<String>,
    findings: Vec<Finding>,
    chunks: chunks::Discovery,
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Decide whether a response is HTML, JS, or something we ignore.
pub fn classify(url: &Url, headers: &Headers, body: &[u8]) -> Option<AssetKind> {
    let ct = headers.content_type().unwrap_or_default();
    let starts_with_markup = body
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<');
    if ct.contains("html") {
        return Some(AssetKind::Html);
    }
    if ct.contains("javascript") || ct.contains("ecmascript") {
        return if starts_with_markup {
            Some(AssetKind::Html)
        } else {
            Some(AssetKind::Js)
        };
    }
    let path = url.path().to_ascii_lowercase();
    let js_ext = [".js", ".mjs", ".cjs"].iter().any(|e| path.ends_with(e));
    let ignorable_ct = ["json", "css", "image/", "font/", "video/", "audio/"]
        .iter()
        .any(|t| ct.contains(t));
    if js_ext && !ignorable_ct {
        return if starts_with_markup {
            Some(AssetKind::Html)
        } else {
            Some(AssetKind::Js)
        };
    }
    if (path.ends_with(".html") || path.ends_with(".htm") || ct.is_empty()) && starts_with_markup {
        return Some(AssetKind::Html);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(ct: &str) -> Headers {
        let mut h = Headers::new();
        if !ct.is_empty() {
            h.push("Content-Type", ct);
        }
        h
    }

    #[test]
    fn classification() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert_eq!(
            classify(&u("https://a/x"), &h("text/html; charset=utf-8"), b"<html>"),
            Some(AssetKind::Html)
        );
        assert_eq!(
            classify(&u("https://a/x"), &h("application/javascript"), b"var a"),
            Some(AssetKind::Js)
        );
        assert_eq!(
            classify(&u("https://a/x.js"), &h(""), b"var a"),
            Some(AssetKind::Js)
        );
        assert_eq!(
            classify(&u("https://a/x.js?v=1"), &h("text/plain"), b"var a"),
            Some(AssetKind::Js)
        );
        // A login page served for a .js URL is HTML (upstream #31).
        assert_eq!(
            classify(&u("https://a/x.js"), &h("text/plain"), b"  <!doctype html>"),
            Some(AssetKind::Html)
        );
        assert_eq!(
            classify(&u("https://a/x.css"), &h("text/css"), b"a{}"),
            None
        );
        assert_eq!(
            classify(&u("https://a/x.json"), &h("application/json"), b"{}"),
            None
        );
        assert_eq!(
            classify(&u("https://a/img.png"), &h("image/png"), b"\x89PNG"),
            None
        );
    }
}
