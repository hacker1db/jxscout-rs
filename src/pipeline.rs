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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;
use url::Url;

use crate::budget::{Budget, Reservation};
use crate::config::Config;
use crate::events::{AssetKind, Event, EventBus};
use crate::js::{self, chunks, html, sourcemap};
use crate::model::{AuthContext, Captured, CapturedResponse, Headers, Origin};
use crate::net::{FetchContext, Fetcher, Purpose, decode};
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
/// Default memory budget for response bodies held by the pipeline
/// (captured bodies, fetched pages/scripts/chunks, and source maps).
pub const DEFAULT_MEMORY_BUDGET: usize = 512 * 1024 * 1024;

/// Everything the pipeline schedules goes through [`Pipeline::admit`] as
/// one of these, so every unit of work takes a slot *and* has its bytes
/// covered by a [`Reservation`].
enum Work {
    /// A captured or discovered request/response.
    Item(Captured),
    /// The source-map lookup for one script: every candidate (remote and
    /// inline) in priority order, stopping at the first that validates.
    Map(MapJob),
}

impl Work {
    /// Bytes this work already holds in memory when admitted.
    fn bytes(&self) -> usize {
        match self {
            Work::Item(item) => body_len(item),
            Work::Map(j) => j.inline_bytes(),
        }
    }

    fn describe(&self) -> String {
        match self {
            Work::Item(item) => item.request.url.to_string(),
            Work::Map(j) => format!("source map for {}", j.js_url),
        }
    }
}

/// Holds a work slot and the work's memory for as long as it runs.
struct AdmitGuard {
    items: Arc<AtomicUsize>,
    _memory: Option<Reservation>,
}

impl Drop for AdmitGuard {
    fn drop(&mut self) {
        self.items.fetch_sub(1, Ordering::AcqRel);
    }
}

fn body_len(item: &Captured) -> usize {
    item.response.as_ref().map_or(0, |r| r.body.len())
}

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
    /// Outstanding discovery work per owning script (see [`Track`]).
    discovery: Mutex<HashMap<String, Track>>,
    tracker: TaskTracker,
    /// Work items queued or running (bounded admission).
    items: Arc<AtomicUsize>,
    /// Memory budget for every body the pipeline holds.
    budget: Budget,
    /// Bounds CPU-heavy parse/analyze work.
    cpu: Semaphore,
    stats: Stats,
}

/// Where the SQLite database for a project lives: next to, not inside, the
/// project folder so it doesn't clutter the tree you open in your editor.
pub fn db_path(output_dir: &Path, project: &str) -> PathBuf {
    output_dir
        .join(crate::store::META_DIR)
        .join(format!("{project}.db"))
}

impl Pipeline {
    pub fn new(cfg: Config, events: EventBus) -> anyhow::Result<Self> {
        Self::with_rules(cfg, events, Registry::default())
    }

    pub fn with_rules(cfg: Config, events: EventBus, rules: Registry) -> anyhow::Result<Self> {
        let store = AssetStore::new(&cfg.output_dir, &cfg.project)
            .with_context(|| format!("creating project dir in {}", cfg.output_dir.display()))?;
        let db_file = crate::store::meta_file(&cfg.output_dir, &format!("{}.db", cfg.project))
            .context("checking the metadata directory")?;
        let db = Db::open(&db_file).with_context(|| format!("opening {}", db_file.display()))?;
        let budget = Budget::new(cfg.discovery.memory_budget);
        let fetcher = Fetcher::with_budget(
            cfg.fetch.clone(),
            Arc::new(cfg.scope.clone()),
            cfg.download_referred_js,
            budget.clone(),
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
                discovery: Mutex::new(HashMap::new()),
                tracker: TaskTracker::new(),
                items: Arc::new(AtomicUsize::new(0)),
                budget,
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

    /// The single entry point for scheduling work. Takes a work slot and
    /// a reservation for the bytes the work already holds; refuses (and
    /// drops the work) when either is unavailable. Bytes the work fetches
    /// later are reserved by the fetcher before they are read.
    fn admit(&self, work: Work) -> bool {
        let Some(guard) = self.try_guard(work.bytes()) else {
            tracing::debug!(
                "pipeline at capacity (items or memory budget), skipping {}",
                crate::text::clean(&work.describe())
            );
            return false;
        };
        self.spawn_work(work, guard);
        true
    }

    /// Like [`admit`](Self::admit) but waits for room (backpressure for
    /// file-based sources). Called only from ingest sources, which hold no
    /// reservation, so waiting can't deadlock.
    async fn admit_wait(&self, work: Work) -> bool {
        let bytes = work.bytes();
        if bytes > self.inner.budget.capacity() {
            tracing::warn!(
                "{} is larger than the memory budget, dropping",
                crate::text::clean(&work.describe())
            );
            return false;
        }
        loop {
            if let Some(guard) = self.try_guard(bytes) {
                self.spawn_work(work, guard);
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    fn try_guard(&self, bytes: usize) -> Option<AdmitGuard> {
        let items = &self.inner.items;
        if items.fetch_add(1, Ordering::AcqRel) >= MAX_PENDING {
            items.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        let memory = if bytes > 0 {
            match self.inner.budget.try_reserve(bytes) {
                Some(r) => Some(r),
                None => {
                    items.fetch_sub(1, Ordering::AcqRel);
                    return None;
                }
            }
        } else {
            None
        };
        Some(AdmitGuard {
            items: Arc::clone(items),
            _memory: memory,
        })
    }

    fn spawn_work(&self, work: Work, guard: AdmitGuard) {
        let this = self.clone();
        self.inner.tracker.spawn(async move {
            let _guard = guard; // released when the work finishes
            match work {
                Work::Item(item) => this.process(item).await,
                Work::Map(job) => {
                    let owner = job.db_url.clone();
                    let ok = this.find_sourcemap(job).await;
                    this.track_done(&owner, ok);
                }
            }
        });
    }

    /// Queue an item; returns immediately. Returns `false` (and drops the
    /// item) when the pipeline is at capacity.
    pub fn submit(&self, item: Captured) -> bool {
        self.admit(Work::Item(item))
    }

    /// Queue an item, waiting for capacity instead of dropping it.
    /// Returns `false` only if the item can never fit (body larger than the
    /// whole memory budget).
    pub async fn submit_wait(&self, item: Captured) -> bool {
        self.admit_wait(Work::Item(item)).await
    }

    /// Work items queued or in progress.
    pub fn pending(&self) -> usize {
        self.inner.items.load(Ordering::Acquire)
    }

    /// The memory budget (for diagnostics and tests).
    pub fn budget(&self) -> &Budget {
        &self.inner.budget
    }

    /// Highest number of body bytes reserved at once so far.
    pub fn peak_memory_bytes(&self) -> usize {
        self.inner.budget.peak()
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
        let owner = item.owner.clone();
        let ok = match self.process_inner(item).await {
            Ok(ok) => ok,
            Err(e) => {
                bump(&self.inner.stats.errors, 1);
                tracing::warn!(%url, "processing failed: {e:#}");
                false
            }
        };
        // A failed derived item releases its claim so a later discovery
        // (e.g. after logging in) can fetch it again.
        if !ok && derived {
            self.unmark_seen(&url);
        }
        if let Some(owner) = owner {
            self.track_done(&owner, ok);
        }
    }

    // --- discovery completion tracking -------------------------------
    //
    // A script's discovery is "complete" only when every chunk and its
    // source-map lookup finished without a retryable failure. Until then
    // re-ingesting the unchanged script runs discovery again (R-35).

    fn tracks(&self) -> std::sync::MutexGuard<'_, HashMap<String, Track>> {
        self.inner
            .discovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Start tracking `owner`, holding one token for the owner itself.
    fn track_begin(&self, owner: &str) {
        self.tracks().insert(
            owner.to_string(),
            Track {
                pending: 1,
                failed: false,
            },
        );
        if let Err(e) = self.inner.db.set_discovery_complete(owner, false) {
            tracing::warn!("recording discovery state: {e}");
        }
    }

    /// Schedule `work` on behalf of `owner`; a refused admission counts as
    /// a retryable failure.
    fn admit_tracked(&self, owner: &str, work: Work) {
        if let Some(t) = self.tracks().get_mut(owner) {
            t.pending += 1;
        }
        if !self.admit(work) {
            self.track_done(owner, false);
        }
    }

    fn track_done(&self, owner: &str, ok: bool) {
        let finished = {
            let mut tracks = self.tracks();
            let Some(t) = tracks.get_mut(owner) else {
                return;
            };
            t.failed |= !ok;
            t.pending = t.pending.saturating_sub(1);
            if t.pending == 0 {
                tracks.remove(owner).map(|t| !t.failed)
            } else {
                None
            }
        };
        if let Some(complete) = finished
            && let Err(e) = self.inner.db.set_discovery_complete(owner, complete)
        {
            tracing::warn!("recording discovery state: {e}");
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

    /// Returns `Ok(true)` when the item succeeded or there is nothing to
    /// retry, `Ok(false)` for retryable failures (non-2xx, a login page
    /// instead of JS, budget refusals).
    async fn process_inner(&self, item: Captured) -> anyhow::Result<bool> {
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
                    host = %url.host_str().unwrap_or_default(),
                    origin = %item.origin.as_str(),
                    "request is not in scope: {decision}"
                );
                return Ok(true);
            }
        }
        if item.depth > inner.cfg.discovery.max_depth {
            tracing::debug!(%url, depth = item.depth, "max discovery depth reached");
            return Ok(true);
        }
        if !item.origin.is_captured() && !self.mark_seen(&url) {
            return Ok(true);
        }
        // Chunk names are content-hashed: one we stored in an earlier run
        // doesn't need downloading again (R-35).
        if item.origin == Origin::Chunk && inner.db.asset_hash(url.as_str())?.is_some() {
            tracing::debug!(%url, "chunk already stored, skipping download");
            return Ok(true);
        }

        // Credentials ride along from the first captured request (R-60).
        let mut auth = item.auth.clone().or_else(|| {
            let h = item
                .request
                .headers
                .filtered(&inner.cfg.fetch.forward_headers);
            (!h.0.is_empty()).then(|| AuthContext {
                origin: url.origin(),
                headers: h,
            })
        });

        // Reservations covering bodies held by this item, kept until done.
        let mut _memory: Vec<Reservation> = Vec::new();
        // `final_url` is where the bytes really came from (after redirects);
        // relative references resolve against it. `url` stays the DB key.
        let (mut response, final_url) = match item.response {
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
                _memory.extend(r.memory);
                // Credential eligibility doesn't come back after leaving the
                // origin, even if the chain returned to it (R-61).
                if !r.stayed_on_origin {
                    auth = None;
                }
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
            return Ok(false);
        }

        // Captured bodies arrive as they were on the wire (R-11b): undo
        // Content-Encoding with a capped, budget-charged decoder. The
        // fetcher's own downloads are decoded (and capped) while streaming.
        if response.headers.get("content-encoding").is_some() {
            match decode::decode_captured(
                &response.headers,
                &response.body,
                inner.cfg.fetch.max_body_bytes as usize,
                &inner.budget,
            ) {
                Ok(Some((body, reservation, headers))) => {
                    response.body = body;
                    response.headers = headers;
                    _memory.push(reservation);
                }
                Ok(None) => {}
                // Some tools hand over an already-decoded body but keep the
                // original header; a body that isn't valid compressed data
                // is taken as-is (it's no bigger than what was admitted).
                Err(decode::DecodeError::Corrupt(enc)) => {
                    tracing::debug!(%url, "body is not valid {enc}; treating it as already decoded");
                    response
                        .headers
                        .0
                        .retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
                }
                Err(e) => {
                    tracing::warn!(%url, "could not decode captured body: {e}");
                    return Ok(false);
                }
            }
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
                // (upstream #31). Don't save it as JS, and let a later,
                // authenticated discovery try again.
                tracing::warn!(
                    %url,
                    "expected JavaScript but got HTML (auth required? check cookies / --forward-auth)"
                );
                return Ok(false);
            }
            Some(AssetKind::Html) => self.handle_html(&ctx, response).await?,
            Some(AssetKind::Js) => {
                let text = String::from_utf8_lossy(&response.body).into_owned();
                let asset = JsAsset {
                    db_url: url.to_string(),
                    base: final_url.clone(),
                    rel_path: paths::asset_path(&url, AssetKind::Js),
                    text,
                    headers: response.headers,
                    find_sourcemaps: true,
                };
                self.handle_js(&ctx, asset).await?;
            }
            Some(AssetKind::Source) | None => {
                tracing::debug!(%url, content_type = ?response.headers.content_type(), "ignoring non HTML/JS asset");
            }
        }
        Ok(true)
    }

    async fn handle_html(&self, cx: &ItemCtx<'_>, resp: CapturedResponse) -> anyhow::Result<()> {
        let inner = &self.inner;
        let rel = paths::asset_path(cx.url, AssetKind::Html);
        // Parsing HTML is CPU work on untrusted input: bounded and off the
        // async workers, like JS parsing.
        let (text, scripts) = {
            let _permit = inner.cpu.acquire().await.expect("semaphore never closed");
            let base = cx.base.clone();
            let max = inner.cfg.discovery.max_scripts_per_page;
            tokio::task::spawn_blocking(move || {
                let text = String::from_utf8_lossy(&resp.body).into_owned();
                let scripts = html::extract(&base, &text, max);
                (text, scripts)
            })
            .await
            .map_err(|e| anyhow::anyhow!("HTML parsing task panicked: {e}"))?
        };
        self.save(cx, AssetKind::Html, &rel, text.as_bytes())
            .await?;
        drop(text);
        if scripts.truncated {
            tracing::info!(
                url = %cx.url,
                "page has more than {} scripts; extra ones were ignored (--max-scripts-per-page)",
                inner.cfg.discovery.max_scripts_per_page
            );
        }

        for script in scripts.external {
            inner.db.add_relation(cx.url.as_str(), script.as_str())?;
            self.spawn_child(script, Origin::Referred, cx, None);
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

    /// Schedule a discovered URL. `owner` is the script whose discovery
    /// this belongs to (tracked for completion), if any.
    fn spawn_child(&self, url: Url, origin: Origin, cx: &ItemCtx<'_>, owner: Option<&str>) {
        let mut child = Captured::url_only(url, origin);
        child.depth = cx.depth + 1;
        // The parent used for scope / same-origin exemptions is the URL we
        // *asked for* (it passed the scope check), never where a redirect
        // took us. If a redirect left that origin, the children lose the
        // captured credentials too: they must never reach another origin.
        child.parent = Some(cx.url.clone());
        child.auth = if cx.base.origin() == cx.url.origin() {
            cx.auth.cloned()
        } else {
            None
        };
        match owner {
            Some(owner) => {
                child.owner = Some(owner.to_string());
                self.admit_tracked(owner, Work::Item(child));
            }
            None => {
                if !self.admit(Work::Item(child)) {
                    tracing::debug!("child not scheduled (pipeline at capacity)");
                }
            }
        }
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
        // R-35: skip files we already processed in an earlier run, unless
        // their discovery didn't complete (a chunk or map failed, e.g.
        // before logging in): then run it again.
        let hash = sha256_hex(asset.text.as_bytes());
        if let Some((stored, complete)) = inner.db.asset_state(&asset.db_url)?
            && stored == hash
        {
            if complete {
                bump(&inner.stats.unchanged, 1);
                tracing::debug!(url = %asset.db_url, "unchanged since last run, skipping");
                return Ok(());
            }
            tracing::debug!(url = %asset.db_url, "unchanged, but discovery was incomplete: retrying");
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
        // From here on, children report back to this owner token.
        let owner = asset.db_url.clone();
        self.track_begin(&owner);

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
                self.spawn_child(chunk, Origin::Chunk, cx, Some(&owner));
            }
        }

        if inner.cfg.discovery.sourcemaps && asset.find_sourcemaps {
            // One job per script with every candidate in priority order
            // (R-71); it stops at the first that validates. Inline map
            // bytes are charged to the budget at admission.
            let candidates = sourcemap::candidates(&asset.base, &asset.headers, &asset.text);
            if !candidates.is_empty() {
                let job = MapJob {
                    candidates,
                    js_url: asset.base.clone(),
                    db_url: owner.clone(),
                    parent: cx.url.clone(),
                    // Same rule as for chunks: credentials don't follow a
                    // cross-origin redirect.
                    auth: (cx.base.origin() == cx.url.origin())
                        .then(|| cx.auth.cloned())
                        .flatten(),
                };
                self.admit_tracked(&owner, Work::Map(job));
            }
        }
        // Release the owner's own token; completion is recorded once every
        // child has reported back.
        self.track_done(&owner, true);
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

    /// Try every candidate in priority order; the first that validates
    /// wins (R-71). Returns `true` if a map was found, or if every
    /// candidate failed definitively (404, not a map), so there's nothing
    /// to retry; `false` if something might work next time (network error,
    /// auth or server error, a login page, no budget).
    async fn find_sourcemap(&self, job: MapJob) -> bool {
        let inner = &self.inner;
        // While this job holds inline-map bytes it must not wait for more
        // budget (deadlock rule in `budget.rs`).
        let holds_memory = job.inline_bytes() > 0;
        let mut retryable = false;
        for candidate in &job.candidates {
            match candidate {
                sourcemap::Candidate::Inline { bytes } => {
                    let map_url = format!("{}#inline-map", job.js_url);
                    if self
                        .apply_sourcemap(&job.js_url, &job.db_url, &map_url, bytes)
                        .await
                    {
                        return true;
                    }
                }
                sourcemap::Candidate::Remote { url, why } => {
                    // The trusted parent is the requested script URL.
                    let mut ctx = FetchContext::new(Purpose::SourceMap)
                        .with_parent(Some(&job.parent))
                        .with_auth(job.auth.as_ref());
                    if holds_memory {
                        ctx = ctx.without_budget_wait();
                    }
                    let r = match inner.fetcher.get(url, &ctx).await {
                        Ok(r) if r.is_success() => r,
                        Ok(r) => {
                            tracing::debug!(%url, status = r.status, why, "source map candidate rejected");
                            retryable |= !matches!(r.status, 404 | 410);
                            continue;
                        }
                        Err(e) => {
                            tracing::debug!(%url, why, "source map candidate failed: {e}");
                            retryable |= !matches!(e, crate::net::FetchError::Blocked(_));
                            continue;
                        }
                    };
                    // `r.memory` covers `r.body` until `r` is dropped.
                    if self
                        .apply_sourcemap(&job.js_url, &job.db_url, url.as_str(), &r.body)
                        .await
                    {
                        return true;
                    }
                    // A 200 HTML page instead of a map is usually a login
                    // page: worth retrying once authenticated.
                    retryable |= classify(url, &r.headers, &r.body) == Some(AssetKind::Html);
                }
            }
        }
        tracing::debug!(js = %job.js_url, "no source map found");
        !retryable
    }

    /// Validate and reverse one map. Returns `true` on success.
    async fn apply_sourcemap(
        &self,
        js_url: &Url,
        db_url: &str,
        map_url: &str,
        bytes: &[u8],
    ) -> bool {
        let inner = &self.inner;
        let rev = match sourcemap::reverse(bytes, inner.cfg.discovery.max_sourcemap_sources) {
            Ok(rev) => rev,
            Err(e) => {
                tracing::debug!(map = %map_url, "not a valid source map: {e}");
                return false;
            }
        };
        let missing = rev.missing_content.len();
        let written = self.write_sources(js_url.clone(), rev).await;
        if missing > 0 {
            tracing::info!(map = %map_url, "{missing} source(s) listed without sourcesContent");
        }
        if let Err(e) = inner.db.record_sourcemap(db_url, map_url, written) {
            tracing::warn!("recording source map: {e}");
        }
        bump(&inner.stats.sourcemaps, 1);
        tracing::info!(js = %js_url, map = %map_url, "reversed {written} source file(s)");
        inner.events.emit(Event::SourceMapReversed {
            js_url: db_url.to_string(),
            map_url: map_url.to_string(),
            sources: written,
        });
        true
    }

    /// Write recovered sources on the blocking pool (it can be thousands
    /// of small files).
    async fn write_sources(&self, js_url: Url, rev: sourcemap::Reversed) -> usize {
        let store = self.inner.store.clone();
        let task = tokio::task::spawn_blocking(move || {
            let mut written = 0;
            for src in &rev.sources {
                let Some(rel) = paths::sourcemap_source_path(&js_url, &src.name) else {
                    continue;
                };
                match store.write(&rel, src.content.as_bytes()) {
                    Ok(_) => written += 1,
                    Err(e) => tracing::warn!(
                        source = %crate::text::clean(&src.name),
                        "could not write source: {e}"
                    ),
                }
            }
            written
        });
        task.await.unwrap_or_else(|e| {
            tracing::warn!("source write task failed: {e}");
            0
        })
    }
}

/// Outstanding discovery work for one script.
struct Track {
    /// Children not yet finished, plus one token held by the owner while it
    /// is still scheduling them.
    pending: usize,
    /// Any child failed in a retryable way.
    failed: bool,
}

/// The source-map lookup for one script, run as its own work item.
struct MapJob {
    /// Every candidate in priority order (R-71).
    candidates: Vec<sourcemap::Candidate>,
    /// URL the map references resolve against (final URL of the script).
    js_url: Url,
    /// Database key of the script (also its discovery owner).
    db_url: String,
    /// Trusted parent for scope decisions: the requested script URL.
    parent: Url,
    auth: Option<AuthContext>,
}

impl MapJob {
    /// Bytes of decoded inline maps this job carries.
    fn inline_bytes(&self) -> usize {
        self.candidates
            .iter()
            .map(|c| match c {
                sourcemap::Candidate::Inline { bytes } => bytes.len(),
                sourcemap::Candidate::Remote { .. } => 0,
            })
            .sum()
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
