# Rust challenges

Exercises built on this codebase, in rough order of difficulty. The tool is
complete without them; each one is an extension you can build on a branch.

Ratings: ★ warm-up · ★★ needs a few concepts together · ★★★ stretch

Before you start:

```sh
cargo test          # everything should pass
cargo doc --open    # browse the crate docs, start at `jxscout`
```

Every exercise lists the **test command that proves it**. Write the test
first, watch it fail, then make it pass.

---

## 1. ★ A rule for Web Workers

**Goal:** report `new Worker(url)`, `new SharedWorker(url)`, and
`importScripts(url)` as `Client Behavior/Workers` with the URL as the value.
Workers load more JavaScript, and that code is often missed.

**Where:** add `src/rules/workers.rs` and register it in
`Registry::default()` (`src/rules/mod.rs`).

**Hints**
- Copy the shape of `ReactRule` in `src/rules/frameworks.rs`.
- Match `AstKind::NewExpression` and `AstKind::CallExpression`.
  `crate::js::member_path(&n.callee)` gives you `"Worker"` or `"window.Worker"`.
- `crate::js::string_value` handles both `"a.js"` and `` `a.js` ``.
- Look at `rules::test_util::{run, has}` for one-line tests.

**Done when**
- `new Worker("/w.js")` → `("Client Behavior/Workers", "/w.js")`
- `importScripts("a.js", "b.js")` reports both URLs
- `new Map()` reports nothing
- `jxscout-rs rules` lists your rule

**Prove it:** `cargo test rules::workers`

---

## 2. ★ Filter the findings pane

**Goal:** when the **Findings** pane is focused, `/` filters findings by
category or value instead of filtering assets.

**Where:** `src/tui/app.rs` (state and keys), `src/tui/ui.rs` (rendering).

**Hints**
- Add `findings_filter: String` next to `filter`, and a
  `visible_findings()` helper that mirrors `visible_assets()`.
- `on_filter_key` has to know which filter it's editing. An enum
  `FilterTarget { Assets, Findings }` keeps that explicit.
- Selection math (`move_selection`) must use the *filtered* length.

**Done when**
- A unit test types `/`, `postMessage`, `Enter` with Findings focused and
  only matching findings remain visible
- The asset filter still works as before (existing tests pass)

**Prove it:** `cargo test tui::`

---

## 3. ★★ Make CPU concurrency configurable

**Goal:** add `--analysis-concurrency <N>` (default: number of CPUs). Today
`Pipeline::with_rules` hardcodes `available_parallelism()`.

**Where:** `DiscoveryConfig` (`src/config.rs`), `GlobalArgs` and
`build_config` (`src/main.rs`), `Pipeline::with_rules` (`src/pipeline.rs`).

**Hints**
- `Option<usize>` in the config, where `None` means "auto", reads well.
- `Semaphore::new(0)` would deadlock the pipeline. Reject 0 in clap with
  `value_parser = clap::value_parser!(u16).range(1..)`, or clamp it.
- Think about why parsing runs inside `spawn_blocking` *and* behind a
  semaphore. What would happen without the semaphore?

**Done when**
- `jxscout-rs --analysis-concurrency 0 rules` exits with an error
- An integration test with `analysis_concurrency: Some(1)` still processes
  the fixture page from `tests/pipeline.rs`

**Prove it:**

```sh
cargo build && cargo test --test pipeline \
  && cargo run -q -- --analysis-concurrency 2 rules >/dev/null \
  && cargo run -q -- --analysis-concurrency 0 rules 2>&1 | grep -q "analysis-concurrency"
```

(The last step passes only if clap rejects `0` with a message naming the flag.)

---

## 4. ★★ Bursty rate limiting

**Goal:** `RateLimiter` (`src/net/ratelimit.rs`) spaces requests evenly.
Add a `burst` parameter so the first `burst` requests go out at once and
the steady-state rate stays the same (a real token bucket).

**Hints**
- Keep it lock-then-sleep: compute the slot under the mutex, then sleep
  outside it. Never `.await` while holding a `tokio::sync::Mutex` guard if
  you can avoid it.
- A token bucket stores `tokens: f64` and `last_refill: Instant`.
- `#[tokio::test(start_paused = true)]` makes time deterministic. Look at
  the existing `spaces_requests` test.

**Done when**
- With `burst = 3, rps = 1`, three acquisitions take 0 s and the fourth 1 s
  (paused clock)
- `burst = 1` behaves exactly like today (existing test unchanged)

**Prove it:** `cargo test net::ratelimit`

---

## 5. ★★ Property-test the scope matcher

**Goal:** prove `scope::wildcard_match` agrees with a reference
implementation on random inputs.

**Where:** `src/scope.rs` tests (there's already a small proptest).

**Hints**
- Build the reference with the `regex` crate: escape each literal piece
  with `regex::escape`, join with `.*`, and anchor with `^…$`.
- Generate patterns from a small alphabet (`[ab*.]{0,8}`) so `*` shows up
  often and shrinking finds minimal counterexamples.
- If proptest finds a mismatch, decide whether the matcher or the
  reference is wrong before you "fix" anything.

**Done when**
- A `proptest!` comparing both implementations passes 10 000 cases
  (`PROPTEST_CASES=10000`)

**Prove it:** `PROPTEST_CASES=10000 cargo test scope::`

---

## 6. ★★ A JSON Lines ingest source

**Goal:** `jxscout-rs ingest-jsonl <file|->`, where each line is one
`IngestPayload` (the same DTO as `POST /ingest`). This makes it easy to pipe
in other tools' output.

**Where:** `src/ingest/jsonl.rs` implementing `IngestSource`, plus a
subcommand in `src/main.rs`.

**Hints**
- `src/ingest/urls.rs` is almost the answer: same line reader, but
  `serde_json::from_str::<IngestPayload>(line)` and then
  `.into_captured(Origin::Proxy)`.
- Count bad lines in `IngestReport::rejected` instead of failing the run.
- Use `submit_wait` for backpressure, as the other file sources do.

**Done when**
- An integration test in `tests/ingest.rs` feeds three lines (two valid,
  one garbage) and asserts `submitted == 2, rejected == 1` and that the
  files are saved

**Prove it:** `cargo test --test ingest jsonl`

---

## 7. ★★★ A dyn-compatible ingest trait

**Goal:** `IngestSource::run` returns `impl Future<Output = …> + Send`
(implementations write it as `async fn`), so you can't write
`Vec<Box<dyn IngestSource>>`. Make sources selectable at runtime, for example
to run the HTTP server **and** a URL list in one process.

**Hints**
- Define a second trait that returns a boxed future:
  ```rust
  pub trait DynIngestSource: Send {
      fn name(&self) -> &'static str;
      fn run_boxed(self: Box<Self>, p: Pipeline)
          -> futures::future::BoxFuture<'static, anyhow::Result<IngestReport>>;
  }
  ```
- A blanket `impl<T: IngestSource + Send + 'static> DynIngestSource for T`
  makes every existing source work for free.
- Read about why `async fn` in traits isn't dyn-compatible: the returned
  future has a different, unnameable type for each implementation.

**Done when**
- A test builds `Vec<Box<dyn DynIngestSource>>` with a URL list and a HAR
  source, runs both, and sees both outputs

**Prove it:** `cargo test --test ingest dyn_sources`

---

## 8. ★★★ Analyze the reversed sources

**Goal:** source maps often recover original `.ts`/`.tsx` files with
readable names and comments. Run the AST rules on them too.

**Where:** `Pipeline::write_sources` (`src/pipeline.rs`) and `js::parse`
(`src/js/mod.rs`).

**Hints**
- `oxc_span::SourceType::from_path("App.tsx")` picks TS/JSX parsing.
  Today `js::parse` always tries `unambiguous` then `jsx`.
- Analysis is CPU work: reuse the `cpu` semaphore and `spawn_blocking`.
- Store findings under a synthetic key such as
  `"{js_url}#source:{name}"` so they show up in the TUI.
- Mind the budget: a map can hold 10 000 sources.

**Done when**
- The `html_to_scripts_to_chunks_to_sourcemaps` test also finds
  `Data/Paths/API = /api/v1/admin` from the reversed `src/api.js`

**Prove it:** `cargo test --test pipeline html_to_scripts`

---

## 9. ★★★ JavaScript semantics in the chunk evaluator

**Goal:** `Evaluator` in `src/js/chunks.rs` treats every value as a string.
Real JS has numbers: `e + 1 + ".js"` is `"11.js"` for `e = 1` only if `e` is a
string; webpack passes numbers, so the runtime produces `"2.js"`. Add a
`Value { Str(String), Num(f64), Undefined }` enum with JS `+`, `||`
(truthiness), and `===`.

**Hints**
- Chunk ids from object keys are strings in JS, but webpack calls
  `__webpack_require__.u(123)` with a number. Decide which one `key` is.
- `"" || "x"` is `"x"`; `0 || "x"` is `"x"`. Write those as tests first.
- Build each lookup table once per expression, not once per key (see the
  review note in `docs/REVIEW_LOG.md`, Milestone 3 #5).

**Done when**
- `r.u = e => e + 1 + ".js"` with ids `{1:…}` yields `2.js`
- All existing `chunks::tests` still pass

**Prove it:** `cargo test js::chunks`
