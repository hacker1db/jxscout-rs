# jxscout-rs

[![CI](https://github.com/hacker1db/jxscout-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hacker1db/jxscout-rs/actions/workflows/ci.yml)
[![CodeQL](https://github.com/hacker1db/jxscout-rs/actions/workflows/codeql.yml/badge.svg)](https://github.com/hacker1db/jxscout-rs/actions/workflows/codeql.yml)

JavaScript recon for security researchers, in one static Rust binary. Feed it
the HTTP traffic from your proxy (Caido plugin included), a URL list, or a HAR
file. It saves every HTML and JS file in a tidy tree, beautifies them, pulls in
webpack and Vite chunks, rebuilds original sources from source maps, and runs
AST rules that point at the interesting parts: sinks, endpoints, secrets,
`postMessage` handlers, GraphQL operations, and more.

No Node, Bun, or Prettier needed.

![demo](docs/demo.gif)

## Disclaimer

This tool is intended for educational and authorized security testing purposes only.

You may use this software only on systems you own or have explicit permission to test.

Any misuse of this tool is strictly prohibited. The author is not responsible for any damage, legal issues, or misuse caused by this software.

## Notice: clean-room reimplementation

`jxscout-rs` is an **independent clean-room reimplementation** of the behavior
of [jxscout](https://github.com/francisconeves97/jxscout) by Francisco Neves.
It is **not affiliated with, endorsed by, or derived from the source code of**
that project. Behavior was specified only from upstream's public README,
`docs/` folder, release notes, and issue text, see [`docs/SPEC.md`](docs/SPEC.md)
for every requirement and its source. No upstream source code was read or
copied. If you want the original author's current product, see
[jxscout Pro](https://jxscout.app/).

## Features

- **Ingest from anywhere**: local HTTP endpoint for proxy plugins (Caido plugin
  in [`integrations/caido`](integrations/caido)), `curl`, URL lists
  (file or stdin), and HAR files.
- **Organized storage**: `~/jxscout/<project>/<host>/<path>`, with pages saved
  as `(index).html`, inline scripts as `(inline-N).js`, and reversed sources
  under `<host>/(sourcemaps)/`. A SQLite index tracks assets, page→script
  relations, findings, and source maps across restarts.
- **Beautifying** with the [oxc](https://oxc.rs) parser and code generator.
- **Chunk discovery** for webpack (static evaluation of the runtime's
  chunk-filename function, brute force when there's no table) and Vite/ESM
  (`import()`, `import … from`, preload arrays), recursively.
- **Source maps** from `SourceMap`/`X-SourceMap` headers, `sourceMappingURL`
  comments, inline `data:` URIs, and a `<file>.map` guess, with retries. The
  first candidate that actually parses as a map wins.
- **Authenticated chunk fetching**: cookies/`Authorization` from the captured
  request go to the same origin, so chunks behind login are downloaded
  instead of a login page.
- **AST rules** you can extend in Rust (`jxscout-rs rules` lists them):

  | rule | finds |
  | --- | --- |
  | `events` | `addEventListener`, `onmessage`, `onhashchange`, `postMessage` |
  | `sinks` | `eval`, `Function`, string timers, `innerHTML`/`outerHTML`, `insertAdjacentHTML`, `document.write`, `window.open` |
  | `dom-state` | `location` reads/writes, `document.domain`, `window.name`, cookies, `localStorage`/`sessionStorage` |
  | `network` | `fetch` (+ options/headers), XHR, axios, jQuery, REST-looking clients, `URLSearchParams`, `WebSocket` |
  | `strings` | paths, API paths, URLs, hostnames, query params, fragments, interesting extensions, MIME types |
  | `regex` | regex literals, `new RegExp`, regex-based matching |
  | `graphql` | queries, mutations, fragments, `gql` tags |
  | `secrets` | AWS/Google/GitHub/Slack/Stripe/… keys, JWTs, private keys, secret-named assignments |
  | `react` | `dangerouslySetInnerHTML` |

- **TUI** with scrollable assets, findings, logs, filter, and help, usable down
  to 40×12. `--no-tui` for headless servers.
- **Safe by default**: SSRF guard, per-hop redirect policy, no credential
  leaks across origins, size and depth limits, authenticated ingest, terminal
  escape sanitizing. See [Security model](#security-model).

## Install

**Homebrew** (macOS, Linux):

```sh
brew install hacker1db/tap/jxscout-rs
```

**Prebuilt binaries**: download a tarball for macOS (arm64, x86_64) or Linux
(x86_64, arm64, static musl) from
[Releases](https://github.com/hacker1db/jxscout-rs/releases) and check it
against the `.sha256` file.

**From source** (Rust ≥ 1.98):

```sh
cargo install --git https://github.com/hacker1db/jxscout-rs --locked
```

## Quick start

```sh
jxscout-rs -p acme -s '*.acme.com,!static.acme.com'
```

This starts the TUI and an ingest endpoint on `http://127.0.0.1:3333/ingest`.
The TUI header shows the **ingest token**. It is generated once and stored in
`~/jxscout/.jxscout-rs/ingest-token` (mode 0600); headless mode prints only
that path, never the token. Then send it traffic with one of the
options below. Assets land in `~/jxscout/acme/`; open that folder in your editor.

### Caido

1. Download `jxscout-rs-caido-plugin.zip` from a release (or build it:
   `cd integrations/caido && pnpm install && pnpm build`).
2. Caido → **Plugins** → **Install package** → pick the zip.
3. Caido → **Environment** → **Global**, add:
   - `JXSCOUT_TOKEN` = the token from the jxscout-rs header (mark it as a
     **secret** variable)
   - optional `JXSCOUT_ENDPOINT` (default `http://127.0.0.1:3333/ingest`)
   - optional `JXSCOUT_IN_SCOPE_ONLY` = `false` to forward everything
     (default: only requests in your Caido scope)

   The plugin refuses plain-`http` endpoints that aren't loopback, so captured
   cookies and the token never cross the network unencrypted. Responses
   larger than 40 MiB are skipped.

Browse the target with your browser cache disabled; every HTML/JS response
flows into jxscout-rs.

### Burp Suite

There's no Burp extension yet. Options that work today:

- Chain Burp → Caido (Caido as upstream proxy) and use the Caido plugin.
- Site map → select items → **Copy URLs**, then
  `pbpaste | jxscout-rs -p acme ingest-urls -`.
- Export a HAR from the browser devtools and run
  `jxscout-rs -p acme ingest-har session.har`.

### curl, scripts, and other tools

```sh
TOKEN=$(cat ~/jxscout/.jxscout-rs/ingest-token)
curl -s http://127.0.0.1:3333/ingest \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"request":{"url":"https://app.acme.com/"}}'
```

The full DTO (batches go to `/ingest/batch`, up to 1000 items):

```json
{
  "request":  { "url": "https://app.acme.com/x.js", "method": "GET",
                "headers": { "Cookie": ["session=…"] } },
  "response": { "status": 200, "headers": { "Content-Type": ["text/javascript"] },
                "body": "…utf-8…" }
}
```

`headers` values may be a string or a list. Use `body_base64` instead of `body`
for binary-safe transport. Leave out `response` (or its body) and jxscout-rs
fetches the URL itself.

### URL lists and HAR files

```sh
jxscout-rs -p acme -s '*.acme.com' ingest-urls urls.txt   # or `-` for stdin
jxscout-rs -p acme ingest-har session.har
```

These run the full pipeline, wait for it to finish, and print a summary.

### Looking at results

```sh
jxscout-rs -p acme findings --category 'Data/Secrets'
jxscout-rs -p acme findings --asset https://app.acme.com/main.js --json
jxscout-rs -p acme assets --search chunk
jxscout-rs -p acme loads https://app.acme.com/     # scripts loaded by a page
jxscout-rs -p acme loaded https://app.acme.com/main.js
jxscout-rs analyze ./some-bundle.js                 # offline, no DB
```

## Scope

- `-s/--scope` takes comma-separated patterns, and `--scope-file` takes one per
  line (`#` comments allowed). Both can be combined.
- `*` matches anything. Patterns without `/` match the host; patterns with `/`
  match the full URL.
- `!pattern` excludes and always wins. With only exclusions, everything else
  is in scope. With no scope, everything is in scope.
- `--debug` logs every dropped request with its URL and the reason.

## Authenticated fetching and security model

jxscout-rs fetches URLs it finds inside JavaScript, which an attacker may have
written. Defaults are strict:

- **Credentials**: `Cookie` and `Authorization` from a captured request
  (configure with `--forward-header`) are only sent to that request's exact
  origin (scheme, host, and port). Once a redirect leaves that origin, nothing
  more is sent, and assets reached that way don't pass credentials on.
  `--forward-auth never` turns this off. Extra `--header` values only go to
  explicitly in-scope origins.
- **SSRF guard**: only `http(s)`; loopback, private, link-local, CGNAT, and
  embedded-IPv4 IPv6 forms are refused after DNS resolution, so DNS rebinding
  doesn't work. Environment proxies are ignored. Use
  `--allow-private-targets` when you test an internal app on purpose.
- **Scope on every hop**: each redirect hop must be in scope or same-origin
  with the asset that referenced it.
- **Limits**: 20 MiB per download (decompressed, `--max-download-mb`), 30 s
  timeouts, depth 3, chunk and source budgets, 2 req/s by default.
- **Ingest endpoint**: loopback only (`--allow-remote-ingest` to change),
  bearer token by default (`--no-auth` to disable), `Host` header checked
  against loopback names to block DNS rebinding, JSON-only to block
  cross-site form posts.
- **Files**: URL and source-map paths are decoded and then sanitized, so `..`
  can't escape. Symlinks inside the project are never followed.
- **Terminal**: control characters in URLs and findings are escaped before
  printing.

## Upstream issues addressed

| Upstream issue | How jxscout-rs handles it |
| --- | --- |
| [#31](https://github.com/francisconeves97/jxscout/issues/31) chunks behind auth not downloaded | Captured `Cookie`/`Authorization` forwarded to the same origin for chunks and maps; HTML returned for a JS URL is detected as a login page and not saved as JS. Test: `chunks_behind_auth_use_captured_cookies` |
| [#27](https://github.com/francisconeves97/jxscout/issues/27) analysis side panel missing (VSCode) | Triage: upstream's VSCode extension couldn't find the file, which was a project/path mismatch. No VSCode dependency here. Findings show in the TUI next to the file path, the active project and folder are always in the header, and `findings --json` exposes results to editors |
| [#20](https://github.com/francisconeves97/jxscout/issues/20) non-Burp, non-Caido users | Documented JSON DTO plus curl examples, `ingest-urls` (file/stdin), `ingest-har`, and the `IngestSource` trait for new sources. Tests: `tests/ingest.rs` |
| [#19](https://github.com/francisconeves97/jxscout/issues/19) chunk discoverer "Unexpected token" | Pure-Rust oxc parser, no external process. Parse errors are values, so the file is saved unformatted and the pipeline continues. The `not a directory` error from the same report is fixed by directory-style `(index).html` paths and deterministic collision handling. Tests: `malformed_js_does_not_stop_the_pipeline`, `file_vs_dir_collisions`, `root_page_is_a_directory_not_a_file` |
| [#18](https://github.com/francisconeves97/jxscout/issues/18) can't scroll options | Every TUI list and the help popup scroll (arrows, j/k, PgUp/PgDn, Home/End), and the layout collapses on small terminals. Tests: `help_popup_scrolls`, `small_terminal_keeps_selection_visible` |
| [#17](https://github.com/francisconeves97/jxscout/issues/17) failed to install bun | No Bun/Node/Prettier: one static binary |
| [#16](https://github.com/francisconeves97/jxscout/issues/16) more AST rules | `Rule` trait and registry, plus 9 rule families: GraphQL, endpoints, postMessage, sinks, fetch/axios/XHR, events, storage, headers, secrets. See `CHALLENGES.md` to write your own |
| [#13](https://github.com/francisconeves97/jxscout/issues/13) source maps not always downloaded | Headers, last `sourceMappingURL` comment, inline `data:` URIs, `.map` guess. Retries on 429/5xx; the first candidate that parses wins, and HTML/404 bodies are rejected. Test: `sourcemap_discovery_methods` |
| [#9](https://github.com/francisconeves97/jxscout/issues/9) show the out-of-scope request in debug | `--debug` logs URL, host, origin, and the rule that rejected it (`no scope pattern matched` / `excluded by !x`) |
| [#8](https://github.com/francisconeves97/jxscout/issues/8) scope from a file | `--scope-file`, plus `!` negative patterns as suggested in the thread. Test: `scope_file_format` |

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                      # unit + integration (local mock servers, no network)
cargo deny check                # advisories, licenses, sources
vhs demo.tape                   # re-record docs/demo.gif (needs a release build)
```

Code map: [`src/lib.rs`](src/lib.rs). Requirements: [`docs/SPEC.md`](docs/SPEC.md).
Review history: [`docs/REVIEW_LOG.md`](docs/REVIEW_LOG.md).

**Learning Rust?** [`CHALLENGES.md`](CHALLENGES.md) has graded exercises built
on this codebase.

Optional local hooks: `pre-commit install` (runs ggshield and `cargo fmt`).
CI also runs CodeQL and, when the `GITGUARDIAN_API_KEY` secret is set,
GitGuardian.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option. Contributions are accepted under the same terms.
