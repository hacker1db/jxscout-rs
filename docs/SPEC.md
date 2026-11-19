# jxscout-rs behavioral specification

This document is the single source of truth for what `jxscout-rs` does. It was
written **before** any implementation, and it was derived only from public,
non-code material about the original [jxscout](https://github.com/francisconeves97/jxscout):

| Tag | Source |
| --- | --- |
| `[README]` | Upstream `README.md` (feature list, CLI flags, prompt command list, troubleshooting) |
| `[TREE]` | Upstream `docs/tree.md` (AST analysis tree / descriptor categories) |
| `[REL-0.3]`, `[REL-0.4]`, `[REL-0.5]`, `[REL-0.9.2]` | Upstream GitHub release notes for those versions |
| `[#N]` | Text of upstream GitHub issue N and its comments |

No upstream source files (`.go`, `.js`, `.ts`, or vendored code) were opened
while writing this spec or the implementation. Where the upstream docs are
silent, this spec makes its own design decisions; those are marked **(design)**.

Requirement IDs (`R-xx`) are referenced from code comments and tests.

---

## 1. Purpose

R-01. Help security researchers analyze the JavaScript of web applications by
capturing HTML and JavaScript that flows through their HTTP proxy, saving it
locally in an organized folder tree, and enriching it. `[README]`

R-02. The tool must have **no Node.js, Bun, or Prettier runtime dependency**.
Beautification, chunk discovery, and AST analysis are implemented in Rust.
`[#17]` (upstream required `bun` and `prettier`, and their installation failed
for several users).

## 2. Ingestion

R-10. The tool listens on an HTTP endpoint (default `localhost:3333`) that proxy
plugins post captured request/response pairs to. `[README]` (`-hostname`,
`-port`, "Proxy Setup").

R-11. **(design)** Ingest payload: `POST /ingest` with a JSON body

```json
{
  "request":  { "url": "https://app.example/x.js", "method": "GET",
                "headers": { "Cookie": ["a=b"] } },
  "response": { "status": 200, "headers": { "Content-Type": ["text/javascript"] },
                "body": "…utf-8 text…", "body_base64": null }
}
```

`headers` values may be a string or an array of strings. Exactly one of `body`
or `body_base64` may be set; both absent means "no body" (the tool may fetch the
URL itself). `GET /health` returns `200 ok`. A batch form (`POST /ingest/batch`,
JSON array) is accepted. `[#20]` asked for a documented "reference request or
DTO".

R-12. Non-Burp / non-Caido users must have standalone ingest paths `[#20]`:
- R-12a. `curl` against the endpoint (documented with an example).
- R-12b. A URL list from a file or stdin (`ingest-urls <file|->`), one URL per
  line, `#` comments ignored; each URL is fetched by the tool and then processed
  as if captured.
- R-12c. A HAR file import (`ingest-har <file>`), using the HAR 1.2 `log.entries`
  request/response pairs, decoding `content.encoding == "base64"`.

R-13. A Caido plugin (shipped in this repo) forwards in-scope proxied
request/response pairs to the ingest endpoint. A Burp path must be documented.
`[README]` ("For Caido users", "For Burp users") **(design: our own plugin)**.

R-14. Ingest sources are pluggable through a Rust trait so new sources can be
added without touching the pipeline. **(design)**

## 3. Scope

R-20. Scope is a list of wildcard patterns (`*` matches any run of characters),
e.g. `*google*,*youtube*`. Requests not matching are ignored. An empty scope
means everything is in scope. `[README]` (`-scope`).

R-21. Scope may be loaded from a file, one pattern per line, blank lines and `#`
comments ignored; file patterns are merged with `--scope` patterns. `[#8]`

R-22. Negative scope: patterns prefixed with `!` exclude matches and win over
positive patterns. `[#8]` (owner comment: "negative scope, to exclude some files").

R-23. **(design)** Patterns without `/` are matched against the URL host;
patterns containing `/` are matched against the full URL (without fragment).
Matching is case-insensitive.

R-24. When a request is out of scope, a debug-level log line must include the
URL (and host) of the rejected request and which rule rejected it. `[#9]`

R-25. JS files on out-of-scope hosts that are referenced from an in-scope HTML
page are downloaded only when `--download-referred-js` is set. `[README]`

## 4. Storage layout

R-30. Assets are saved under `<output-dir>/<project-name>/` (default output dir
`~/jxscout`, default project `default`). `[README]` ("saved to your `~/jxscout`
folder", `-project-name`).

R-31. Within a project, files are organized by host, then URL path, e.g.
`default/app.example/static/js/main.js`. HTML documents whose path ends with `/`
or has no extension are saved as `(index).html` in a directory named after the
path. `[README]` (override command mentions "keep the (index).html suffix").

R-32. Path mapping must never fail because a path component already exists as a
file (upstream error: `mkdir …/att.com/levelblue.com: not a directory`). If a
component collides with an existing file, an alternate directory name is used.
`[#19]`

R-33. Path mapping must be immune to traversal: `..`, absolute paths, NUL,
drive letters, and reserved characters from URLs or source-map `sources` must
never escape the project directory. **(design, security)**

R-34. Reversed source-map sources are written under
`<project>/<host>/(sourcemaps)/…`, prefixed by host to avoid clashes between
sites. `[REL-0.9.2]`

R-35. All ingested assets are tracked in a local database (SQLite) so restarts
don't re-download the same files; relationships "HTML page loads JS" and "JS
loaded by pages" are recorded. `[REL-0.5]`, `[README]` (`loads`, `loaded`,
`assets`, `truncate-tables`).

R-36. Downloads have a max size (default 20 MiB) and a timeout; oversized
responses are aborted and logged. **(design, security)**

## 5. Processing pipeline

R-40. HTML responses: save the page, extract `<script src>` URLs and inline
scripts, and process the referenced JS. `[README]` ("Asset Organization").

R-41. JS responses: beautify, save, discover chunks, discover source maps, run
AST analysis. `[README]` (Key Features).

R-42. Beautification is done by parsing with a Rust JS parser and re-printing;
on parse failure the original text is saved unchanged and a warning is logged.
`[#19]`, `[#17]`

R-43. A parse error, network error, or bad source map for one file must **never**
stop the pipeline; it is logged with the file URL and processing continues.
`[#19]`

## 6. Chunk discovery

R-50. Detect and pre-fetch Webpack and Vite chunks. `[README]`

R-51. **(design)** Webpack: find the chunk-filename function (a function whose
return value concatenates string literals, the function parameter, and
object-literal lookups indexed by the parameter), statically evaluate it for each
key of those object literals, and resolve the results against the public path
(`<x>.p = "…"` assignment) or the script's directory.

R-52. When the chunk-filename expression depends on the parameter but no key
set can be found, brute-force numeric ids `0..limit` (default 3000).
`[README]` (`-chunk-discoverer-bruteforce-limit`).

R-53. **(design)** Vite / ESM: collect the string sources of `import()`
expressions, static `import`/`export … from` declarations, and string arrays of
`.js` paths passed to preload helpers; resolve relative to the script URL (for
`./`, `../`) or to the origin root otherwise.

R-54. Discovered chunks are processed like any other JS (recursively), with URL
de-duplication and a depth limit. `[README]`

R-55. Fetches of chunks and source maps are rate-limited (default 2 req/s, 0 =
unlimited) and concurrency-limited (default 5). `[README]` (`-fetch-concurrency`,
`-rate-limiter-max-requests-per-second`, `-rate-limiter-max-requests-per-minute`),
`[REL-0.4]`

R-56. Chunk and source-map fetches only target `http`/`https` URLs, and only
hosts that are in scope, the same host as the parent asset, or (with
`--download-referred-js`) anything referenced. **(design, SSRF guard)**

## 7. Authenticated fetching

R-60. When the tool fetches chunks or source maps derived from a captured
request, it forwards that request's authentication headers (default `Cookie`,
`Authorization`; configurable list) so assets behind auth are downloaded
correctly instead of a login redirect. `[#31]`

R-61. **(design, security)** Forwarding is limited by `--forward-auth`
`same-host` (default), `in-scope`, or `never`; headers are never forwarded to
other hosts by default, and never across an `https`→`http` downgrade.

R-62. **(design)** Extra static headers can be supplied with `--header 'K: V'`
(repeatable) for every tool-initiated fetch.

## 8. Source maps

R-70. Reverse application source code when source maps are available. `[README]`

R-71. Discovery order, first hit wins `[#13]`:
1. `SourceMap` response header, then `X-SourceMap`.
2. The last `//# sourceMappingURL=` (or legacy `//@`) comment in the file.
3. Inline `data:` URIs (base64 or percent-encoded JSON).
4. A guess: `<url-without-query>.map`.

R-72. Transient fetch failures (connect errors, 429, 5xx) are retried with
backoff (default 2 retries). `[#13]`

R-73. A response is only accepted as a source map if it parses as one; HTML login
pages or 404 bodies are rejected. `[#13]`, `[#31]`

R-74. Each `sources[i]` that has `sourcesContent[i]` is written to disk
(R-34); sources without content are listed in the log. `[README]`

## 9. AST analysis

R-80. Analyze each JS file's AST and record findings with file, line, column,
category path and matched value. `[README]`, `[TREE]`

R-81. Rules are extensible: each rule is a type implementing a `Rule` trait,
registered in a registry; adding one requires no pipeline changes. `[#16]`

R-82. Shipped rule categories (subset of `[TREE]` plus `[#16]` requests):
- Client behavior: `addEventListener` (event name), `onmessage`, `postMessage`,
  `onhashchange`, `eval`/`Function`/string `setTimeout`/`setInterval`,
  `document.domain`, `window.open`, `innerHTML`/`outerHTML`/`insertAdjacentHTML`,
  `document.write`, `fetch`, `XMLHttpRequest.open`, axios/jQuery ajax ("possible
  REST client" with method), `URLSearchParams`, `location` read/assign,
  `window.name`, `document.cookie`, `localStorage`/`sessionStorage`.
- Data: URL paths, API paths, full URLs, hostnames, query strings, file
  extensions, MIME types, regex literals, secrets/API keys, GraphQL
  queries/mutations, header names in request options.
- Frameworks: React `dangerouslySetInnerHTML`.
- Object schemas: fetch options objects (method/headers keys).

R-83. Findings are stored in the database and shown in the TUI and via CLI
(`findings`), including JSON output for editor integrations. **(design;
upstream used a VSCode extension `[README]`, `[#27]`)**

## 10. User interface

R-90. A terminal UI shows assets, findings for the selected asset, and logs.
`[README]` (prompt, `logs (l)` toggles logs).

R-91. Every list in the TUI is scrollable with keyboard (arrows/`j`/`k`,
PgUp/PgDn, Home/End) and works on small terminals (≥ 40×12): panes collapse
instead of overflowing. Help/options are shown in a scrollable popup. `[#18]`

R-92. A non-TUI mode (`--no-tui`) prints logs to stderr for headless use.
**(design)**

R-93. CLI subcommands: `serve` (default), `ingest-urls`, `ingest-har`,
`assets [--search]`, `loads <html-url>`, `loaded <js-url>`, `findings`,
`rules`, `analyze <file>`, `truncate`. `[README]` (prompt command list)

R-94. `--debug` enables verbose logs; logs are also written to
`~/.jxscout-rs/jxscout.log`. `[README]` (Troubleshooting → View logs)

## 11. Non-goals for v0.1

- Caido match-and-replace "overrides" (`override`, `caido-auth`) `[README]`.
- The VSCode extension; findings are exposed as JSON instead.
- An interactive prompt shell; subcommands + TUI replace it.

## 12. Upstream issue mapping

| Issue | Requirement(s) |
| --- | --- |
| #31 chunks behind auth | R-60, R-61, R-62, R-73 |
| #27 extension panel missing | R-83 (triage: VSCode-specific; findings exposed via TUI/CLI/JSON; active project shown in TUI header) |
| #20 non-Burp/Caido user | R-11, R-12, R-14 |
| #19 "Unexpected token" in chunk discoverer | R-42, R-43, R-32 (the logged `not a directory` error) |
| #18 can't scroll options | R-91 |
| #17 failed to install bun | R-02 |
| #16 more AST rules | R-81, R-82 |
| #13 source maps not always downloaded | R-71, R-72, R-73 |
| #9 show out-of-scope request in debug | R-24 |
| #8 scope from file | R-21, R-22 |
