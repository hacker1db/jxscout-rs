# Review log

Continuous review by Codex (`gpt-6.2-sol`, read-only sandbox) at each milestone.
Every finding is either fixed or rejected with a one-line reason.

## Milestone 1: docs/SPEC.md (`2be16b5..c1d90a6`)

| # | Sev | Finding | Action |
| --- | --- | --- | --- |
| 1 | High | SSRF: host-only check, only chunks/maps, no IP/redirect policy | Fixed: R-56 now one outbound policy for every fetch + redirect hop; IP check in DNS resolver; `--allow-private-targets` opt-in |
| 2 | High | Credential forwarding allowed cross-port; static headers sent everywhere | Fixed: R-61 default `same-origin`; R-62 static headers only to in-scope origins; dropped on cross-origin redirect |
| 3 | High | Filesystem escape: symlinks, decoding order, collisions unspecified | Fixed: R-33 decode-before-validate, project-name validation, no symlink follow, deterministic collisions. Rejected race-safe `openat` style writes: single-user local tool, symlink check + confinement is proportionate |
| 4 | High | Resource exhaustion beyond per-download cap | Fixed: R-36 decompressed-stream cap, total timeout, depth/chunk/source budgets; R-11 ingest body + batch caps |
| 5 | Med | Ingest trust boundary | Fixed: R-11a optional bearer token, non-loopback bind needs `--allow-remote-ingest`. Rejected making missing-body fetches opt-in: they are still scope + SSRF guarded and are needed for curl/URL-list users (#20) |
| 6 | Med | Scope precedence ambiguous | Fixed: R-22a exclusions always win; negative-only scope defined |
| 7 | Med | ESM bare specifiers mis-resolved | Fixed: R-53 resolution rules per specifier form; bare specifiers skipped |
| 8 | Med | Source-map "first hit" ambiguous | Fixed: R-71/R-73 first *validated* candidate wins; 2xx + parse required |
| 9 | Low | Clean-room traceability | Fixed: pinned README/tree.md commit links, release links, note that code links inside issues were not followed |

## Milestone 2: core lib, ingest, pipeline (`f7db590..277a275`)

Scoped to `src/{config,scope,model,net,store,js,pipeline,ingest,events,main,lib}` and `tests/`.

| # | Sev | Finding | Action |
| --- | --- | --- | --- |
| 1 | High | Env proxy bypasses guarded resolver | Fixed: `.no_proxy()`; regression `tests/proxy_env.rs` |
| 2 | High | Credentials re-sent after cross-origin redirect | Fixed: once a chain leaves the first origin no credentials are sent for the rest of it; test `credentials_are_not_resent_after_leaving_the_origin` |
| 3 | High | Symlink following in store (root, temp file, races) | Fixed: project dir must not be a symlink, temp files opened `create_new` (O_EXCL), cleanup on failed rename; tests `refuses_symlinked_project_dir_and_leaf`. Rejected full `openat`/handle-anchored walk: local single-user tool, attacker needs write access to the output dir already |
| 4 | High | Unbounded task admission | Fixed: `MAX_PENDING` (20k) bounded admission; HTTP returns 503, file sources use `submit_wait` backpressure |
| 5 | Med | Auth checked after body parse | Fixed: guard middleware (Host, token, Content-Type) runs before extraction; test `host_and_content_type_are_enforced_before_the_body` |
| 6 | Med | Redirect hops not rate-limited; permit held during backoff | Fixed: limiter per hop, permit scoped to one attempt |
| 7 | Med | Redirected assets resolve against requested URL | Fixed: final URL used as base/parent, requested URL stays DB key; test `redirected_pages_resolve_against_final_url` |
| 8 | Med | Failed derived fetch stays "seen"; chunks re-downloaded after restart | Fixed: claim released on failure; chunks already in DB are skipped |
| 9 | Med | Query variants share one file | Rejected: intentional; cache-busting `?v=` would otherwise multiply identical files. DB keeps per-URL rows and hashes |
| 10 | Med | MSRV 1.88 too low for oxc 0.159 | Fixed: `rust-version = "1.98"` |
| 11 | Med | Webpack evaluation unbounded before cap | Fixed: per-script evaluation budget, names deduped and JS-filtered while generated |
| 12 | Low | `wait_idle` close/reopen race with concurrent callers | Rejected: single owner by design (CLI command / test); documented on the method |
| 13 | Low | Extensionless ESM imports skipped | Fixed: `./bootstrap` followed, `.css`/`.json` skipped; test `extensionless_imports` |
| 14 | Low | Blocking file I/O on async workers | Fixed for file writes (`spawn_blocking`). SQLite calls stay inline: indexed single-row queries under WAL, microseconds |

## Milestone 3: AST rules + TUI (`f7db590..277a275`)

Scoped to `src/rules`, `src/tui`, `src/js/chunks.rs`.

| # | Sev | Finding | Action |
| --- | --- | --- | --- |
| 1 | High | Table-only webpack filenames dropped | Fixed: `.js` in table values counts; test `table_only_filenames` |
| 2 | High | Public path handling (relative prefixes, multiple runtimes) | Fixed concat semantics + relative prefixes; test `relative_public_path`. Rejected per-runtime association: one runtime per bundle file is the norm, first plausible `.p` is used |
| 3 | High | Lag resync can show wrong asset's findings | Fixed: `select_url` restores by URL, findings reloaded; test `select_url_survives_reorder` |
| 4 | Med | Computed members / `window.location =` missed | Fixed; test `computed_members_and_location_object`. Rejected bare `location` reads (too noisy) and compound/update split (still reported as Assignment) |
| 5 | Med | Evaluator string-only semantics | Rejected: webpack filename functions only concatenate; ids are compared as the same strings the table keys use, matching runtime behavior for chunk ids |
| 6 | Med | Heuristic webpack candidates crowd out explicit imports | Fixed: ESM/preload first, dedup before cap |
| 7 | Med | Sync SQLite in TUI loop (N+1 counts) | Fixed N+1 with `assets_with_counts` single query. Per-selection findings query kept inline (indexed, small) |
| 8 | Med | axios config / `$.ajax` method / tuple headers missed | Fixed; test `request_configs`. Rejected restricting `.open()` to XHR-named receivers: minified code renames them, category is explicitly "Possible" |
| 9 | Med | Help popup scrolls into blank space, no End | Fixed: clamp to wrapped content height, End key |
| 10 | Med | Standalone hostnames missed | Fixed with curated-TLD regex; test `standalone_hostnames` |
| 11 | Low | Known token double-reported | Fixed: generic assignment skips values matching a known format; test `known_token_not_double_reported` |

## Security review (security-guidance plugin, on `277a275`)

| # | Sev | Finding | Action |
| --- | --- | --- | --- |
| 1 | Med | SSRF bypass via env proxy; redirects/literal IPs | Fixed `.no_proxy()` (no proxy opt-in offered); redirects were already re-validated per hop, literal IPs checked by `check_url_host`; regression `tests/proxy_env.rs` |
| 2 | Med | IPv6 embedded-IPv4 forms (NAT64, 6to4, Teredo, compat) | Fixed: `embedded_v4` + Teredo/site-local blocked; table tests in `guard.rs` |
| 3 | Med | Local ingest open to DNS rebinding / CSRF | Fixed: Host allow-list, random persisted token by default (`--no-auth` opt-out), JSON-only Content-Type, 64 MiB cap; Caido plugin sends the token; ingest tests |
| 4 | Med | Terminal escape injection | Fixed: `text::clean` escapes control + bidi chars in CLI output, TUI, and log pane; unit test |
