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

## Security review, 2nd pass (security-guidance plugin, on `f3ebc69`)

| # | Sev | Finding | Action |
| --- | --- | --- | --- |
| 1 | Med | Post-redirect base used as trusted parent: credential leak / scope bypass | Fixed: children and source-map fetches use the requested URL as parent; credentials dropped when the final origin differs; cross-origin `in-scope` forwarding mode removed entirely (R-61). Regression `redirect_target_is_not_a_trusted_parent` (verified failing on the old code) |
| 2 | Med | `analyze` printed category unsanitized | Fixed: categories restricted to a safe alphabet at creation (`text::category`), verbs allow-listed, `Clean` Display wrapper added, all CLI prints sanitized; `tests/output_hygiene.rs` fails on any raw finding-field `println!` |

## Milestone 4: CI, CodeQL, GitGuardian, release, Caido plugin, docs (`277a275..7b90fa3`)

| # | Sev | Finding | Action |
| --- | --- | --- | --- |
| 1 | Med | Manual dispatch against a tag could publish | Fixed: publish requires `push` + tag; `gh release create --verify-tag` |
| 2 | Med | Caido plugin could send cookies/token over plaintext to a remote endpoint | Fixed: plain `http` only to loopback (`endpointProblem` + test); README says mark `JXSCOUT_TOKEN` secret |
| 3 | Med | Headless mode printed the token | Fixed: prints only the token file path for generated tokens, nothing for explicit ones |
| 4 | Med | Caido plugin encoded bodies the server would reject | Fixed: 40 MiB pre-check on `Body.length` before copying |
| 5 | Low | arm64 musl never executed; smoke test too shallow; zigbuild unpinned | Fixed: `smoke-arm64` job on `ubuntu-24.04-arm`, shared `.github/smoke-test.sh` (static check, SQLite, TLS client, analyzer), `cargo-zigbuild@0.24.1` |
| 6 | Low | GitGuardian ignores too broad | Fixed: only the two files embedding AWS's documented example key. Kept the skip-with-notice behavior when the secret is absent (explicit requirement) |
| 7 | Low | cargo-deny unsound scope | Fixed: `unsound = "all"` |
| 8 | Low | Challenge 3 proof could pass vacuously; challenge 7 signature wording | Fixed both |
| 9 | Low | README HAR command missing file | Fixed |

## Milestone 5: final pre-PR pass (`7b90fa3..00c8e58`, plus `277a275..00c8e58 -- src/`)

| # | Sev | Finding | Action |
| --- | --- | --- | --- |
| 1 | High | Credential eligibility lost when a redirect chain returned to the origin | Fixed: `FetchResponse::stayed_on_origin`; descendants of such a response get no captured credentials. `credentials_are_not_resent_after_leaving_the_origin` now also asserts the child request has no cookie (verified failing on the previous code). Static `--header` values stay scope-based by design (R-62) |
| 2 | Med | Caido plaintext check used a regex on the authority (userinfo bypass) | Fixed: WHATWG `URL` parsing, userinfo rejected, userinfo tests. Redirect behavior of Caido's `fetch` isn't configurable through `RequestOpts`, so it's documented as a limitation |
| 3 | Med | Non-2xx derived fetches stayed claimed for the session | Fixed: claim released on non-2xx too; test `failed_derived_fetch_can_be_rediscovered` |
| 4 | Med | Admission bounded count, not bytes; `submit_wait` race | Fixed: RAII `AdmitGuard` over items **and** body bytes (512 MiB), `submit_wait` reserves atomically; ingest server bounds concurrent body buffering (8) |
| 5 | Med | Chunk tables re-parsed per lookup | Fixed: tables parsed once per expression in `ExprInfo`, lookups by span |
| 6 | Med | Local-use NAT64 IPv4 position assumed | Fixed: whole `64:ff9b:1::/48` blocked; tests |
| 7 | Low | Temp file left on failed write; source writes on async worker | Fixed: temp removed on write failure; recovered-source batch runs in `spawn_blocking` |
| 8 | Low | Raw filesystem paths printed | Rejected: the remaining raw paths (`analyze <file>`, project dir) are user-supplied CLI/config values, not attacker-derived; attacker-derived fields all go through `clean` |
| 9 | Low | Release: Caido typecheck; gate publish on CI; TLS handshake in smoke | Fixed typecheck; zig pinned to 0.17.1 (the version the local aarch64-musl cross build was verified with). Rejected gating publish on a separate CI run: the release workflow rebuilds and smoke-tests every artifact itself and tags are cut from `main` after PR CI. Rejected a TLS handshake in smoke: needs network or a cert fixture; client construction + rustls init is covered |
