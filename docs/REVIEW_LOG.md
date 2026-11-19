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
