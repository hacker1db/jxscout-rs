# jxscout-rs Caido plugin

Backend-only Caido plugin that forwards in-scope HTML and JavaScript
responses to a running `jxscout-rs serve`.

```sh
pnpm install --frozen-lockfile
pnpm test        # unit tests for the payload helpers (Node >= 22.18)
pnpm build       # → dist/plugin_package.zip
```

Install: Caido → Plugins → Install Package → choose `dist/plugin_package.zip`
(or download `jxscout-rs-caido-plugin.zip` from a GitHub release).

Configure under Caido → Environment → Global:

| Variable | Default | Meaning |
| --- | --- | --- |
| `JXSCOUT_ENDPOINT` | `http://127.0.0.1:3333/ingest` | ingest URL |
| `JXSCOUT_TOKEN` | (none) | token printed by `jxscout-rs serve` |
| `JXSCOUT_IN_SCOPE_ONLY` | `true` | only forward requests in the Caido scope |

Safety: the plugin refuses plain-`http` endpoints that aren't loopback and
endpoints with credentials in the URL. It skips responses over 40 MiB. Caido's
backend `fetch` doesn't let plugins control redirects, so point
`JXSCOUT_ENDPOINT` at the jxscout-rs server directly, not at something that
redirects.
