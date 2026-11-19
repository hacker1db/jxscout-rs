#!/usr/bin/env bash
# Smoke-test a release binary: runs, is static on Linux, opens SQLite,
# builds the TLS client, and analyzes JS.
set -euo pipefail
BIN="$1"
EXPECTED_VERSION="${2:-}"
got="$("$BIN" --version)"
echo "$got"
if [[ -n "$EXPECTED_VERSION" && "$got" != "jxscout-rs $EXPECTED_VERSION" ]]; then
  echo "expected 'jxscout-rs $EXPECTED_VERSION', got '$got'" >&2
  exit 1
fi
"$BIN" rules >/dev/null
if [[ "$(uname -s)" == "Linux" ]]; then
  if file "$BIN" | grep -q "dynamically linked"; then
    echo "expected a static binary: $(file "$BIN")" >&2
    exit 1
  fi
fi
tmp="$(mktemp -d)"
printf 'eval(location.hash)\n' > "$tmp/a.js"
"$BIN" analyze "$tmp/a.js" | grep -q "Client Behavior/eval"
# Empty URL list: exercises config, SQLite (bundled), and the rustls client.
printf '# nothing\n' > "$tmp/urls.txt"
"$BIN" --output-dir "$tmp/out" ingest-urls "$tmp/urls.txt" >/dev/null
test -f "$tmp/out/.jxscout-rs/default.db"
# HAR import with a gzip-encoded body header (decoded by the HAR exporter).
printf '{"log":{"entries":[{"request":{"method":"GET","url":"https://smoke.test/a.js"},"response":{"status":200,"headers":[{"name":"content-type","value":"text/javascript"}],"content":{"text":"eval(x)"}}}]}}' > "$tmp/s.har"
"$BIN" --output-dir "$tmp/out" --no-sourcemaps ingest-har "$tmp/s.har" >/dev/null
echo "smoke test ok"
