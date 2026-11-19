#!/usr/bin/env bash
# Smoke-test a release binary: runs, is static on Linux, opens SQLite,
# builds the TLS client, and analyzes JS.
set -euo pipefail
BIN="$1"
"$BIN" --version
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
echo "smoke test ok"
