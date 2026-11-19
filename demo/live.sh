#!/usr/bin/env bash
# Start the TUI + ingest endpoint, and after a few seconds POST the fixture
# page to it the way a proxy plugin would.
set -euo pipefail
OUT="${OUT:?set OUT to an output directory}"
(
  sleep 4
  curl -s -H "Authorization: Bearer $(cat "$OUT/.jxscout-rs/ingest-token")" \
    -H 'content-type: application/json' \
    -d '{"request":{"url":"http://127.0.0.1:8765/"}}' \
    http://127.0.0.1:3333/ingest >/dev/null
) &
exec jxscout-rs --output-dir "$OUT" -p live --allow-private-targets --rate-limit-rps 2 serve
