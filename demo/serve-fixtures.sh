#!/usr/bin/env bash
# Serve the demo fixture site on 127.0.0.1:8765 (no network needed).
set -euo pipefail
cd "$(dirname "$0")/fixtures/site"
exec python3 -m http.server 8765 --bind 127.0.0.1
