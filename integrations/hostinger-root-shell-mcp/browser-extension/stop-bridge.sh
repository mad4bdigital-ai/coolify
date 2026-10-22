#!/bin/sh
# Stop only the exact local bridge process, never Chromium or Webtop.
for pid in $(pgrep -f '^python3 /config/hpanel-reader-extension/bridge_server.py$' || true); do
    kill "$pid" 2>/dev/null || true
done
