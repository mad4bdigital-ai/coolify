#!/bin/sh
set -eu
export MAD4B_BROWSER_PAIRING_TOKEN="$(cat /config/hpanel-reader-extension/bridge-token)"
exec python3 /config/hpanel-reader-extension/bridge_server.py
