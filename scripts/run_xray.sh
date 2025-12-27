#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run_xray.sh <URL> [OUTPUT]
# Starts xray (use XRAY_PATH env var to override) and proxies tests through it.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$SCRIPT_DIR/../main.py"
PYTHON_BIN="${PYTHON:-python}"
XRAY_PATH="${XRAY_PATH:-xray}"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <URL> [OUTPUT]"
  exit 1
fi

URL="$1"
OUTPUT="${2:-nodes_xray.json}"

exec "$PYTHON_BIN" "$MAIN" --url "$URL" --output "$OUTPUT" --start-xray --xray-path "$XRAY_PATH" "$@"
