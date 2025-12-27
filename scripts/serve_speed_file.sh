#!/usr/bin/env bash
set -euo pipefail

# Helper: run speed test serving a local temporary file of N MB
# Usage: ./serve_speed_file.sh <URL> <MB> [OUTPUT]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$SCRIPT_DIR/../main.py"
PYTHON_BIN="${PYTHON:-python}"

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <URL> <MB> [OUTPUT]"
  exit 1
fi

URL="$1"
MB="$2"
OUTPUT="${3:-nodes_speed_local.json}"

exec "$PYTHON_BIN" "$MAIN" --url "$URL" --output "$OUTPUT" --do-speed --serve-speed-size "$MB" --speed-duration "${SPEED_DURATION:-10}" --speed-concurrency "${SPEED_CONCURRENCY:-1}" "$@"
