#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run_speed.sh <URL> [OUTPUT]
# Environment overrides:
#  SPEED_URL (default: http://speedtest.tele2.net/5MB.zip)
#  SPEED_DURATION, SPEED_CONCURRENCY
#  SERVE_SPEED_SIZE (MB) to serve a local file via built-in server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$SCRIPT_DIR/../main.py"
PYTHON_BIN="${PYTHON:-python}"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <URL> [OUTPUT]"
  exit 1
fi

URL="$1"
OUTPUT="${2:-nodes_speed.json}"
SPEED_URL="${SPEED_URL:-http://speedtest.tele2.net/5MB.zip}"
SPEED_DURATION="${SPEED_DURATION:-10}"
SPEED_CONCURRENCY="${SPEED_CONCURRENCY:-1}"
SERVE_SIZE="${SERVE_SPEED_SIZE:-0}"

if [ "$SERVE_SIZE" -gt 0 ] 2>/dev/null; then
  echo "Using local served file of ${SERVE_SIZE}MB for speed tests"
  exec "$PYTHON_BIN" "$MAIN" --url "$URL" --output "$OUTPUT" --do-speed --speed-duration "$SPEED_DURATION" --speed-concurrency "$SPEED_CONCURRENCY" --serve-speed-size "$SERVE_SIZE" "$@"
else
  exec "$PYTHON_BIN" "$MAIN" --url "$URL" --output "$OUTPUT" --do-speed --speed-url "$SPEED_URL" --speed-duration "$SPEED_DURATION" --speed-concurrency "$SPEED_CONCURRENCY" "$@"
fi
