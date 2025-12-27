#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run_full_test.sh <URL> [UDP_TARGET host:port] [OUTPUT]
# Composite run: ping/tcp + speed + optional game + start xray + generate html report (opened if supported)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$SCRIPT_DIR/../main.py"
PYTHON_BIN="${PYTHON:-python}"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <URL> [UDP_TARGET] [OUTPUT]"
  exit 1
fi

URL="$1"
UDP_TARGET="${2:-}"
OUTPUT="${3:-nodes_full.json}"
HTML_OUTPUT="report.html"

CMD=("$PYTHON_BIN" "$MAIN" --url "$URL" --output "$OUTPUT" --do-speed --speed-duration "${SPEED_DURATION:-10}" --speed-concurrency "${SPEED_CONCURRENCY:-1}" --start-xray --html-output "$HTML_OUTPUT" --open-report)
if [ -n "$UDP_TARGET" ]; then
  CMD+=(--do-game --udp-target "$UDP_TARGET" --game-duration "${GAME_DURATION:-5}")
fi

echo "Running full test for: $URL"
exec "${CMD[@]}" "$@"
