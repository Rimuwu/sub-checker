#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run_basic.sh <URL> [OUTPUT] [-- extra args passed to main.py]
# Example: ./run_basic.sh "https://example.com/sub" nodes.json

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$SCRIPT_DIR/../main.py"
PYTHON_BIN="${PYTHON:-python}"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <URL> [OUTPUT] [-- extra args]"
  exit 1
fi

URL="$1"
OUTPUT="${2:-nodes.json}"
shift || true
if [ "$#" -gt 0 ]; then
  # if user passed second arg and it's not an extra option
  if [[ $@ != --* ]]; then
    # remove the second arg (output) from parameters if it was consumed
    shift || true
  fi
fi

echo "Running basic checks for: $URL"
exec "$PYTHON_BIN" "$MAIN" --url "$URL" --output "$OUTPUT" --workers "${WORKERS:-10}" --timeout "${TIMEOUT:-5}" "$@"
