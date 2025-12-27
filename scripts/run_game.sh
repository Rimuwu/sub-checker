#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run_game.sh <URL> <UDP_TARGET host:port> [OUTPUT]
# Example: ./run_game.sh "https://example.com/sub" "1.2.3.4:27015" game_nodes.json

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$SCRIPT_DIR/../main.py"
PYTHON_BIN="${PYTHON:-python}"

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <URL> <UDP_TARGET host:port> [OUTPUT]"
  exit 1
fi

URL="$1"
UDP_TARGET="$2"
OUTPUT="${3:-nodes_game.json}"
GAME_DURATION="${GAME_DURATION:-5}"
GAME_PSIZE="${GAME_PSIZE:-60}"
GAME_INTERVAL="${GAME_INTERVAL:-20}"

exec "$PYTHON_BIN" "$MAIN" --url "$URL" --output "$OUTPUT" --do-game --udp-target "$UDP_TARGET" --game-duration "$GAME_DURATION" --game-psize "$GAME_PSIZE" --game-interval "$GAME_INTERVAL" "$@"
