#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: bash scripts/get_telegram_chat_id.sh <BOT_TOKEN>"
  exit 1
fi

curl -s "https://api.telegram.org/bot$1/getUpdates" | python3 -m json.tool | grep '"id"' | head -5
