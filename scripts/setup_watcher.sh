#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/setup_watcher.sh"
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p /opt/snort-alert
python3 -m venv /opt/snort-alert/venv
/opt/snort-alert/venv/bin/pip install --upgrade pip
/opt/snort-alert/venv/bin/pip install -r "${PROJECT_ROOT}/watcher/requirements.txt"

cp -f "${PROJECT_ROOT}/watcher/watcher.py" /opt/snort-alert/watcher.py
chmod 700 /opt/snort-alert/watcher.py

if [[ ! -f /opt/snort-alert/.env ]]; then
  cp -f "${PROJECT_ROOT}/.env.example" /opt/snort-alert/.env
  echo "Created /opt/snort-alert/.env - edit it before starting services."
fi
