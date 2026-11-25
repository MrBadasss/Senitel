#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/enable_services.sh"
  exit 1
fi

snort -T -c /etc/snort/snort.conf -i eth0

systemctl daemon-reload
systemctl enable --now snort
systemctl enable --now snort-watcher

systemctl status snort --no-pager
systemctl status snort-watcher --no-pager
