#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/verify_pipeline.sh"
  exit 1
fi

echo '04/03-14:22:01.123456  [**] [1:1000001:2] [SSH] Brute Force Attack [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1]
TCP 1.2.3.4:54321 -> 203.0.113.10:22' >> /var/log/snort/alert.log

tail -n 20 /var/log/snort/alert.log
journalctl -u snort-watcher -n 40 --no-pager
