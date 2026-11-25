#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/deploy_configs.sh"
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p /etc/snort/rules /var/log/snort /opt/snort-alert /etc/systemd/system /etc/logrotate.d
cp -f "${PROJECT_ROOT}/snort/snort.conf" /etc/snort/snort.conf
cp -f "${PROJECT_ROOT}/snort/rules/local.rules" /etc/snort/rules/local.rules
cp -f "${PROJECT_ROOT}/systemd/snort.service" /etc/systemd/system/snort.service
cp -f "${PROJECT_ROOT}/systemd/snort-watcher.service" /etc/systemd/system/snort-watcher.service
cp -f "${PROJECT_ROOT}/logrotate/snort" /etc/logrotate.d/snort

touch /var/log/snort/alert.log
chmod 755 /var/log/snort

echo "Config deployment complete."
