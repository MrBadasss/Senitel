#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/setup_modsecurity.sh"
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODSEC_DIR="/usr/local/lsws/conf/modsec"

mkdir -p "${MODSEC_DIR}"
cd "${MODSEC_DIR}"

if [[ ! -f v3.3.5.tar.gz ]]; then
  wget https://github.com/coreruleset/coreruleset/archive/v3.3.5.tar.gz
fi

tar -xzf v3.3.5.tar.gz
cp -f coreruleset-3.3.5/crs-setup.conf.example crs-setup.conf
cp -f "${PROJECT_ROOT}/modsecurity/modsec.conf" "${MODSEC_DIR}/modsec.conf"

echo "ModSecurity CRS prepared. Enable ModSecurity per site in CyberPanel and restart OpenLiteSpeed."
