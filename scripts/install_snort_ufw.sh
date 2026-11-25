#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install_snort_ufw.sh"
  exit 1
fi

MAIN_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
MAIN_IFACE="${MAIN_IFACE:-eth0}"

# Avoid package post-install service auto-start (common failure with transient veth interfaces)
POLICY_RC_PATH="/usr/sbin/policy-rc.d"
trap 'rm -f "${POLICY_RC_PATH}"' EXIT
cat > "${POLICY_RC_PATH}" <<'EOF'
#!/bin/sh
exit 101
EOF
chmod +x "${POLICY_RC_PATH}"

apt update
DEBIAN_FRONTEND=noninteractive apt install -y snort ufw

# Recover if dpkg was left half-configured by previous failed snort postinst
DEBIAN_FRONTEND=noninteractive dpkg --configure -a || true
DEBIAN_FRONTEND=noninteractive apt -f install -y || true

# Pin Debian Snort init helper to stable main interface only
if [[ -f /etc/snort/snort.debian.conf ]]; then
  if grep -q '^DEBIAN_SNORT_INTERFACE=' /etc/snort/snort.debian.conf; then
    sed -i "s/^DEBIAN_SNORT_INTERFACE=.*/DEBIAN_SNORT_INTERFACE=\"${MAIN_IFACE}\"/" /etc/snort/snort.debian.conf
  else
    echo "DEBIAN_SNORT_INTERFACE=\"${MAIN_IFACE}\"" >> /etc/snort/snort.debian.conf
  fi
fi

rm -f "${POLICY_RC_PATH}"
trap - EXIT

ufw default deny incoming
ufw default allow outgoing

for rule in \
  "22/tcp" "80/tcp" "443/tcp" "443/udp" "8090/tcp" "7080/tcp" \
  "25/tcp" "465/tcp" "587/tcp" "110/tcp" "143/tcp" "993/tcp" "995/tcp" "21/tcp"; do
  ufw allow "$rule"
done
ufw allow 53

ufw --force enable
ufw status verbose
