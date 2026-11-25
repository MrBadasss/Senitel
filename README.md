# Senitel

Senitel is an intrusion detection and response setup for an Ubuntu VPS running CyberPanel with OpenLiteSpeed. It combines Snort network detection, ModSecurity web application firewalling, and a Python alert watcher that notifies you and blocks attackers automatically.

## What it does

- **Snort IDS** watches all VPS traffic, including Docker bridge networks, with 35 custom rules covering:
  - SSH, FTP, SMTP, IMAP and POP3 brute force and root login attempts
  - Web attacks: SQL injection, XSS, directory traversal, remote file inclusion, command injection and Shellshock
  - HTTP flood, automated scanners (sqlmap, nikto, nmap, masscan and others) and CyberPanel admin brute force
  - Legacy TLS handshakes (SSLv3, TLS 1.0, TLS 1.1)
  - Port scans (TCP SYN, UDP, ICMP ping sweep) and external MySQL access
  - Outbound indicators: IRC command-and-control ports, crypto miner pools, large DNS queries and reverse shells
  - Docker container egress to the internet
- **Alert watcher** (`watcher/watcher.py`) tails the Snort alert log and the ModSecurity audit log, then:
  - Sends an email and a Telegram alert for each new alert, with priority, source, destination and recommended actions
  - Auto-blocks the source IP with UFW for critical (priority 1) alerts, and sends a Telegram notice with the unblock command
  - Throttles repeated alerts (120 seconds per message) and suppresses bursts (more than 10 alerts in 60 seconds from one IP)
  - Never blocks the server's own IP, loopback, or IPs on the exclusion list, and keeps working if email or Telegram fails
- **ModSecurity with OWASP CRS** inspects decrypted HTTPS traffic in OpenLiteSpeed, which Snort cannot see inside encrypted TLS.

## Project structure

```
snort/snort.conf          Snort configuration template
snort/rules/local.rules   Custom detection rules (SIDs 1000001-1000064)
watcher/watcher.py        Alert processor: email, Telegram, UFW auto-block
watcher/requirements.txt  Python dependency (requests)
systemd/snort.service     Snort service unit
systemd/snort-watcher.service  Watcher service unit
modsecurity/modsec.conf   ModSecurity configuration for OpenLiteSpeed
logrotate/snort           Rotation rules for Snort and ModSecurity logs
scripts/*.sh              Install, deploy, verify and helper scripts
.env.example              Environment template for watcher settings
```

## Configure before deploying

1. `snort/snort.conf` — set `HOME_NET` to your VPS IP or CIDR, and `DOCKER_NET` to your Docker network ranges.
2. Copy `.env.example` to `/opt/snort-alert/.env` and fill in:
   - SMTP credentials (optional; leave blank to disable email)
   - Telegram bot token and chat IDs (`TELEGRAM_CHAT_IDS` accepts a comma-separated list)
   - `VPS_IP`
   - `WATCH_MODSEC=true` and `MODSEC_AUDIT_LOG=/var/log/modsec_audit.log`
   - `AUTO_BLOCK_EXCLUDE_IPS` for trusted IPs that must never be blocked

## Deploy on Ubuntu

Run in order from the project root:

```bash
sudo bash scripts/install_snort_ufw.sh   # Install Snort + UFW, baseline firewall rules
sudo bash scripts/deploy_configs.sh      # Deploy Snort, systemd and logrotate configs
sudo bash scripts/setup_watcher.sh       # Watcher runtime, then edit /opt/snort-alert/.env
sudo bash scripts/setup_modsecurity.sh   # ModSecurity CRS for OpenLiteSpeed
sudo bash scripts/enable_services.sh     # Validate and start services
sudo bash scripts/verify_pipeline.sh     # Verify the alert pipeline
```

Then in CyberPanel, enable ModSecurity per website under Security, and restart OpenLiteSpeed.

Get a Telegram chat ID with:

```bash
bash scripts/get_telegram_chat_id.sh <BOT_TOKEN>
```

## Live operations

```bash
sudo tail -f /var/log/snort/alert.log
sudo journalctl -u snort-watcher -f
sudo ufw status verbose
```

## Limits

- Snort sees encrypted traffic only at the network layer (handshakes, protocols, brute-force patterns, scans, denial of service, outbound indicators). It cannot decrypt SSH or TLS payloads. HTTPS payload inspection is done by ModSecurity after OpenLiteSpeed decrypts it.
- If Tor is intentional on the server, add its IPs to `AUTO_BLOCK_EXCLUDE_IPS` to prevent unwanted auto-blocking.
