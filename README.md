# Senitel — Snort IDS Project for VPS (CyberPanel/OpenLiteSpeed)

This repository implements the full project from your shared chat:

- Snort-based IDS for full VPS traffic (`-i any`, including Docker bridges)
- Custom rules for SSH/FTP/Web/Mail/DB/port scan/outbound indicators
- Python alert watcher for real-time Email + Telegram alerts
- Optional UFW auto-block for critical alerts
- ModSecurity + OWASP CRS setup for HTTPS-layer protection on OpenLiteSpeed
- systemd and logrotate configs for production operation

## Encrypted Traffic Coverage (Important)

- HTTPS payload inspection is done by ModSecurity in OpenLiteSpeed (decrypted at web server).
- Snort still monitors encrypted TLS/SSH at network layer (handshake/protocol/behavior anomalies, brute-force patterns, scans, DoS, outbound indicators).
- Snort cannot decrypt arbitrary SSH or end-to-end TLS payloads directly.
- The watcher now monitors both Snort alerts and ModSecurity audit alerts for immediate Email/Telegram notifications.
- If Tor is intentional, keep it running and add trusted IPs to `AUTO_BLOCK_EXCLUDE_IPS` in `.env` to prevent unwanted auto-blocking.

## Project Structure

- `snort/snort.conf` — Snort main configuration template
- `snort/rules/local.rules` — Custom detection rules
- `watcher/watcher.py` — Alert processor (email/telegram/autoblock)
- `watcher/requirements.txt` — Python dependency (`requests`)
- `systemd/snort.service` — Snort service unit
- `systemd/snort-watcher.service` — Watcher service unit
- `modsecurity/modsec.conf` — ModSecurity main config for OLS
- `logrotate/snort` — Rotation rules for Snort + ModSecurity logs
- `scripts/*.sh` — Installation/deployment/verification scripts
- `.env.example` — Environment template for watcher secrets

## Important Customization Before Deploy

Update these values first:

1. `snort/snort.conf`
   - `HOME_NET` (your VPS IP/CIDR)
   - `DOCKER_NET` ranges if your Docker networks differ
2. `.env.example` (later copied to `/opt/snort-alert/.env`)
   - SMTP credentials (optional; leave blank to disable email)
   - Telegram bot token/chat IDs (`TELEGRAM_CHAT_IDS` supports comma-separated list)
   - `VPS_IP`
   - `WATCH_MODSEC=true` and `MODSEC_AUDIT_LOG=/var/log/modsec_audit.log`
   - optional `AUTO_BLOCK_EXCLUDE_IPS` (comma-separated)
3. Any ports/rules you don’t use (mail/ftp/db/admin ports)

## Deployment Steps on VPS (Ubuntu)

Run in this order from project root:

1. Install Snort + UFW and baseline firewall rules

```bash
sudo bash scripts/install_snort_ufw.sh
```

2. Deploy Snort/systemd/logrotate configs

```bash
sudo bash scripts/deploy_configs.sh
```

3. Set up watcher runtime (venv + script + env)

```bash
sudo bash scripts/setup_watcher.sh
sudo nano /opt/snort-alert/.env
```

4. Set up ModSecurity CRS for OpenLiteSpeed (HTTPS inspection path)

```bash
sudo bash scripts/setup_modsecurity.sh
```

Then in CyberPanel:
- Security → ModSecurity → enable per website
- restart OpenLiteSpeed

5. Validate and start services

```bash
sudo bash scripts/enable_services.sh
```

6. Verify alert pipeline

```bash
sudo bash scripts/verify_pipeline.sh
```

## Telegram Chat ID Helper

```bash
bash scripts/get_telegram_chat_id.sh <BOT_TOKEN>
```

## Live Operations

```bash
sudo tail -f /var/log/snort/alert.log
sudo journalctl -u snort-watcher -f
sudo ufw status verbose
```

## Notes

- This design follows your CyberPanel/OpenLiteSpeed setup from the shared plan (not nginx mirroring).
- Snort covers network-level/transport detections; ModSecurity handles decrypted HTTPS payload attacks.
- Watcher is intentionally fail-open: if email/telegram fails, IDS continues running.
