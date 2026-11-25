#!/usr/bin/env python3
import os
import re
import time
import smtplib
import socket
import subprocess
import threading
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict, deque
from ipaddress import ip_address

import requests


ENV_PATH = os.environ.get("WATCHER_ENV", "/opt/snort-alert/.env")


def load_dotenv(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


load_dotenv(ENV_PATH)


def get_env(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and (value is None or value == ""):
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value or ""


VPS_HOSTNAME = socket.gethostname()
VPS_IP = get_env("VPS_IP", "127.0.0.1")
ALERT_LOG = get_env("ALERT_LOG", "/var/log/snort/alert.log")
MODSEC_AUDIT_LOG = get_env("MODSEC_AUDIT_LOG", "/var/log/modsec_audit.log")
WATCH_MODSEC = get_env("WATCH_MODSEC", "true").lower() == "true"

SMTP_HOST = get_env("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(get_env("SMTP_PORT", "587"))
SMTP_USER = get_env("SMTP_USER", "")
SMTP_PASS = get_env("SMTP_PASS", "")
EMAIL_TO = [x.strip() for x in get_env("EMAIL_TO", "").split(",") if x.strip()]

TELEGRAM_TOKEN = get_env("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT = get_env("TELEGRAM_CHAT", "")
TELEGRAM_CHAT_IDS = [
    value.strip()
    for value in get_env("TELEGRAM_CHAT_IDS", TELEGRAM_CHAT).split(",")
    if value.strip()
]

AUTO_BLOCK_ENABLED = get_env("AUTO_BLOCK_ENABLED", "true").lower() == "true"
AUTO_BLOCK_PRIORITY = set(x.strip() for x in get_env("AUTO_BLOCK_PRIORITY", "1").split(",") if x.strip())
THROTTLE_SEC = int(get_env("THROTTLE_SEC", "120"))
BURST_LIMIT = int(get_env("BURST_LIMIT", "10"))
BURST_WINDOW = int(get_env("BURST_WINDOW", "60"))
BLOCK_PRIVATE_IPS = get_env("BLOCK_PRIVATE_IPS", "false").lower() == "true"
AUTO_BLOCK_EXCLUDE_IPS = {
    item.strip()
    for item in get_env("AUTO_BLOCK_EXCLUDE_IPS", "").split(",")
    if item.strip()
}

PRIORITY_LABEL = {
    "1": "🔴 CRITICAL",
    "2": "🟠 HIGH",
    "3": "🟡 MEDIUM",
    "4": "🔵 LOW",
}

throttle_map: dict[str, float] = {}
burst_tracker: defaultdict[str, deque] = defaultdict(deque)
blocked_ips: set[str] = set()


def is_public_ip(ip: str) -> bool:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return False
    return parsed.is_global


def should_block_ip(ip: str) -> bool:
    if ip in blocked_ips or ip in ("unknown", VPS_IP) or ip.startswith("127."):
        return False
    if ip in AUTO_BLOCK_EXCLUDE_IPS:
        return False
    if BLOCK_PRIVATE_IPS:
        return True
    return is_public_ip(ip)


def modsec_priority(severity: str) -> str:
    normalized = severity.strip().upper()
    if normalized in {"CRITICAL", "EMERGENCY", "ALERT"}:
        return "1"
    if normalized in {"ERROR", "HIGH"}:
        return "2"
    if normalized in {"WARNING", "NOTICE", "MEDIUM"}:
        return "3"
    return "4"


def parse_modsec_message(line: str) -> dict | None:
    if "Message:" not in line:
        return None

    msg_match = re.search(r'\[msg\s+"([^"]+)"\]', line)
    id_match = re.search(r'\[id\s+"([^"]+)"\]', line)
    severity_match = re.search(r'\[severity\s+"([^"]+)"\]', line)
    client_match = re.search(r'\[client\s+([^\]]+)\]', line)
    uri_match = re.search(r'\[uri\s+"([^"]+)"\]', line)

    if not msg_match:
        return None

    severity = severity_match.group(1) if severity_match else "NOTICE"
    src_ip = client_match.group(1).strip() if client_match else "unknown"
    uri = uri_match.group(1).strip() if uri_match else "-"
    rule_id = id_match.group(1).strip() if id_match else "modsec"

    return {
        "timestamp": datetime.now().strftime("%m/%d-%H:%M:%S.%f")[:-3],
        "sid": f"MODSEC:{rule_id}",
        "message": f"[HTTPS-WAF] {msg_match.group(1).strip()}",
        "priority": modsec_priority(severity),
        "classification": f"ModSecurity/{severity}",
        "proto": "HTTPS",
        "src_ip": src_ip,
        "src_port": "-",
        "dst_ip": VPS_IP,
        "dst_port": "443",
        "uri": uri,
    }


def notify_block(ip: str, reason: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_IDS:
        return
    text = (
        f"🚫 *IP AUTO-BLOCKED*\n"
        f"🖥 Host: `{VPS_HOSTNAME}`\n"
        f"🌍 IP: `{ip}`\n"
        f"📋 Reason: `{reason}`\n"
        f"🕐 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n\n"
        f"_To unblock:_ `ufw delete deny from {ip}`"
    )
    for chat_id in TELEGRAM_CHAT_IDS:
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception as exc:
            print(f"[NOTIFY BLOCK ERROR] chat={chat_id} {exc}")


def block_ip(ip: str, reason: str) -> None:
    if not should_block_ip(ip):
        return
    try:
        subprocess.run(
            ["ufw", "deny", "from", ip, "to", "any"],
            capture_output=True,
            check=True,
            text=True,
        )
        blocked_ips.add(ip)
        print(f"[BLOCKED] {ip} — {reason}")
        notify_block(ip, reason)
    except Exception as exc:
        print(f"[BLOCK ERROR] {ip}: {exc}")


def parse_alert(block: str) -> dict | None:
    lines = [line.strip() for line in block.strip().splitlines() if line.strip()]
    if not lines:
        return None

    first_line = lines[0]
    match = re.match(
        r"(\d{2}/\d{2}-[\d:.]+)\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]",
        first_line,
    )
    if not match:
        return None

    alert = {
        "timestamp": match.group(1),
        "sid": match.group(2),
        "message": match.group(3).strip(),
        "priority": "4",
        "classification": "unknown",
        "proto": "TCP",
        "src_ip": "unknown",
        "src_port": "-",
        "dst_ip": "unknown",
        "dst_port": "-",
    }

    for line in lines:
        priority_match = re.search(r"\[Priority:\s*(\d+)\]", line)
        if priority_match:
            alert["priority"] = priority_match.group(1)

        class_match = re.search(r"Classification:\s*(.+)", line)
        if class_match:
            alert["classification"] = class_match.group(1).strip()

        src_dst_match = re.search(r"([\d.]+):?(\d+)?\s*->\s*([\d.]+):?(\d+)?", line)
        if src_dst_match:
            alert["src_ip"] = src_dst_match.group(1)
            alert["src_port"] = src_dst_match.group(2) or "-"
            alert["dst_ip"] = src_dst_match.group(3)
            alert["dst_port"] = src_dst_match.group(4) or "-"

        for proto in ("TCP", "UDP", "ICMP"):
            if line.startswith(proto):
                alert["proto"] = proto

    return alert


def is_throttled(key: str) -> bool:
    now = time.time()
    last_sent = throttle_map.get(key, 0)
    if now - last_sent < THROTTLE_SEC:
        return True
    throttle_map[key] = now
    return False


def is_burst(src_ip: str) -> bool:
    now = time.time()
    queue = burst_tracker[src_ip]
    while queue and now - queue[0] > BURST_WINDOW:
        queue.popleft()
    queue.append(now)
    return len(queue) > BURST_LIMIT


def send_email(alert: dict) -> None:
    if not SMTP_USER or not SMTP_PASS or not EMAIL_TO:
        return

    priority_text = PRIORITY_LABEL.get(alert["priority"], "⚪ UNKNOWN")
    subject = f"[SNORT IDS] {priority_text} | {alert['message']} | {alert['src_ip']}"
    body = f"""
============================================================
  SNORT IDS ALERT — {VPS_HOSTNAME} ({VPS_IP})
============================================================

Time          : {alert['timestamp']}
Priority      : {priority_text}
Alert         : {alert['message']}
Classification: {alert['classification']}
SID           : {alert['sid']}
Protocol      : {alert['proto']}

Source        : {alert['src_ip']}:{alert['src_port']}
Destination   : {alert['dst_ip']}:{alert['dst_port']}

============================================================
RECOMMENDED ACTIONS:
  • Review:  tail -50 /var/log/snort/alert.log
  • Block:   ufw deny from {alert['src_ip']}
  • Unblock: ufw delete deny from {alert['src_ip']}
============================================================
"""

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = ", ".join(EMAIL_TO)
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_USER, EMAIL_TO, msg.as_string())
        print(f"[EMAIL] Sent: {alert['message']}")
    except Exception as exc:
        print(f"[EMAIL ERROR] {exc}")


def send_telegram(alert: dict) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_IDS:
        return

    priority_text = PRIORITY_LABEL.get(alert["priority"], "⚪ UNKNOWN")
    blocked_note = ""
    if AUTO_BLOCK_ENABLED and alert["priority"] in AUTO_BLOCK_PRIORITY:
        blocked_note = "\n🚫 *IP may be auto-blocked by UFW*"

    text = (
        f"🚨 *SNORT IDS ALERT*\n"
        f"🖥 `{VPS_HOSTNAME}` • `{VPS_IP}`\n\n"
        f"*{priority_text}*\n"
        f"📋 `{alert['message']}`\n\n"
        f"🕐 `{alert['timestamp']}`\n"
        f"📡 Proto: `{alert['proto']}`  SID: `{alert['sid']}`\n"
        f"🔖 `{alert['classification']}`\n\n"
        f"🌍 *From:* `{alert['src_ip']}:{alert['src_port']}`\n"
        f"🏠 *To:*   `{alert['dst_ip']}:{alert['dst_port']}`"
        f"{blocked_note}\n\n"
        f"_Manual block:_ `ufw deny from {alert['src_ip']}`"
    )

    for chat_id in TELEGRAM_CHAT_IDS:
        try:
            response = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10,
            )
            if response.status_code == 200:
                print(f"[TELEGRAM] Sent to {chat_id}: {alert['message']}")
            else:
                print(f"[TELEGRAM ERROR] chat={chat_id} {response.text}")
        except Exception as exc:
            print(f"[TELEGRAM ERROR] chat={chat_id} {exc}")


def dispatch(alert: dict) -> None:
    source_ip = alert.get("src_ip", "unknown")
    if is_throttled(alert["message"]):
        print(f"[THROTTLED] {alert['message']}")
        return
    if is_burst(source_ip):
        print(f"[BURST] {source_ip}")
        return

    if AUTO_BLOCK_ENABLED and alert["priority"] in AUTO_BLOCK_PRIORITY:
        block_ip(source_ip, alert["message"])

    send_email(alert)
    send_telegram(alert)


def watch_modsecurity() -> None:
    print(f"[WATCHER] Started — monitoring {MODSEC_AUDIT_LOG}")
    while not os.path.exists(MODSEC_AUDIT_LOG):
        print("[WATCHER] Waiting for ModSecurity audit log...")
        time.sleep(5)

    with open(MODSEC_AUDIT_LOG, "r", encoding="utf-8", errors="ignore") as file:
        current_inode = os.stat(MODSEC_AUDIT_LOG).st_ino

        while True:
            line = file.readline()
            if line:
                parsed = parse_modsec_message(line.strip())
                if parsed:
                    dispatch(parsed)
            else:
                time.sleep(0.5)
                try:
                    new_inode = os.stat(MODSEC_AUDIT_LOG).st_ino
                    if new_inode != current_inode:
                        print("[WATCHER] ModSecurity log rotated — reopening")
                        file.close()
                        file = open(MODSEC_AUDIT_LOG, "r", encoding="utf-8", errors="ignore")
                        current_inode = new_inode
                except Exception:
                    pass


def watch() -> None:
    print(f"[WATCHER] Started — monitoring {ALERT_LOG}")

    while not os.path.exists(ALERT_LOG):
        print("[WATCHER] Waiting for alert log...")
        time.sleep(5)

    with open(ALERT_LOG, "r", encoding="utf-8", errors="ignore") as file:
        buffer: list[str] = []
        current_inode = os.stat(ALERT_LOG).st_ino

        while True:
            line = file.readline()
            if line:
                if re.match(r"\d{2}/\d{2}-", line) and buffer:
                    parsed = parse_alert("\n".join(buffer))
                    if parsed:
                        dispatch(parsed)
                    buffer = []
                buffer.append(line.rstrip())
            else:
                if buffer:
                    parsed = parse_alert("\n".join(buffer))
                    if parsed:
                        dispatch(parsed)
                    buffer = []
                time.sleep(0.5)

                try:
                    new_inode = os.stat(ALERT_LOG).st_ino
                    if new_inode != current_inode:
                        print("[WATCHER] Log rotated — reopening")
                        file.close()
                        file = open(ALERT_LOG, "r", encoding="utf-8", errors="ignore")
                        current_inode = new_inode
                except Exception:
                    pass


if __name__ == "__main__":
    threads = [threading.Thread(target=watch, daemon=True)]
    if WATCH_MODSEC:
        threads.append(threading.Thread(target=watch_modsecurity, daemon=True))

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()
