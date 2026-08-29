#!/usr/bin/env -S python3 -u
import hashlib
import json
import os
import sqlite3
import sys
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import OllamaLLM
import paramiko
import requests

# ================================
# CONFIGURATION (Loaded from Environment)
# ================================
WAZUH_VM_IP = os.getenv("WAZUH_VM_IP", "192.168.80.128")
SSH_USER = os.getenv("SSH_USER")
SSH_PASS = os.getenv("SSH_PASS")
ALERTS_PATH = os.getenv("ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
MIN_RULE_LEVEL = int(os.getenv("MIN_RULE_LEVEL", 7))

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Credential checks
if not SSH_USER or not SSH_PASS:
    sys.exit(
        "[-] Error: SSH_USER or SSH_PASS not provided. Run via: op run"
        " --env-file=local.env -- python3 local_ai_soc.py"
    )


# ================================
# 1. IDEMPOTENCY ENGINE (SQLite)
# ================================
def init_db():
    """Initializes a local SQLite database to record processed alert hashes."""
    conn = sqlite3.connect("processed_alerts.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyzed_events (
            event_hash TEXT PRIMARY KEY,
            timestamp TEXT,
            rule_id TEXT
        )
    """)
    conn.commit()
    conn.close()


def is_event_processed(event_hash):
    """Checks if the log event has already been analyzed by Ollama."""
    conn = sqlite3.connect("processed_alerts.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM analyzed_events WHERE event_hash = ?", (event_hash,)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


def mark_event_processed(event_hash, timestamp, rule_id):
    """Saves the processed log hash so it is never analyzed twice."""
    conn = sqlite3.connect("processed_alerts.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO analyzed_events VALUES (?, ?, ?)",
        (event_hash, timestamp, rule_id),
    )
    conn.commit()
    conn.close()


# ================================
# 2. TELEGRAM ALERT DISPATCHER
# ================================
def send_telegram_alert(summary, ai_report):
    """Sends structured alert telemetry and AI report to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(
            "[*] Telegram credentials missing in environment. Skipping"
            " notification.",
            flush=True,
        )
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    message = (
        f"🚨 *Wazuh Alert Detected (Level {summary['rule_level']})*\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"• *Host:* `{summary['agent_name']}` ({summary['agent_ip']})\n"
        f"• *Rule ID:* `{summary['rule_id']}`\n"
        f"• *Description:* {summary['rule_description']}\n\n"
        f"🤖 *AI SOC ANALYST REPORT:*\n"
        f"{ai_report}"
    )

    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
    }

    try:
        resp = requests.post(url, json=payload, timeout=8)
        if resp.status_code != 200:
            # Fallback if markdown parsing fails due to special characters in LLM response
            payload.pop("parse_mode", None)
            retry_resp = requests.post(url, json=payload, timeout=8)
            if retry_resp.status_code != 200:
                print(
                    f"[-] Telegram API Error ({resp.status_code}): {resp.text}",
                    flush=True,
                )
            else:
                print(
                    "[+] Telegram alert dispatched (plain text fallback).",
                    flush=True,
                )
        else:
            print("[+] Telegram alert dispatched successfully!", flush=True)
    except Exception as e:
        print(f"[-] Failed to send Telegram alert: {e}", flush=True)


# ================================
# 3. LOCAL AI SOC ANALYST
# ================================
def run_langchain_analyst(alert_data):
    """Sends event telemetry to Ollama via local SSH tunnel on localhost:11434."""
    llm = OllamaLLM(model="llama3.2")

    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            (
                "You are an expert AI SOC Analyst monitoring a local laboratory"
                " network in real-time.\n"
                "Analyze the provided structured Wazuh security alert and"
                " provide a concise report:\n\n"
                "1. **Threat Assessment**: Briefly explain what occurred and"
                " its severity.\n"
                "2. **MITRE ATT&CK Mapping**: Map the activity to techniques if"
                " applicable.\n"
                "3. **Remediation Commands**: Provide exact bash/CLI commands"
                " for the admin to investigate or mitigate."
            ),
        ),
        ("user", "Live Security Alert Telemetry:\n\n{event}"),
    ])

    chain = prompt | llm
    return chain.invoke({"event": json.dumps(alert_data, indent=2)})


# ================================
# 4. REAL-TIME EVENT STREAM TAILER
# ================================
def tail_wazuh_alerts():
    """Establishes an SSH stream to 'tail -f' alerts.json in real time."""
    init_db()

    print(
        f"[+] Connecting to Wazuh Manager VM ({WAZUH_VM_IP})...", flush=True
    )
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            WAZUH_VM_IP, username=SSH_USER, password=SSH_PASS, timeout=10
        )
    except Exception as e:
        print(f"[-] SSH Connection failed: {e}", flush=True)
        sys.exit(1)

    tail_cmd = f"tail -f -n 0 {ALERTS_PATH}"
    stdin, stdout, stderr = ssh.exec_command(tail_cmd, get_pty=True)

    print(
        f"[+] Connected! Monitoring {ALERTS_PATH} for new events (Rule Level >="
        f" {MIN_RULE_LEVEL})...\n",
        flush=True,
    )

    while not stdout.channel.exit_status_ready():
        line = stdout.readline()
        if not line or not line.strip():
            continue

        try:
            alert = json.loads(line)
            rule_level = alert.get("rule", {}).get("level", 0)

            # Noise Filter
            if rule_level < MIN_RULE_LEVEL:
                continue

            # Idempotency Check
            alert_id = alert.get("id")
            event_hash = (
                str(alert_id)
                if alert_id
                else hashlib.sha256(line.encode("utf-8")).hexdigest()
            )

            if is_event_processed(event_hash):
                print(
                    f"[*] [IDEMPOTENCY] Event {event_hash} already analyzed."
                    " Skipping...",
                    flush=True,
                )
                continue

            # Extract Minimal Context Payload
            rule_data = alert.get("rule", {})
            agent_data = alert.get("agent", {})

            summary = {
                "alert_id": alert_id,
                "timestamp": alert.get("timestamp"),
                "agent_name": agent_data.get("name"),
                "agent_ip": agent_data.get("ip"),
                "rule_id": rule_data.get("id"),
                "rule_description": rule_data.get("description"),
                "rule_level": rule_level,
                "mitre_technique": rule_data.get("mitre", {}).get("technique"),
                "raw_log": alert.get("full_log", alert.get("message", "")),
            }

            print(
                f"⚡ [EVENT DETECTED] Agent: '{summary['agent_name']}' | Rule"
                f" {summary['rule_id']} (Level {rule_level})",
                flush=True,
            )
            print(
                f"    Description: {summary['rule_description']}", flush=True
            )
            print(f"[+] Dispatching to Ollama (llama3.2)...", flush=True)

            # LLM Analysis
            report = run_langchain_analyst(summary)

            print("\n" + "=" * 25 + " LOCAL AI SOC REPORT " + "=" * 25)
            print(report)
            print("=" * 73 + "\n", flush=True)

            # Dispatch to Telegram
            send_telegram_alert(summary, report)

            # Persist Event
            mark_event_processed(
                event_hash,
                alert.get("timestamp", ""),
                str(rule_data.get("id", "")),
            )

        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[-] Processing Error: {e}", flush=True)


if __name__ == "__main__":
    try:
        tail_wazuh_alerts()
    except KeyboardInterrupt:
        print("\n[+] AI SOC Agent shut down gracefully.", flush=True)
