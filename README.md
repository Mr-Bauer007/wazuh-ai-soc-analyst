# Wazuh AI SOC Analyst

A lightweight, automated Security Operations Center (SOC) agent that streams real-time telemetry from a Wazuh SIEM manager, evaluates high-severity alerts using an LLM (Llama 3.2 via Ollama), and dispatches structured incident triage reports directly to Telegram.

## Architecture

```text
┌────────────────────────────────────────────────────────┐
│ VMware Homelab                                         │
│  ├── Wazuh Manager (Ubuntu) -> /alerts.json            │
│  └── Target VM (Vulnerable Linux Endpoint)             │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼ (SSH Streaming tail -f)
┌────────────────────────────────────────────────────────┐
│ Local Host / Agent Runner                              │
│  ├── agent.py (Paramiko + LangChain Engine)            │
│  ├── SQLite (Idempotency deduplication engine)         │
│  └── 1Password CLI (Secret Reference Injection)        │
└───────────────┬───────────────────────────────┬────────┘
                │                               │
                ▼ (Local Port Forward)          ▼ (HTTPS POST)
┌───────────────────────────────┐ ┌───────────────────────────────┐
│ Cloud GPU/CPU Instance        │ │ Telegram Bot API              │
│ └── Ollama Server (Llama 3.2) │ │ └── Incident Alert Channel    │
└───────────────────────────────┘ └───────────────────────────────┘
Features
Real-Time Log Streaming: Connects to the Wazuh Manager via SSH and streams newly written alert entries.
 
Rule Severity Filtering: Bypasses operational noise by filtering on high-severity thresholds (Rule Level >= 7).

Idempotency Engine: Uses SQLite to store alert hashes, preventing duplicate processing and redundant token usage.

Offloaded LLM Inference: Routes prompt chains to an Ollama server over an encrypted SSH local port forward.

Zero-Plaintext Secret Storage: Injects all credentials directly into process memory via the 1Password CLI (op).

Automated Dispatch: Formats MITRE ATT&CK mappings and remediation CLI commands for instant delivery to Telegram.

## Setup & Installation

1. Clone & configure dependencies

```xml
git clone https://github.com/yourusername/wazuh-ai-soc-analyst.git
cd wazuh-ai-soc-analyst
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Configure 1Password & environment variables

Copy the example file and update the `op://` reference paths to match your 1Password vault.

```xml
cp local.env.example local.env
# Edit local.env and replace placeholders with your op:// secrets
```

3. Establish the Ollama inference tunnel

Forward local port `11434` to your remote cloud instance (replace placeholders):

```xml
ssh -f -N -L 11434:localhost:11434 <remote-user>@<remote-ip>
```

4. Run the agent

Execute the agent using the 1Password CLI wrapper to inject secrets into process memory:

```xml
op run --env-file=local.env -- python src/agent.py
```

Notes:
- Replace `yourusername`, `<remote-user>`, and `<remote-ip>` with your repository and host details.

