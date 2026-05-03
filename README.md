# STS — Semantic Traffic Sanitizer
### AI-Powered HTTP Security Proxy · UTS 41909 Capstone

> An application-layer security gateway that sits in front of any web server, inspects every HTTP request in real time using an LLM, blocks or sanitises malicious payloads, and displays live threat intelligence on a SOC-grade dashboard.

---

## Table of Contents
1. [What It Does](#what-it-does)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [API Keys & Secrets](#api-keys--secrets)
5. [Configuration](#configuration)
6. [Detection Modes](#detection-modes)
7. [Deploying for a Real Company](#deploying-for-a-real-company)
8. [Project Structure](#project-structure)
9. [Dashboard Features](#dashboard-features)
10. [Attack Coverage](#attack-coverage)
11. [Benchmarking](#benchmarking)

---

## What It Does

STS intercepts every HTTP request destined for a web application. For each user-supplied input field it:

1. Sends the value to **Groq Llama 3.3 70B** (primary AI engine) for semantic analysis
2. Falls back to **Gemini 2.0 Flash** if Groq is rate-limited
3. Falls back to **rule-based pattern matching** if both APIs are unavailable
4. Takes action based on risk level and the configured mode:
   - **Block** — returns an immediate 403 with attack details
   - **Sanitize** — strips the malicious fragment and forwards the clean request
   - **Allow** — passes the request through unchanged
5. Enriches every malicious event with a **real CVE ID**, **CVSS score**, and **MITRE ATT&CK technique**, then stores it in SQLite
6. Streams everything live to the **SOC dashboard**

---

## Architecture

```
Browser / curl
      │
      ▼ HTTP (port 8080)
┌─────────────────────────────────┐
│   mitmproxy + sts_proxy.py      │  ← intercepts requests
│                                 │
│  ┌──────────┐ ┌───────────────┐ │
│  │ LLM      │ │ Rule-based    │ │
│  │ Engine   │ │ Fallback      │ │
│  │ (Groq /  │ │ (offline)     │ │
│  │  Gemini) │ └───────────────┘ │
│  └──────────┘                   │
│  ┌──────────────────────────────┐│
│  │ CVE Intel + MITRE ATT&CK    ││
│  └──────────────────────────────┘│
│  ┌──────────────────────────────┐│
│  │ SQLite (data/sts.db)        ││
│  └──────────────────────────────┘│
└─────────────────────────────────┘
      │ (clean request forwarded)
      ▼ HTTP (port 8000)
┌─────────────────┐
│  Target Web App │  ← your real app goes here
└─────────────────┘

┌─────────────────────────────────┐
│  Flask Dashboard (port 3000)    │  ← SOC interface
│  Chart.js  Bootstrap  SQLite    │
└─────────────────────────────────┘
```

**Why mitmproxy?** It operates as a transparent HTTP proxy, meaning you do not touch a single line of the target application's code. The app never knows STS exists.

---

## Quick Start

### Prerequisites
```bash
pip install mitmproxy flask requests python-dotenv
```

### 1. Clone / copy the STS folder
```bash
cd ~/Desktop/sts
```

### 2. Add your API keys
```bash
# Create a .env file (never commit this)
echo "GROQ_API_KEY=your_groq_key_here"   >> .env
echo "GEMINI_API_KEY=your_gemini_key_here" >> .env
```
Get a free Groq key at: https://console.groq.com  
Get a free Gemini key at: https://aistudio.google.com

### 3. Start everything
```bash
bash start_all.sh
```

This starts:
- **VulnBank demo server** → http://127.0.0.1:8000
- **STS Proxy** → 127.0.0.1:8080 (configure your browser/app to use this)
- **SOC Dashboard** → http://127.0.0.1:3000

### 4. Open the proxied browser (macOS)
```bash
bash open_browser.sh
```
This launches Chrome with the proxy configured and localhost bypass disabled.

### 5. Fire a test attack
```bash
curl -x http://127.0.0.1:8080 "http://127.0.0.1:8000/search?q=' OR 1=1--"
```
Then open the dashboard and watch it appear in real time.

---

## API Keys & Secrets

| Secret | Where stored | How used |
|--------|-------------|----------|
| `GROQ_API_KEY` | `sts/.env` | Loaded at startup by `start_all.sh` via `source .env` |
| `GEMINI_API_KEY` | `sts/.env` | Same — fallback engine |

**The `.env` file is local only.** It is never sent anywhere, never written into code, and should never be committed to git. Add `.env` to your `.gitignore`.

The proxy reads keys from environment variables at runtime:
```python
groq_key = os.environ.get("GROQ_API_KEY", "")
```

If both keys are missing, STS still works — it falls back to offline rule-based detection automatically.

---

## Configuration

Edit `config.json` to change any setting. Changes to mode take effect instantly (no restart needed). Port changes require a restart.

```json
{
  "proxy":     { "port": 8080,  "target_host": "127.0.0.1", "target_port": 8000 },
  "dashboard": { "port": 3000 },
  "server":    { "port": 8000 },
  "mode":      "strict",
  "ai": {
    "primary":           "groq",
    "secondary":         "gemini",
    "fallback":          "rules",
    "cache_size":        512,
    "rate_limit_per_min": 12
  }
}
```

| Field | Description |
|-------|-------------|
| `proxy.port` | Port mitmproxy listens on |
| `proxy.target_host/port` | Where to forward clean requests |
| `mode` | Detection mode — see below |
| `ai.cache_size` | LRU cache entries (identical payloads skip the API) |

---

## Detection Modes

Switch modes live by clicking the badge on the dashboard, or edit `config.json`:

| Mode | Critical/High | Medium | Low | Use case |
|------|--------------|--------|-----|----------|
| `detect` | Log only | Log only | Log only | Audit / visibility — zero disruption |
| `strict` | **Block 403** | Sanitize | Allow | Production — recommended |
| `paranoid` | **Block 403** | **Block 403** | Allow | High-security environments |

---

## Deploying for a Real Company

Deploying STS in front of a real application requires **three changes** only:

### Step 1 — Point the proxy at the real server

Edit `config.json`:
```json
"proxy": {
  "target_host": "192.168.1.50",
  "target_port": 80
}
```
Replace `192.168.1.50:80` with the actual web server's IP and port.

### Step 2 — Route traffic through the proxy

**Option A — Browser/client proxy setting**  
Tell users (or the corporate browser policy) to use `http://sts-server-ip:8080` as their HTTP proxy.

**Option B — Transparent proxy (network-level)**  
On a Linux gateway, add an iptables rule to redirect port 80 traffic through mitmproxy:
```bash
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
mitmdump -s proxy/sts_proxy.py --mode transparent --listen-port 8080
```
The application needs zero changes. Users notice nothing.

**Option C — Reverse proxy (public-facing apps)**  
Put Nginx in front, proxy to STS, STS proxies to the app:
```
Internet → Nginx (443 SSL) → STS (8080) → App (8000)
```

### Step 3 — Secure the API keys

For a company deployment, use environment variables injected by the server rather than a `.env` file:
```bash
# On Linux server, add to /etc/environment or systemd service file:
GROQ_API_KEY=gsk_company_key_here
GEMINI_API_KEY=AIza_company_key_here
```

### Step 4 — Keep the dashboard private

The dashboard (port 3000) should not be public. Restrict it:
```bash
# Only allow internal network
ufw allow from 10.0.0.0/8 to any port 3000
ufw deny 3000
```

### Full production stack example
```
[Internet]
     │ HTTPS
     ▼
[Nginx — SSL termination]
     │ HTTP
     ▼
[STS Proxy :8080] ──── logs → [SQLite]
     │ HTTP (clean only)         │
     ▼                           ▼
[Company Web App :8000]   [SOC Dashboard :3000]
                               (internal only)
```

---

## Project Structure

```
sts/
├── config.json          ← All settings. Edit this.
├── .env                 ← API keys. Never commit.
├── start_all.sh         ← One-command launcher
├── open_browser.sh      ← Launch Chrome via proxy (macOS)
├── benchmark.py         ← Detection accuracy benchmarking
│
├── proxy/
│   ├── sts_proxy.py     ← mitmproxy addon (main interception logic)
│   ├── llm_engine.py    ← Groq → Gemini → Rule-based detection
│   ├── cve_intel.py     ← CVE database + MITRE ATT&CK mappings
│   └── db.py            ← SQLite schema + insert helpers
│
├── dashboard/
│   ├── app.py           ← Flask API server
│   ├── templates/
│   │   └── dashboard.html  ← SOC UI (Chart.js + Bootstrap)
│   └── static/
│       ├── css/bootstrap.min.css
│       └── js/chart.umd.min.js
│
├── server/              ← VulnBank demo target (for testing)
│   ├── app.py
│   └── templates/
│
├── data/
│   └── sts.db           ← SQLite event database
│
└── logs/
    ├── proxy.log
    ├── dashboard.log
    └── server.log
```

---

## Dashboard Features

| Tab | What you see |
|-----|-------------|
| **Live Monitor** | 12 stat cards, 5 live charts, security score ring |
| **Event Log** | Filterable table with attack badges, search by IP/URL/field, modal with full CVE + payload details |
| **Threat Intel** | CVE severity breakdown, CVSS bar chart, live CVE match feed |
| **Threat Model** | STRIDE analysis, MITRE ATT&CK coverage matrix, decision policy |

**Security Score** (0–100): calculated from attack ratio and critical event count. Updates every 3 seconds.

**Mode badge**: click it on the dashboard to cycle between Detect → Strict → Paranoid instantly.

---

## Attack Coverage

| Attack Type | Example Payload | Risk | MITRE |
|-------------|----------------|------|-------|
| SQL Injection | `' OR 1=1--` | High | T1190 |
| XSS | `<script>alert(1)</script>` | Medium | T1059.007 |
| Command Injection | `; whoami` | Critical | T1059.004 |
| Path Traversal | `../../etc/passwd` | High | T1083 |
| SSRF | `http://169.254.169.254/` | High | T1090.002 |
| LDAP Injection | `)(cn=*` | Medium | T1078 |
| NoSQL Injection | `{"$gt":""}` | High | T1190 |

---

## Benchmarking

Run the benchmark suite to measure detection accuracy:

```bash
python3 benchmark.py
```

Output includes:
- Detection rate across 18 malicious payloads
- False positive rate across 12 benign inputs
- P95 latency per engine (Groq / Gemini / Rule-based)
- Per-attack-type breakdown
- Letter grade (A–D)
- JSON report saved to `/tmp/sts_benchmark_report.json`

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Proxy engine | mitmproxy 10+ |
| AI — Primary | Groq API (Llama 3.3 70B) |
| AI — Secondary | Google Gemini 2.0 Flash |
| AI — Fallback | Rule-based pattern matching (offline) |
| Database | SQLite 3 |
| Dashboard server | Flask 3 |
| Dashboard UI | Bootstrap 5 + Chart.js 4 |
| CVE intelligence | Mapped to NVD database entries |
| Threat framework | MITRE ATT&CK |

---

*STS — Semantic Traffic Sanitizer · Built for UTS 41909 · 2025*
