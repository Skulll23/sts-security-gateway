"""
Semantic Traffic Sanitizer — mitmproxy addon
Intercepts HTTP requests, analyses every input field with an LLM,
then BLOCKS (Critical/High), SANITIZES (Medium), or ALLOWS (Low/Benign).
All decisions are logged to SQLite for the live dashboard.
"""

import os, sys, json, datetime, uuid, time
from collections import defaultdict

# ── Load .env ──────────────────────────────────────────────────────────────────
_here = os.path.dirname(os.path.abspath(__file__))
_env_candidates = [
    os.path.join(_here, "..", ".env"),
    os.path.expanduser("~/Desktop/sts/.env"),
    "/sessions/sharp-gifted-goldberg/mnt/Desktop/sts/.env",
]
for _env_path in _env_candidates:
    if os.path.exists(_env_path):
        for line in open(_env_path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
        break

sys.path.insert(0, _here)
from db import init_db, insert_event
from llm_engine import analyze
from cve_intel import get_cve, get_technique

from mitmproxy import http
from urllib.parse import parse_qs, urlencode, urlparse, parse_qsl, urlunparse

_sts_root = os.path.abspath(os.path.join(_here, ".."))
init_db()

# ── IP Velocity Tracker ────────────────────────────────────────────────────────
# Detects scanning/brute-force: >5 attacks from same IP within 60 seconds
_ip_events: dict = defaultdict(list)   # ip → [timestamp, ...]
_VELOCITY_WINDOW = 60   # seconds
_VELOCITY_THRESHOLD = 5  # attacks in window = scanning

def _record_attack_ip(ip: str) -> bool:
    """Record an attack from this IP. Returns True if IP is scanning."""
    now = time.time()
    _ip_events[ip] = [t for t in _ip_events[ip] if now - t < _VELOCITY_WINDOW]
    _ip_events[ip].append(now)
    return len(_ip_events[ip]) >= _VELOCITY_THRESHOLD

def _get_ip_attack_count(ip: str) -> int:
    now = time.time()
    return len([t for t in _ip_events.get(ip, []) if now - t < _VELOCITY_WINDOW])


# ── Professional 403 Block Page ────────────────────────────────────────────────
def _block_page(attack_type: str, risk: str, confidence: int,
                explanation: str, field: str, original: str,
                cve_id: str = "N/A", cvss: float = 0.0,
                mitre_id: str = "", client_ip: str = "",
                scanning: bool = False) -> str:

    req_id = str(uuid.uuid4()).upper()[:16]
    ts     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    risk_colors = {
        "Critical": ("#ff4d6d", "#ff4d6d22", "🔴"),
        "High":     ("#ff8c42", "#ff8c4222", "🟠"),
        "Medium":   ("#ffd166", "#ffd16622", "🟡"),
        "Low":      ("#06d6a0", "#06d6a022", "🟢"),
    }
    color, bg, dot = risk_colors.get(risk, ("#ff4d6d", "#ff4d6d22", "🔴"))

    attack_icons = {
        "SQL Injection": "🗃️", "XSS": "📜", "Command Injection": "💻",
        "Path Traversal": "📂", "SSRF": "🌐", "LDAP Injection": "📋",
        "NoSQL Injection": "📦",
    }
    icon = attack_icons.get(attack_type, "⚠️")

    scanning_banner = ""
    if scanning:
        scanning_banner = f"""
        <div class="scan-warn">
          ⚡ SCANNING DETECTED — Multiple attacks from {client_ip} within 60 seconds.
          This IP has been flagged for enhanced monitoring.
        </div>"""

    payload_display = original[:200] + ("..." if len(original) > 200 else "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Request Blocked — STS Security Gateway</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #07090f;
      color: #c9d1e0;
      font-family: 'Inter', -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 2rem 1rem;
      position: relative;
      overflow: hidden;
    }}
    /* Animated background grid */
    body::before {{
      content: '';
      position: fixed; inset: 0;
      background-image:
        linear-gradient(rgba(255,77,109,.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,77,109,.04) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
    }}
    /* Radial glow behind card */
    body::after {{
      content: '';
      position: fixed;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      width: 600px; height: 600px;
      background: radial-gradient(circle, {bg} 0%, transparent 70%);
      pointer-events: none;
    }}

    /* ── Top bar ── */
    .topbar {{
      position: fixed; top: 0; left: 0; right: 0;
      height: 48px;
      background: rgba(10,12,20,.95);
      border-bottom: 1px solid #1a1e2e;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 1.5rem;
      backdrop-filter: blur(12px);
      z-index: 10;
    }}
    .topbar-logo {{ display: flex; align-items: center; gap: .5rem; font-size: .85rem; font-weight: 700; }}
    .logo-box {{
      width: 26px; height: 26px;
      background: linear-gradient(135deg, #3b82f6, #8b5cf6);
      border-radius: 5px;
      display: flex; align-items: center; justify-content: center;
      font-size: .7rem;
    }}
    .topbar-ref {{ font-size: .72rem; color: #4a5270; font-family: monospace; }}

    /* ── Main card ── */
    .card {{
      background: rgba(13,15,25,.97);
      border: 1px solid #1a1e2e;
      border-top: 3px solid {color};
      border-radius: 16px;
      padding: 2.5rem 2.2rem;
      max-width: 580px;
      width: 100%;
      position: relative;
      z-index: 2;
      box-shadow: 0 25px 60px rgba(0,0,0,.6), 0 0 0 1px #ffffff08;
      margin-top: 48px;
    }}

    /* Scanning warning banner */
    .scan-warn {{
      background: rgba(255,77,109,.1);
      border: 1px solid rgba(255,77,109,.3);
      border-radius: 8px;
      padding: .7rem 1rem;
      font-size: .78rem;
      color: #ff4d6d;
      margin-bottom: 1.5rem;
      font-weight: 500;
    }}

    /* ── Shield icon ── */
    .shield-wrap {{
      display: flex; align-items: center; gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .shield-icon {{
      font-size: 2.4rem;
      animation: shield-pulse 2s infinite;
    }}
    @keyframes shield-pulse {{
      0%, 100% {{ filter: drop-shadow(0 0 4px {color}); }}
      50%       {{ filter: drop-shadow(0 0 14px {color}); }}
    }}
    .shield-text h1 {{
      font-size: 1.25rem; font-weight: 700; color: {color};
      letter-spacing: -.3px;
    }}
    .shield-text p {{
      font-size: .8rem; color: #5a6280; margin-top: .15rem;
    }}

    /* ── Attack badge ── */
    .attack-badge {{
      display: inline-flex; align-items: center; gap: .5rem;
      background: {bg};
      border: 1px solid {color}55;
      color: {color};
      padding: .4rem 1rem;
      border-radius: 20px;
      font-size: .85rem; font-weight: 600;
      margin-bottom: 1.5rem;
    }}

    /* ── Detail rows ── */
    .details {{
      background: rgba(255,255,255,.02);
      border: 1px solid #1a1e2e;
      border-radius: 10px;
      overflow: hidden;
      margin-bottom: 1.2rem;
    }}
    .detail-row {{
      display: flex; justify-content: space-between; align-items: center;
      padding: .65rem 1rem;
      border-bottom: 1px solid #1a1e2e;
      font-size: .82rem;
    }}
    .detail-row:last-child {{ border-bottom: none; }}
    .dl {{ color: #4a5270; font-weight: 500; }}
    .dv {{ color: #c9d1e0; font-weight: 600; text-align: right; max-width: 320px; word-break: break-all; }}
    .risk-pill {{
      display: inline-block;
      padding: .15em .65em; border-radius: 4px;
      font-size: .75rem; font-weight: 700;
      background: {bg}; color: {color};
      border: 1px solid {color}55;
    }}
    .cve-pill {{
      display: inline-block;
      padding: .15em .65em; border-radius: 4px;
      font-size: .72rem; font-weight: 600;
      background: rgba(6,182,212,.1); color: #06b6d4;
      border: 1px solid rgba(6,182,212,.3);
      font-family: monospace;
    }}

    /* ── Explanation ── */
    .explanation {{
      background: rgba(255,255,255,.025);
      border-left: 3px solid {color};
      border-radius: 0 8px 8px 0;
      padding: .85rem 1rem;
      font-size: .82rem;
      line-height: 1.6;
      color: #a0aab8;
      margin-bottom: 1.2rem;
    }}

    /* ── Payload box ── */
    .payload-label {{
      font-size: .67rem; font-weight: 600;
      color: #4a5270; text-transform: uppercase;
      letter-spacing: .8px; margin-bottom: .4rem;
    }}
    .payload {{
      background: #070910;
      border: 1px solid #1a1e2e;
      border-radius: 8px;
      padding: .75rem 1rem;
      font-family: 'JetBrains Mono', 'Fira Code', monospace;
      font-size: .75rem;
      color: #ff8c8c;
      word-break: break-all;
      line-height: 1.5;
      margin-bottom: 1.5rem;
    }}

    /* ── Actions ── */
    .actions {{ display: flex; gap: .75rem; margin-bottom: 1.5rem; }}
    .btn-back {{
      display: inline-flex; align-items: center; gap: .4rem;
      background: #1a1e2e; color: #c9d1e0;
      border: 1px solid #2a2e45;
      padding: .55rem 1.2rem; border-radius: 8px;
      font-size: .82rem; font-weight: 500;
      text-decoration: none; cursor: pointer;
      transition: background .15s, border-color .15s;
    }}
    .btn-back:hover {{ background: #252a3e; border-color: #3a3e55; }}

    /* ── Footer ── */
    .card-footer {{
      border-top: 1px solid #1a1e2e;
      padding-top: 1rem;
      font-size: .72rem; color: #3a4060;
      display: flex; justify-content: space-between; align-items: center;
    }}
    .ref-id {{ font-family: monospace; color: #4a5270; font-size: .7rem; }}
  </style>
</head>
<body>

<div class="topbar">
  <div class="topbar-logo">
    <div class="logo-box">🛡</div>
    <span>STS <span style="color:#4a5270;font-weight:400">Security Gateway</span></span>
  </div>
  <div class="topbar-ref">REF: {req_id}</div>
</div>

<div class="card">
  {scanning_banner}

  <div class="shield-wrap">
    <div class="shield-icon">🛡️</div>
    <div class="shield-text">
      <h1>Access Denied</h1>
      <p>Your request was blocked by the STS Security Gateway</p>
    </div>
  </div>

  <div class="attack-badge">{icon} {attack_type} Detected</div>

  <div class="details">
    <div class="detail-row">
      <span class="dl">Risk Level</span>
      <span class="dv"><span class="risk-pill">{dot} {risk}</span></span>
    </div>
    <div class="detail-row">
      <span class="dl">Confidence</span>
      <span class="dv">{confidence}%</span>
    </div>
    <div class="detail-row">
      <span class="dl">Affected Field</span>
      <span class="dv" style="font-family:monospace">{field}</span>
    </div>
    {'<div class="detail-row"><span class="dl">CVE Reference</span><span class="dv"><span class="cve-pill">' + cve_id + '</span>' + (f' &nbsp; CVSS {cvss}' if cvss else '') + '</span></div>' if cve_id and cve_id != 'N/A' else ''}
    {'<div class="detail-row"><span class="dl">MITRE ATT&CK</span><span class="dv" style="font-family:monospace;color:#8b5cf6">' + mitre_id + '</span></div>' if mitre_id else ''}
    <div class="detail-row">
      <span class="dl">Client IP</span>
      <span class="dv" style="font-family:monospace">{client_ip or "unknown"}</span>
    </div>
    <div class="detail-row">
      <span class="dl">Timestamp</span>
      <span class="dv">{ts}</span>
    </div>
  </div>

  <div class="explanation">💡 {explanation}</div>

  <div class="payload-label">Blocked Payload</div>
  <div class="payload">{payload_display}</div>

  <div class="actions">
    <a href="javascript:history.back()" class="btn-back">← Go Back</a>
  </div>

  <div class="card-footer">
    <span>If you believe this is an error, contact your security administrator with the reference ID above.</span>
    <span class="ref-id">{req_id}</span>
  </div>
</div>

</body>
</html>"""


def _log(event: dict):
    log_file = os.path.join(_sts_root, "logs", "events.json")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, "a") as f:
        f.write(json.dumps(event) + "\n")


# Fields that are never user-controlled input — skip analysis entirely
_SKIP_FIELDS = {
    "_", "csrf", "csrftoken", "csrf_token", "_token", "authenticity_token",
    "__RequestVerificationToken", "nonce", "state", "redirect", "next",
    "callback", "format", "v", "ver", "version", "_method",
}

def _process_fields(fields: dict) -> tuple[dict, list[dict]]:
    """Analyse each field. Returns (modified_fields, list_of_event_dicts)."""
    events   = []
    modified = dict(fields)
    for fname, values in fields.items():
        original = values[0] if values else ""
        if not original.strip():
            continue
        if fname.lower() in _SKIP_FIELDS:
            continue
        result, method = analyze(original, fname)
        event = {
            "timestamp":        str(datetime.datetime.now()),
            "field_name":       fname,
            "original_value":   original,
            "sanitized_value":  result["sanitized_text"],
            "attack_detected":  result["malicious"],
            "attack_type":      result["attack_type"],
            "confidence":       result["confidence"],
            "risk_level":       result["risk_level"],
            "action_taken":     result["action"],
            "explanation":      result["explanation"],
            "detection_method": method,
        }
        if result["malicious"] and result["action"] == "Sanitize":
            modified[fname] = [result["sanitized_text"]]

        # Attach CVE + MITRE intelligence for malicious events
        if result["malicious"]:
            cve  = get_cve(result["attack_type"])
            tech = get_technique(result["attack_type"])
            event.update({
                "cve_id":       cve["id"],
                "cvss_score":   cve["cvss"],
                "cve_severity": cve["severity"],
                "cve_desc":     cve["desc"],
                "mitre_id":     tech["id"],
                "mitre_name":   tech["name"],
            })

        events.append(event)
    return modified, events


def request(flow: http.HTTPFlow):
    url    = flow.request.pretty_url
    method = flow.request.method
    ip     = flow.client_conn.address[0] if flow.client_conn.address else "unknown"

    if "localhost:8000" not in url and "127.0.0.1:8000" not in url:
        return

    print(f"\n[STS] → {method} {url}")
    base_event      = {"client_ip": ip, "method": method, "url": url}
    analysed_fields = []

    # ── 1. URL query parameters ────────────────────────────────────────────────
    parsed = urlparse(url)
    if parsed.query:
        qparams    = dict(parse_qsl(parsed.query, keep_blank_values=True))
        flat       = {k: [v] for k, v in qparams.items()}
        modified_q, evts = _process_fields(flat)
        analysed_fields.extend(evts)

        blocked_evt = next((e for e in evts if e["action_taken"] == "Block"), None)
        if blocked_evt:
            scanning = _record_attack_ip(ip)
            _persist(base_event, evts)
            flow.response = http.Response.make(
                403,
                _block_page(
                    blocked_evt["attack_type"], blocked_evt["risk_level"],
                    blocked_evt["confidence"],   blocked_evt["explanation"],
                    blocked_evt["field_name"],   blocked_evt["original_value"],
                    cve_id=blocked_evt.get("cve_id", "N/A"),
                    cvss=blocked_evt.get("cvss_score", 0.0),
                    mitre_id=blocked_evt.get("mitre_id", ""),
                    client_ip=ip, scanning=scanning,
                ),
                {"Content-Type": "text/html; charset=utf-8"}
            )
            print(f"[STS] BLOCKED — {blocked_evt['attack_type']} "
                  f"({blocked_evt['risk_level']}, {blocked_evt['confidence']}%)"
                  f"{' [SCANNING]' if scanning else ''}")
            return

        if modified_q != flat:
            new_query = urlencode({k: v[0] for k, v in modified_q.items()})
            p = parsed._replace(query=new_query)
            flow.request.url = urlunparse(p)

    # ── 2. POST form body ──────────────────────────────────────────────────────
    ct = flow.request.headers.get("content-type", "")
    if method == "POST" and "application/x-www-form-urlencoded" in ct:
        body = flow.request.get_text()
        if body:
            fields     = parse_qs(body, keep_blank_values=True)
            modified_f, evts = _process_fields(fields)
            analysed_fields.extend(evts)

            blocked_evt = next((e for e in evts if e["action_taken"] == "Block"), None)
            if blocked_evt:
                scanning = _record_attack_ip(ip)
                _persist(base_event, evts)
                flow.response = http.Response.make(
                    403,
                    _block_page(
                        blocked_evt["attack_type"], blocked_evt["risk_level"],
                        blocked_evt["confidence"],   blocked_evt["explanation"],
                        blocked_evt["field_name"],   blocked_evt["original_value"],
                        cve_id=blocked_evt.get("cve_id", "N/A"),
                        cvss=blocked_evt.get("cvss_score", 0.0),
                        mitre_id=blocked_evt.get("mitre_id", ""),
                        client_ip=ip, scanning=scanning,
                    ),
                    {"Content-Type": "text/html; charset=utf-8"}
                )
                print(f"[STS] BLOCKED — {blocked_evt['attack_type']} ({blocked_evt['risk_level']})"
                      f"{' [SCANNING]' if scanning else ''}")
                return

            if modified_f != fields:
                flow.request.text = urlencode(modified_f, doseq=True)

    # ── 3. POST JSON body ──────────────────────────────────────────────────────
    elif method == "POST" and "application/json" in ct:
        try:
            data = json.loads(flow.request.get_text())
            flat = {k: [str(v)] for k, v in data.items() if isinstance(v, str)}
            modified_j, evts = _process_fields(flat)
            analysed_fields.extend(evts)

            blocked_evt = next((e for e in evts if e["action_taken"] == "Block"), None)
            if blocked_evt:
                scanning = _record_attack_ip(ip)
                _persist(base_event, evts)
                flow.response = http.Response.make(
                    403,
                    _block_page(
                        blocked_evt["attack_type"], blocked_evt["risk_level"],
                        blocked_evt["confidence"],   blocked_evt["explanation"],
                        blocked_evt["field_name"],   blocked_evt["original_value"],
                        cve_id=blocked_evt.get("cve_id", "N/A"),
                        cvss=blocked_evt.get("cvss_score", 0.0),
                        mitre_id=blocked_evt.get("mitre_id", ""),
                        client_ip=ip, scanning=scanning,
                    ),
                    {"Content-Type": "text/html; charset=utf-8"}
                )
                return

            if modified_j != flat:
                for k, v in modified_j.items():
                    data[k] = v[0]
                flow.request.text = json.dumps(data)
        except Exception:
            pass

    if analysed_fields:
        _persist(base_event, analysed_fields)


def _persist(base: dict, events: list):
    for evt in events:
        row = {**base, **evt}
        insert_event(row)
        _log(row)
