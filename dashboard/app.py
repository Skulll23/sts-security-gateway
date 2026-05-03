from flask import Flask, render_template, jsonify, request, send_file
import sqlite3, os, json, io
from datetime import datetime, timedelta

app = Flask(__name__)
DB  = os.path.join(os.path.dirname(__file__), "..", "data", "sts.db")

# ── Config ─────────────────────────────────────────────────────────────────────
_cfg_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
def _load_cfg() -> dict:
    try:
        with open(_cfg_path) as f:
            return json.load(f)
    except Exception:
        return {}

def db():
    if not os.path.exists(DB):
        return None
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def _q(conn, sql, args=()):
    return conn.execute(sql, args).fetchone()[0]

# ── Pages ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("dashboard.html")

# ── Config API ─────────────────────────────────────────────────────────────────
@app.route("/api/config")
def get_config():
    cfg = _load_cfg()
    return jsonify({
        "mode":           cfg.get("mode", "strict"),
        "proxy_port":     (cfg.get("proxy") or {}).get("port", 8080),
        "dashboard_port": (cfg.get("dashboard") or {}).get("port", 3000),
        "server_port":    (cfg.get("server") or {}).get("port", 8000),
        "ai_primary":     (cfg.get("ai") or {}).get("primary", "groq"),
    })

@app.route("/api/config", methods=["POST"])
def set_config():
    data = request.get_json(force=True)
    if "mode" not in data:
        return jsonify({"error": "missing mode"}), 400
    mode = data["mode"].lower()
    if mode not in ("detect", "strict", "paranoid"):
        return jsonify({"error": "invalid mode"}), 400
    cfg = _load_cfg()
    cfg["mode"] = mode
    with open(_cfg_path, "w") as f:
        json.dump(cfg, f, indent=2)
    return jsonify({"ok": True, "mode": mode})

# ── Stats ──────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
def stats():
    conn = db()
    if not conn:
        return jsonify({})

    total     = _q(conn, "SELECT COUNT(*) FROM events")
    attacks   = _q(conn, "SELECT COUNT(*) FROM events WHERE attack_detected=1")
    blocked   = _q(conn, "SELECT COUNT(*) FROM events WHERE action_taken='Block'")
    sanitized = _q(conn, "SELECT COUNT(*) FROM events WHERE action_taken='Sanitize'")
    high_risk = _q(conn, "SELECT COUNT(*) FROM events WHERE risk_level IN ('High','Critical') AND attack_detected=1")
    groq_hits    = _q(conn, "SELECT COUNT(*) FROM events WHERE detection_method='groq'    AND attack_detected=1")
    gemini_hits  = _q(conn, "SELECT COUNT(*) FROM events WHERE detection_method='gemini'  AND attack_detected=1")
    fallback_hits= _q(conn, "SELECT COUNT(*) FROM events WHERE detection_method='fallback' AND attack_detected=1")
    ai_hits   = groq_hits + gemini_hits

    def acount(t):
        return _q(conn, "SELECT COUNT(*) FROM events WHERE attack_type=? AND attack_detected=1", (t,))

    sql_count   = acount("SQL Injection")
    xss_count   = acount("XSS")
    cmd_count   = acount("Command Injection")
    path_count  = acount("Path Traversal")
    ssrf_count  = acount("SSRF")
    nosql_count = acount("NoSQL Injection")
    ldap_count  = acount("LDAP Injection")

    rows  = conn.execute("SELECT attack_type, COUNT(*) n FROM events WHERE attack_detected=1 GROUP BY attack_type ORDER BY n DESC").fetchall()
    arows = conn.execute("SELECT action_taken, COUNT(*) n FROM events GROUP BY action_taken ORDER BY n DESC").fetchall()
    rrows = conn.execute("SELECT risk_level, COUNT(*) n FROM events WHERE attack_detected=1 GROUP BY risk_level").fetchall()

    breakdown        = {r["attack_type"]: r["n"] for r in rows}
    action_breakdown = {r["action_taken"]: r["n"] for r in arows}
    risk_breakdown   = {r["risk_level"]:   r["n"] for r in rrows}

    critical_count = _q(conn, "SELECT COUNT(*) FROM events WHERE risk_level='Critical' AND attack_detected=1")
    score = 100
    if total > 0:
        attack_ratio = attacks / total
        score = max(10, min(100, int(100 - (attack_ratio * 60) - (critical_count * 3) - (blocked * 2))))

    conn.close()
    return jsonify({
        "total": total, "attacks": attacks, "blocked": blocked,
        "sanitized": sanitized, "high_risk": high_risk,
        "ai_hits": ai_hits, "groq_hits": groq_hits,
        "gemini_hits": gemini_hits, "fallback_hits": fallback_hits,
        "sql_count": sql_count, "xss_count": xss_count,
        "cmd_count": cmd_count, "path_count": path_count,
        "ssrf_count": ssrf_count, "nosql_count": nosql_count,
        "ldap_count": ldap_count,
        "breakdown": breakdown,
        "action_breakdown": action_breakdown,
        "risk_breakdown": risk_breakdown,
        "security_score": score,
    })

# ── Events ─────────────────────────────────────────────────────────────────────
@app.route("/api/events")
def events():
    conn = db()
    if not conn:
        return jsonify([])
    rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/new_events")
def new_events():
    """Fast-poll: return events newer than ?since=<id> for toast notifications."""
    since = request.args.get("since", 0, type=int)
    conn  = db()
    if not conn:
        return jsonify([])
    rows = conn.execute(
        "SELECT id, attack_type, risk_level, field_name, client_ip, action_taken, timestamp "
        "FROM events WHERE id > ? AND attack_detected=1 ORDER BY id DESC LIMIT 10",
        (since,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── Timeline ───────────────────────────────────────────────────────────────────
@app.route("/api/timeline")
def timeline():
    conn = db()
    if not conn:
        return jsonify({"labels":[],"requests":[],"attacks":[],"blocked":[]})
    now = datetime.now()
    labels, reqs, atks, blkd = [], [], [], []
    for i in range(29, -1, -1):
        t0 = (now - timedelta(minutes=i+1)).strftime("%Y-%m-%d %H:%M")
        t1 = (now - timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M")
        r  = _q(conn, "SELECT COUNT(*) FROM events WHERE timestamp>=? AND timestamp<?", (t0,t1))
        a  = _q(conn, "SELECT COUNT(*) FROM events WHERE timestamp>=? AND timestamp<? AND attack_detected=1", (t0,t1))
        b  = _q(conn, "SELECT COUNT(*) FROM events WHERE timestamp>=? AND timestamp<? AND action_taken='Block'", (t0,t1))
        labels.append((now - timedelta(minutes=i)).strftime("%H:%M"))
        reqs.append(r); atks.append(a); blkd.append(b)
    conn.close()
    return jsonify({"labels": labels, "requests": reqs, "attacks": atks, "blocked": blkd})

# ── CVE Feed ───────────────────────────────────────────────────────────────────
@app.route("/api/cve_feed")
def cve_feed():
    conn = db()
    if not conn:
        return jsonify([])
    rows = conn.execute("""
        SELECT cve_id, cvss_score, cve_severity, cve_desc, attack_type, timestamp,
               mitre_id, mitre_name, confidence, risk_level
        FROM events
        WHERE attack_detected=1 AND cve_id != '' AND cve_id != 'N/A'
        ORDER BY id DESC LIMIT 20
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── Top Attacking IPs ──────────────────────────────────────────────────────────
@app.route("/api/top_ips")
def top_ips():
    conn = db()
    if not conn:
        return jsonify([])
    rows = conn.execute("""
        SELECT
            client_ip,
            COUNT(*) as attack_count,
            MAX(timestamp) as last_seen,
            SUM(CASE WHEN risk_level='Critical' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN risk_level='High'     THEN 1 ELSE 0 END) as high_count,
            GROUP_CONCAT(DISTINCT attack_type) as attack_types
        FROM events
        WHERE attack_detected=1 AND client_ip != '' AND client_ip != 'unknown'
        GROUP BY client_ip
        ORDER BY attack_count DESC
        LIMIT 10
    """).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        # Flag as scanning if 5+ attacks recorded
        d["scanning"] = d["attack_count"] >= 5
        result.append(d)
    return jsonify(result)

# ── PDF Security Report ────────────────────────────────────────────────────────
@app.route("/api/report")
def generate_report():
    """Generate and return a PDF security report."""
    try:
        from report_gen import build_report
        import sys
        sys.path.insert(0, os.path.dirname(__file__))
        report_dir = os.path.join(os.path.dirname(__file__), "..")
        pdf_bytes = build_report(DB, report_dir)
        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)
        fname = f"STS_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(buf, mimetype="application/pdf",
                         as_attachment=True, download_name=fname)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    cfg  = _load_cfg()
    port = (cfg.get("dashboard") or {}).get("port", 3000)
    app.run(host="0.0.0.0", port=port, debug=False)
