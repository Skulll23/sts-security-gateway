import sqlite3, os

_sts_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH   = os.path.join(_sts_root, "data", "sts.db")

def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp        TEXT    NOT NULL,
            client_ip        TEXT,
            method           TEXT,
            url              TEXT,
            field_name       TEXT,
            original_value   TEXT,
            sanitized_value  TEXT,
            attack_detected  INTEGER DEFAULT 0,
            attack_type      TEXT    DEFAULT 'Benign',
            confidence       INTEGER DEFAULT 0,
            risk_level       TEXT    DEFAULT 'Low',
            action_taken     TEXT    DEFAULT 'Allowed',
            explanation      TEXT,
            detection_method TEXT    DEFAULT 'none',
            cve_id           TEXT    DEFAULT '',
            cvss_score       REAL    DEFAULT 0.0,
            cve_severity     TEXT    DEFAULT '',
            cve_desc         TEXT    DEFAULT '',
            mitre_id         TEXT    DEFAULT '',
            mitre_name       TEXT    DEFAULT ''
        )
    """)
    # Add CVE columns to existing DBs that pre-date this schema
    for col, typedef in [
        ("cve_id",     "TEXT    DEFAULT ''"),
        ("cvss_score", "REAL    DEFAULT 0.0"),
        ("cve_severity","TEXT   DEFAULT ''"),
        ("cve_desc",   "TEXT    DEFAULT ''"),
        ("mitre_id",   "TEXT    DEFAULT ''"),
        ("mitre_name", "TEXT    DEFAULT ''"),
    ]:
        try:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} {typedef}")
        except Exception:
            pass  # column already exists
    conn.commit()
    conn.close()

def insert_event(e):
    conn = get_conn()
    conn.execute("""
        INSERT INTO events
        (timestamp, client_ip, method, url, field_name,
         original_value, sanitized_value, attack_detected,
         attack_type, confidence, risk_level, action_taken,
         explanation, detection_method,
         cve_id, cvss_score, cve_severity, cve_desc,
         mitre_id, mitre_name)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        e["timestamp"], e.get("client_ip",""), e.get("method",""), e.get("url",""),
        e.get("field_name",""), e.get("original_value",""), e.get("sanitized_value",""),
        1 if e.get("attack_detected") else 0,
        e.get("attack_type","Benign"), e.get("confidence",0),
        e.get("risk_level","Low"), e.get("action_taken","Allowed"),
        e.get("explanation",""), e.get("detection_method","none"),
        e.get("cve_id",""), e.get("cvss_score",0.0),
        e.get("cve_severity",""), e.get("cve_desc",""),
        e.get("mitre_id",""), e.get("mitre_name",""),
    ))
    conn.commit()
    conn.close()
