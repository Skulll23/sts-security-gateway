"""
STS LLM Engine
Detection priority:
  1. Groq (Llama 3.3 70B) — 6,000 RPM free, ~100ms latency
  2. Gemini 2.0 Flash      — fallback if Groq fails
  3. Rule-based patterns   — always-available offline fallback

Mode support (read from config.json):
  detect   — log only, never block or sanitize
  strict   — Block Critical/High, Sanitize Medium, Allow Low  (default)
  paranoid — Block Critical/High/Medium, Allow only Low
"""

import os, json, time, hashlib, requests
from collections import OrderedDict

GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# ── Load config.json ──────────────────────────────────────────────────────────
_here = os.path.dirname(os.path.abspath(__file__))
_cfg_path = os.path.join(_here, "..", "config.json")
_CFG: dict = {}
try:
    with open(_cfg_path) as _f:
        _CFG = json.load(_f)
except Exception:
    pass

def _get_mode() -> str:
    """Re-read mode from config every time so hot-editing config.json takes effect."""
    try:
        with open(_cfg_path) as _f:
            return json.load(_f).get("mode", "strict").lower()
    except Exception:
        return "strict"

_CACHE_MAX = int((_CFG.get("ai") or {}).get("cache_size", 512))

# ── LRU result cache — identical payloads skip the API entirely ───────────────
_cache: OrderedDict = OrderedDict()

def _cache_key(value: str, field_name: str) -> str:
    return hashlib.sha256(f"{field_name}:{value}".encode()).hexdigest()

def _cache_get(key: str):
    if key in _cache:
        _cache.move_to_end(key)
        return _cache[key]
    return None

def _cache_set(key: str, value):
    _cache[key] = value
    _cache.move_to_end(key)
    if len(_cache) > _CACHE_MAX:
        _cache.popitem(last=False)

# ── Risk → action mapping (mode-aware) ────────────────────────────────────────
_STRICT_MAP   = {"Critical": "Block",    "High": "Block",    "Medium": "Sanitize", "Low": "Allow"}
_PARANOID_MAP = {"Critical": "Block",    "High": "Block",    "Medium": "Block",    "Low": "Allow"}
_DETECT_MAP   = {"Critical": "Allowed",  "High": "Allowed",  "Medium": "Allowed",  "Low": "Allowed"}

def _action_for_risk(risk: str) -> str:
    mode = _get_mode()
    if mode == "detect":
        return "Allowed"
    if mode == "paranoid":
        return _PARANOID_MAP.get(risk, "Allow")
    return _STRICT_MAP.get(risk, "Allow")  # strict (default)

# ── Prompt (shared between Groq and Gemini) ────────────────────────────────────
PROMPT_TEMPLATE = """You are a WAF (Web Application Firewall) security engine.
Analyze this HTTP input field for injection attacks.

Field name : {field_name}
Field value: {value}

Detect any of:
- SQL Injection      : OR 1=1, UNION SELECT, DROP TABLE, INSERT/DELETE/UPDATE, EXEC, xp_cmdshell
- XSS                : <script>, onerror=, javascript:, alert(, <img, <svg, document.cookie, eval(
- Command Injection  : ; whoami, && ls, | cat, `id`, $(), rm -rf, /bin/sh, /bin/bash
- Path Traversal     : ../, ..\\, /etc/passwd, /etc/shadow, /proc/, C:\\Windows\\
- SSRF               : file://, http://localhost, http://127., http://169.254., dict://, gopher://
- LDAP Injection     : )(cn=*, |(uid=*, *)(objectClass=*
- NoSQL Injection    : {{"$gt":""}}, {{"$where":""}}, {{"$ne":""}}

Risk guide: Critical=RCE potential, High=data exfiltration, Medium=client-side, Low=suspicious
Action guide: Block=Critical/High, Sanitize=Medium, Allow=Low/Benign

Respond ONLY with a JSON object (no markdown, no code fences):
{{
  "malicious": true or false,
  "attack_type": "SQL Injection"|"XSS"|"Command Injection"|"Path Traversal"|"SSRF"|"LDAP Injection"|"NoSQL Injection"|"Benign",
  "confidence": 0-100,
  "risk_level": "Critical"|"High"|"Medium"|"Low",
  "explanation": "one sentence describing what was detected and why it is dangerous",
  "sanitized_text": "input with malicious parts replaced by [blocked]",
  "action": "Block"|"Sanitize"|"Allow"
}}"""

# ── Rule-based fallback ────────────────────────────────────────────────────────
RULES = {
    "SQL Injection":     {"risk": "High",     "patterns": ["' or ", "1=1", "union select", "drop table", "insert into", "delete from", "exec(", "xp_cmdshell", "'; --", "-- ", "char(", "cast("]},
    "Command Injection": {"risk": "Critical",  "patterns": ["; ls", "; cat", "; whoami", "&&", "| bash", "| sh", "/bin/sh", "/bin/bash", "whoami", "`id`", "$(", "rm -rf"]},
    "Path Traversal":    {"risk": "High",     "patterns": ["../", "..\\", "/etc/passwd", "/etc/shadow", "/etc/hosts", "c:\\windows", "/proc/self", "/root/"]},
    "XSS":               {"risk": "Medium",   "patterns": ["<script", "</script>", "javascript:", "onerror=", "onload=", "onclick=", "alert(", "<img ", "<svg ", "document.cookie", "eval("]},
    "SSRF":              {"risk": "High",     "patterns": ["file://", "http://localhost", "http://127.", "http://0.0.0.0", "http://169.254", "dict://", "gopher://"]},
    "LDAP Injection":    {"risk": "Medium",   "patterns": [")(cn=*", "|(uid=*", "*)(objectclass="]},
    "NoSQL Injection":   {"risk": "High",     "patterns": ["$gt", "$where", "$ne", "$regex", "$exists"]},
}

def _fallback(value: str) -> dict:
    v = value.lower()
    for atype, cfg in RULES.items():
        for p in cfg["patterns"]:
            if p.lower() in v:
                risk      = cfg["risk"]
                sanitized = value
                for pat in cfg["patterns"]:
                    sanitized = sanitized.replace(pat, "[blocked]").replace(pat.upper(), "[blocked]")
                return {
                    "malicious": True, "attack_type": atype, "confidence": 88,
                    "risk_level": risk, "action": _action_for_risk(risk),
                    "explanation": f"Rule-based detection matched pattern '{p}'.",
                    "sanitized_text": sanitized,
                }
    return {
        "malicious": False, "attack_type": "Benign", "confidence": 0,
        "risk_level": "Low", "action": "Allow",
        "explanation": "No known attack patterns detected.",
        "sanitized_text": value,
    }

def _normalise(result: dict, value: str) -> dict:
    """Fill missing keys and enforce risk→action policy based on current mode."""
    result.setdefault("confidence",     90)
    result.setdefault("explanation",    "")
    result.setdefault("sanitized_text", value)
    risk = result.get("risk_level", "Low")
    result["action"] = _action_for_risk(risk) if result.get("malicious") else "Allow"
    return result

# ── Groq call ─────────────────────────────────────────────────────────────────
def _call_groq(value: str, field_name: str, api_key: str) -> dict | None:
    prompt  = PROMPT_TEMPLATE.format(field_name=field_name, value=value)
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model":       GROQ_MODEL,
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=10)
    if resp.status_code == 429:
        print("[LLM] Groq 429 — rate limited, falling through")
        return None
    resp.raise_for_status()
    raw = resp.json()["choices"][0]["message"]["content"]
    return json.loads(raw.strip())

# ── Gemini call ───────────────────────────────────────────────────────────────
def _call_gemini(value: str, field_name: str, api_key: str) -> dict | None:
    prompt  = PROMPT_TEMPLATE.format(field_name=field_name, value=value)
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.0, "response_mime_type": "application/json"},
    }
    resp = requests.post(f"{GEMINI_URL}?key={api_key}", json=payload, timeout=8)
    if resp.status_code == 429:
        print("[LLM] Gemini 429 — rate limited, falling through")
        return None
    resp.raise_for_status()
    raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    return json.loads(raw.strip())

# ── Public interface ───────────────────────────────────────────────────────────
def analyze(value: str, field_name: str = "input") -> tuple[dict, str]:
    """
    Returns (result_dict, detection_method).
    method is one of: 'groq', 'gemini', 'fallback'
    """
    ckey   = _cache_key(value, field_name)
    cached = _cache_get(ckey)
    if cached is not None:
        # Re-apply mode in case it changed since caching
        if cached.get("malicious"):
            cached["action"] = _action_for_risk(cached.get("risk_level", "Low"))
        print(f"[LLM] Cache hit — '{field_name}' (mode={_get_mode()})")
        return cached, "groq"

    groq_key   = os.environ.get("GROQ_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    mode       = _get_mode()
    print(f"[LLM] Analysing '{field_name}' (mode={mode})")

    # ── 1. Try Groq ───────────────────────────────────────────────────────────
    if groq_key:
        try:
            result = _call_groq(value, field_name, groq_key)
            if result is not None:
                result = _normalise(result, value)
                _cache_set(ckey, result)
                print(f"[LLM] Groq ✓ — '{field_name}' → {result['attack_type']} ({result['risk_level']}) → {result['action']}")
                return result, "groq"
        except Exception as e:
            print(f"[LLM] Groq error: {e}")

    # ── 2. Try Gemini ─────────────────────────────────────────────────────────
    if gemini_key:
        try:
            result = _call_gemini(value, field_name, gemini_key)
            if result is not None:
                result = _normalise(result, value)
                _cache_set(ckey, result)
                print(f"[LLM] Gemini ✓ — '{field_name}' → {result['attack_type']} ({result['risk_level']}) → {result['action']}")
                return result, "gemini"
        except Exception as e:
            print(f"[LLM] Gemini error: {e}")

    # ── 3. Rule-based fallback ────────────────────────────────────────────────
    print(f"[LLM] Rule-based fallback — '{field_name}'")
    return _fallback(value), "fallback"
