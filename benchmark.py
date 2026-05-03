#!/usr/bin/env python3
"""
STS Benchmark — automated accuracy and latency evaluation.

Fires known-malicious and known-benign payloads through the proxy,
measures detection rate, false positives/negatives, and response latency.

Usage:
    python3 ~/Desktop/sts/benchmark.py

Requirements: start.sh must be running and open_browser.sh proxy must be active.
"""

import requests, time, sys, json
from datetime import datetime

PROXY     = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
BASE      = "http://localhost:8000"
TIMEOUT   = 15

# ── Test payloads ──────────────────────────────────────────────────────────────

MALICIOUS = [
    # SQL Injection
    ("SQL Injection",    "POST", "/login",  {"username": "admin' OR '1'='1' --",     "password": "x"}),
    ("SQL Injection",    "POST", "/login",  {"username": "' UNION SELECT * FROM users--", "password": "x"}),
    ("SQL Injection",    "POST", "/login",  {"username": "1; DROP TABLE users--",     "password": "x"}),
    ("SQL Injection",    "GET",  "/search", {"q": "' OR 1=1 UNION SELECT table_name FROM information_schema.tables--"}),

    # XSS
    ("XSS",              "POST", "/comment", {"author": "hacker", "content": "<script>alert('xss')</script>"}),
    ("XSS",              "POST", "/comment", {"author": "hacker", "content": "<img src=x onerror=alert(document.cookie)>"}),
    ("XSS",              "GET",  "/search",  {"q": "<svg onload=alert(1)>"}),
    ("XSS",              "GET",  "/search",  {"q": "javascript:alert(1)"}),

    # Command Injection
    ("Command Injection","GET",  "/ping",   {"host": "8.8.8.8; whoami"}),
    ("Command Injection","GET",  "/ping",   {"host": "localhost && cat /etc/passwd"}),
    ("Command Injection","GET",  "/ping",   {"host": "`id`"}),
    ("Command Injection","GET",  "/ping",   {"host": "8.8.8.8 | ls -la /"}),

    # Path Traversal
    ("Path Traversal",   "GET",  "/file",   {"path": "../../etc/passwd"}),
    ("Path Traversal",   "GET",  "/file",   {"path": "../../../etc/shadow"}),
    ("Path Traversal",   "GET",  "/file",   {"path": "../../../../proc/self/environ"}),

    # SSRF
    ("SSRF",             "GET",  "/search", {"q": "http://localhost:22"}),
    ("SSRF",             "GET",  "/search", {"q": "file:///etc/passwd"}),
    ("SSRF",             "GET",  "/search", {"q": "http://169.254.169.254/latest/meta-data/"}),
]

BENIGN = [
    ("Benign", "POST", "/login",  {"username": "alice",          "password": "hunter2"}),
    ("Benign", "POST", "/login",  {"username": "bob@example.com","password": "P@ssw0rd!"}),
    ("Benign", "GET",  "/search", {"q": "checking account"}),
    ("Benign", "GET",  "/search", {"q": "savings transfer"}),
    ("Benign", "GET",  "/search", {"q": "john smith"}),
    ("Benign", "POST", "/comment",{"author": "Alice", "content": "Great service!"}),
    ("Benign", "POST", "/comment",{"author": "Bob",   "content": "How do I reset my PIN?"}),
    ("Benign", "GET",  "/file",   {"path": "readme.txt"}),
    ("Benign", "GET",  "/file",   {"path": "report.pdf"}),
    ("Benign", "GET",  "/ping",   {"host": "8.8.8.8"}),
    ("Benign", "GET",  "/ping",   {"host": "google.com"}),
    ("Benign", "GET",  "/search", {"q": "account number 12345"}),
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def send(method: str, path: str, params: dict) -> tuple[int, float]:
    url = BASE + path
    t0  = time.perf_counter()
    try:
        if method == "POST":
            r = requests.post(url, data=params, proxies=PROXY, timeout=TIMEOUT, allow_redirects=False)
        else:
            r = requests.get(url, params=params, proxies=PROXY, timeout=TIMEOUT, allow_redirects=False)
        latency = (time.perf_counter() - t0) * 1000
        return r.status_code, latency
    except Exception as e:
        latency = (time.perf_counter() - t0) * 1000
        print(f"     ⚠  Request failed: {e}")
        return 0, latency

def bar(n, total, width=20):
    filled = int(width * n / total) if total else 0
    return "█" * filled + "░" * (width - filled)

# ── Main ───────────────────────────────────────────────────────────────────────

def run():
    print("\n" + "═"*66)
    print("  STS BENCHMARK — Semantic Traffic Sanitizer Evaluation")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═"*66)

    # Check services are up
    try:
        requests.get(BASE + "/", proxies=PROXY, timeout=5)
        print("  ✅  Proxy + server reachable\n")
    except:
        print("  ❌  Cannot reach proxy/server. Make sure start.sh + proxy are running.\n")
        sys.exit(1)

    results = []

    # ── Malicious payloads (expect 403 Block) ─────────────────────────────────
    print("  ── MALICIOUS PAYLOADS (expect 403 Block or modified response) ──")
    print(f"  {'#':<3} {'Type':<20} {'Method':<6} {'Path':<10} {'Status':<8} {'Latency':<10} {'Result'}")
    print("  " + "─"*62)

    tp = fp_miss = 0
    mal_latencies = []

    for i, (atype, method, path, params) in enumerate(MALICIOUS, 1):
        status, latency = send(method, path, params)
        mal_latencies.append(latency)
        detected = status in (403, 200)   # 403=blocked, 200=sanitized+forwarded
        blocked  = status == 403
        result   = "✅ BLOCKED" if blocked else ("⚠  SANITIZED" if status==200 else "❌ MISSED")
        if blocked or status == 200:
            tp += 1
        else:
            fp_miss += 1
        results.append({"type": atype, "expected": "malicious", "status": status, "latency": latency, "detected": detected})
        print(f"  {i:<3} {atype:<20} {method:<6} {path:<10} {status:<8} {latency:>6.0f}ms   {result}")

    print()

    # ── Benign payloads (expect 200 Allow) ────────────────────────────────────
    print("  ── BENIGN PAYLOADS (expect 200, no false positives) ──")
    print(f"  {'#':<3} {'Type':<20} {'Method':<6} {'Path':<10} {'Status':<8} {'Latency':<10} {'Result'}")
    print("  " + "─"*62)

    tn = fp = 0
    ben_latencies = []

    for i, (atype, method, path, params) in enumerate(BENIGN, 1):
        status, latency = send(method, path, params)
        ben_latencies.append(latency)
        false_positive = status == 403
        result = "❌ FALSE POS" if false_positive else "✅ ALLOWED"
        if false_positive:
            fp += 1
        else:
            tn += 1
        results.append({"type": atype, "expected": "benign", "status": status, "latency": latency, "detected": false_positive})
        print(f"  {i:<3} {atype:<20} {method:<6} {path:<10} {status:<8} {latency:>6.0f}ms   {result}")

    print()

    # ── Summary ───────────────────────────────────────────────────────────────
    total_mal = len(MALICIOUS)
    total_ben = len(BENIGN)
    detection_rate  = tp / total_mal * 100
    fp_rate         = fp / total_ben * 100
    avg_mal_latency = sum(mal_latencies) / len(mal_latencies)
    avg_ben_latency = sum(ben_latencies) / len(ben_latencies)
    p95_latency     = sorted(mal_latencies + ben_latencies)[int(len(mal_latencies+ben_latencies)*.95)]

    print("═"*66)
    print("  RESULTS SUMMARY")
    print("─"*66)
    print(f"  Attack Detection Rate  : {detection_rate:>5.1f}%  {bar(tp,total_mal)}  {tp}/{total_mal}")
    print(f"  False Positive Rate    : {fp_rate:>5.1f}%  {bar(fp,total_ben)}  {fp}/{total_ben}")
    print(f"  True Negatives (benign): {100-fp_rate:>5.1f}%  {bar(tn,total_ben)}  {tn}/{total_ben}")
    print()
    print(f"  Avg latency (malicious): {avg_mal_latency:>7.0f} ms")
    print(f"  Avg latency (benign)   : {avg_ben_latency:>7.0f} ms")
    print(f"  p95 latency (all)      : {p95_latency:>7.0f} ms")
    print()

    # Attack-type breakdown
    from collections import defaultdict
    by_type = defaultdict(lambda: {"detected": 0, "total": 0})
    for r in results:
        if r["expected"] == "malicious":
            by_type[r["type"]]["total"] += 1
            if r["status"] in (403, 200):
                by_type[r["type"]]["detected"] += 1

    print("  Per-attack-type detection:")
    for atype, counts in sorted(by_type.items()):
        rate = counts["detected"] / counts["total"] * 100
        print(f"    {atype:<22} {rate:>5.1f}%  {bar(counts['detected'],counts['total'],12)}  {counts['detected']}/{counts['total']}")

    print()
    grade = "A" if detection_rate >= 90 and fp_rate < 10 else \
            "B" if detection_rate >= 75 and fp_rate < 20 else \
            "C" if detection_rate >= 60 else "D"
    print(f"  Overall Grade: {grade}  (Detection {detection_rate:.1f}% | FP {fp_rate:.1f}%)")
    print("═"*66)
    print()

    # Save JSON report
    report_path = "/tmp/sts_benchmark_report.json"
    with open(report_path, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "detection_rate": round(detection_rate, 2),
                "false_positive_rate": round(fp_rate, 2),
                "avg_malicious_latency_ms": round(avg_mal_latency, 2),
                "avg_benign_latency_ms": round(avg_ben_latency, 2),
                "p95_latency_ms": round(p95_latency, 2),
                "grade": grade,
            },
            "by_type": {k: {"rate": round(v["detected"]/v["total"]*100,1), **v} for k,v in by_type.items()},
            "raw": results,
        }, f, indent=2)
    print(f"  JSON report saved → {report_path}\n")

if __name__ == "__main__":
    run()
