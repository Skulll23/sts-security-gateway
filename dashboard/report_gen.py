"""
STS Security Report Generator
Produces a professional PDF security report using fpdf2.
"""

import sqlite3, os, json, subprocess, sys
from datetime import datetime

def _ensure_fpdf2():
    try:
        from fpdf import FPDF
        return True
    except ImportError:
        print("[STS] fpdf2 not found - installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "fpdf2", "-q"])
        return True

def build_report(db_path: str, report_dir: str) -> bytes:
    _ensure_fpdf2()
    from fpdf import FPDF, XPos, YPos

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    def q(sql, args=()):
        return conn.execute(sql, args).fetchone()[0]

    total      = q("SELECT COUNT(*) FROM events")
    attacks    = q("SELECT COUNT(*) FROM events WHERE attack_detected=1")
    blocked    = q("SELECT COUNT(*) FROM events WHERE action_taken='Block'")
    sanitized  = q("SELECT COUNT(*) FROM events WHERE action_taken='Sanitize'")
    critical   = q("SELECT COUNT(*) FROM events WHERE risk_level='Critical' AND attack_detected=1")
    high       = q("SELECT COUNT(*) FROM events WHERE risk_level='High'     AND attack_detected=1")
    groq_hits  = q("SELECT COUNT(*) FROM events WHERE detection_method='groq'    AND attack_detected=1")
    gemini_hits= q("SELECT COUNT(*) FROM events WHERE detection_method='gemini'  AND attack_detected=1")
    rule_hits  = q("SELECT COUNT(*) FROM events WHERE detection_method='fallback' AND attack_detected=1")

    attack_rows = conn.execute(
        "SELECT attack_type, COUNT(*) n FROM events WHERE attack_detected=1 "
        "GROUP BY attack_type ORDER BY n DESC LIMIT 8"
    ).fetchall()

    cve_rows = conn.execute(
        "SELECT cve_id, cvss_score, cve_severity, cve_desc, attack_type "
        "FROM events WHERE attack_detected=1 AND cve_id != '' AND cve_id != 'N/A' "
        "GROUP BY cve_id ORDER BY cvss_score DESC LIMIT 8"
    ).fetchall()

    recent_rows = conn.execute(
        "SELECT timestamp, attack_type, risk_level, field_name, client_ip, action_taken "
        "FROM events WHERE attack_detected=1 ORDER BY id DESC LIMIT 20"
    ).fetchall()

    top_ips = conn.execute(
        "SELECT client_ip, COUNT(*) n FROM events WHERE attack_detected=1 "
        "GROUP BY client_ip ORDER BY n DESC LIMIT 5"
    ).fetchall()

    conn.close()

    # Score
    score = 100
    if total > 0:
        score = max(10, min(100, int(100 - (attacks/total*60) - (critical*3) - (blocked*2))))

    # ?? PDF class with header/footer ???????????????????????????????????????????
    class STS_PDF(FPDF):
        def header(self):
            if self.page_no() == 1:
                return
            self.set_fill_color(13, 17, 30)
            self.rect(0, 0, 210, 12, 'F')
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(100, 116, 180)
            self.set_y(4)
            self.cell(0, 4, "STS  -  Semantic Traffic Sanitizer  |  Security Assessment Report", align="L")
            self.cell(0, 4, f"Page {self.page_no()}", align="R")
            self.set_y(13)

        def footer(self):
            self.set_y(-12)
            self.set_fill_color(13, 17, 30)
            self.rect(0, 285, 210, 12, 'F')
            self.set_font("Helvetica", "", 7)
            self.set_text_color(60, 70, 100)
            self.cell(0, 4, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  CONFIDENTIAL  -  Internal Use Only", align="C")

    pdf = STS_PDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(18, 18, 18)

    # ??????????????????????????????????????????????????????????????????
    # PAGE 1  -  COVER
    # ??????????????????????????????????????????????????????????????????
    pdf.add_page()

    # Dark background
    pdf.set_fill_color(7, 9, 15)
    pdf.rect(0, 0, 210, 297, 'F')

    # Accent stripe at top
    pdf.set_fill_color(59, 130, 246)
    pdf.rect(0, 0, 210, 4, 'F')

    # STS Logo area
    pdf.set_fill_color(20, 25, 45)
    pdf.rect(18, 30, 174, 55, 'F')
    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(0.5)
    pdf.rect(18, 30, 174, 55)

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(59, 130, 246)
    pdf.set_xy(18, 44)
    pdf.cell(174, 12, "STS", align="C")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(148, 163, 184)
    pdf.set_xy(18, 57)
    pdf.cell(174, 7, "Semantic Traffic Sanitizer", align="C")

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(100, 116, 180)
    pdf.set_xy(18, 67)
    pdf.cell(174, 6, "AI-Powered HTTP Security Proxy  |  UTS 41909 Cybersecurity Capstone", align="C")

    # Report title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(241, 245, 249)
    pdf.set_xy(18, 100)
    pdf.cell(174, 10, "Security Assessment Report", align="C")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 116, 180)
    pdf.set_xy(18, 113)
    pdf.cell(174, 7, datetime.now().strftime("%B %d, %Y"), align="C")

    # Security Score box
    score_color = (34, 197, 94) if score >= 70 else (249, 115, 22) if score >= 40 else (239, 68, 68)
    pdf.set_fill_color(13, 17, 30)
    pdf.rect(65, 128, 80, 50, 'F')
    pdf.set_draw_color(*score_color)
    pdf.rect(65, 128, 80, 50)

    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(*score_color)
    pdf.set_xy(65, 135)
    pdf.cell(80, 18, str(score), align="C")

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(100, 116, 180)
    pdf.set_xy(65, 154)
    pdf.cell(80, 5, "SECURITY SCORE / 100", align="C")

    grade = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D"
    pdf.set_font("Helvetica", "", 8)
    pdf.set_xy(65, 161)
    pdf.cell(80, 5, f"Grade: {grade}", align="C")

    # Key numbers row
    nums = [
        (str(total),    "Total Requests"),
        (str(attacks),  "Attacks Detected"),
        (str(blocked),  "Requests Blocked"),
        (str(critical), "Critical Events"),
    ]
    x_start = 18
    box_w   = 40
    for i, (val, lbl) in enumerate(nums):
        x = x_start + i * (box_w + 2.5)
        pdf.set_fill_color(13, 17, 30)
        pdf.rect(x, 190, box_w, 28, 'F')
        pdf.set_draw_color(30, 35, 55)
        pdf.rect(x, 190, box_w, 28)
        pdf.set_font("Helvetica", "B", 18)
        col = (239, 68, 68) if lbl == "Critical Events" else (59, 130, 246)
        pdf.set_text_color(*col)
        pdf.set_xy(x, 195)
        pdf.cell(box_w, 10, val, align="C")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(100, 116, 180)
        pdf.set_xy(x, 206)
        pdf.cell(box_w, 5, lbl, align="C")

    # Confidential footer
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(50, 55, 80)
    pdf.set_xy(18, 265)
    pdf.cell(174, 6, "CONFIDENTIAL  -  For Internal Security Review Only", align="C")
    pdf.set_xy(18, 271)
    pdf.cell(174, 6, "Semantic Traffic Sanitizer   |   UTS 41909   |   AI-Powered Application Security", align="C")

    # ??????????????????????????????????????????????????????????????????
    # PAGE 2  -  EXECUTIVE SUMMARY
    # ??????????????????????????????????????????????????????????????????
    pdf.add_page()

    def section_header(title: str, subtitle: str = ""):
        pdf.set_fill_color(13, 17, 30)
        pdf.rect(18, pdf.get_y(), 174, 12, 'F')
        pdf.set_draw_color(59, 130, 246)
        pdf.set_line_width(0.3)
        pdf.line(18, pdf.get_y(), 18, pdf.get_y() + 12)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(96, 165, 250)
        pdf.set_x(22)
        pdf.cell(0, 12, title)
        pdf.ln(14)
        if subtitle:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(100, 116, 180)
            pdf.cell(0, 5, subtitle)
            pdf.ln(7)

    def stat_row(label, value, color=(241,245,249)):
        y = pdf.get_y()
        pdf.set_fill_color(15, 19, 32)
        pdf.rect(18, y, 174, 9, 'F')
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(148, 163, 184)
        pdf.set_xy(22, y + 1.5)
        pdf.cell(120, 6, str(label))
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*color)
        pdf.set_xy(140, y + 1.5)
        pdf.cell(50, 6, str(value), align="R")
        pdf.ln(10)

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(241, 245, 249)
    pdf.cell(0, 10, "Executive Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(0.5)
    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
    pdf.ln(6)

    # Narrative
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(148, 163, 184)
    narrative = (
        f"This report covers the security posture of the monitored application as analysed by the STS Security Gateway. "
        f"During the monitoring period, a total of {total} HTTP requests were intercepted. Of these, {attacks} "
        f"({(attacks/total*100 if total else 0):.1f}%) were identified as potentially malicious. "
        f"The system blocked {blocked} high-risk requests entirely and sanitized "
        f"{sanitized} medium-risk inputs before forwarding them. "
        f"The overall security score is {score}/100 (Grade {grade})."
    )
    pdf.multi_cell(174, 5.5, narrative)
    pdf.ln(8)

    section_header("Traffic Overview")
    stat_row("Total Requests Intercepted",  total,     (96, 165, 250))
    stat_row("Malicious Requests Detected", attacks,   (239, 68, 68))
    stat_row("Requests Blocked (403)",      blocked,   (239, 68, 68))
    stat_row("Requests Sanitized",          sanitized, (249, 115, 22))
    stat_row("Benign Requests Passed",      total - attacks, (34, 197, 94))
    pdf.ln(5)

    section_header("Risk Breakdown")
    stat_row("Critical Risk Events",  critical, (239, 68, 68))
    stat_row("High Risk Events",      high,     (249, 115, 22))
    stat_row("Other Risk Events",     attacks - critical - high, (234, 179, 8))
    pdf.ln(5)

    section_header("AI Detection Engine")
    stat_row("Groq Llama 3.3 70B",      groq_hits,   (6, 182, 212))
    stat_row("Gemini 2.0 Flash",         gemini_hits, (139, 92, 246))
    stat_row("Rule-Based Fallback",      rule_hits,   (148, 163, 184))
    ai_total = groq_hits + gemini_hits + rule_hits
    if ai_total > 0:
        stat_row("AI Detection Rate",
                 f"{(groq_hits+gemini_hits)/ai_total*100:.1f}%", (34, 197, 94))

    # ??????????????????????????????????????????????????????????????????
    # PAGE 3  -  ATTACK ANALYSIS
    # ??????????????????????????????????????????????????????????????????
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(241, 245, 249)
    pdf.cell(0, 10, "Attack Analysis", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(59, 130, 246)
    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
    pdf.ln(6)

    # Attack distribution bar chart (ASCII-style)
    section_header("Attack Type Distribution")
    max_n = max((r["n"] for r in attack_rows), default=1)
    bar_width = 80
    ATTACK_COLORS = {
        "SQL Injection":     (239, 68, 68),
        "XSS":               (249, 115, 22),
        "Command Injection": (239, 68, 68),
        "Path Traversal":    (234, 179, 8),
        "SSRF":              (168, 85, 247),
        "LDAP Injection":    (6, 182, 212),
        "NoSQL Injection":   (96, 165, 250),
    }
    for row in attack_rows:
        y     = pdf.get_y()
        atype = row["attack_type"]
        n     = row["n"]
        pct   = n / max_n
        col   = ATTACK_COLORS.get(atype, (100, 116, 180))

        # Label
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(148, 163, 184)
        pdf.set_xy(18, y + 1.5)
        pdf.cell(52, 6, atype[:28])

        # Bar background
        pdf.set_fill_color(20, 25, 40)
        pdf.rect(72, y + 1, bar_width, 7, 'F')

        # Bar fill
        fill_w = max(2, int(bar_width * pct))
        pdf.set_fill_color(*col)
        pdf.rect(72, y + 1, fill_w, 7, 'F')

        # Count
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*col)
        pdf.set_xy(155, y + 1.5)
        pdf.cell(30, 6, str(n))

        pdf.ln(11)

    pdf.ln(6)

    # Top Attacking IPs
    if top_ips:
        section_header("Top Attacking IPs")
        # Table header
        y = pdf.get_y()
        pdf.set_fill_color(20, 25, 40)
        pdf.rect(18, y, 174, 8, 'F')
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(100, 116, 180)
        pdf.set_xy(20, y + 1.5)
        pdf.cell(55, 5, "IP Address")
        pdf.cell(40, 5, "Attacks")
        pdf.cell(0,  5, "Status")
        pdf.ln(9)

        for row in top_ips:
            y = pdf.get_y()
            pdf.set_fill_color(13, 17, 30)
            pdf.rect(18, y, 174, 8, 'F')
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(241, 245, 249)
            pdf.set_xy(20, y + 1.5)
            pdf.cell(55, 5, str(row["client_ip"]))
            pdf.set_text_color(239, 68, 68)
            pdf.cell(40, 5, str(row["n"]))
            status = "SCANNING" if row["n"] >= 5 else "Hostile"
            col = (239, 68, 68) if row["n"] >= 5 else (249, 115, 22)
            pdf.set_text_color(*col)
            pdf.cell(0,  5, status)
            pdf.ln(9)

    # ??????????????????????????????????????????????????????????????????
    # PAGE 4  -  CVE INTELLIGENCE
    # ??????????????????????????????????????????????????????????????????
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(241, 245, 249)
    pdf.cell(0, 10, "CVE Intelligence Findings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(6, 182, 212)
    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
    pdf.ln(6)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 116, 180)
    pdf.multi_cell(174, 5,
        "The following CVE records were matched against detected attacks. "
        "CVE IDs are sourced from the National Vulnerability Database (NVD). "
        "CVSS scores indicate severity on a 0-10 scale.")
    pdf.ln(6)

    if cve_rows:
        for row in cve_rows:
            y = pdf.get_y()
            cvss  = float(row["cvss_score"] or 0)
            sev   = str(row["cve_severity"] or "Unknown")
            sev_colors = {"Critical":(239,68,68),"High":(249,115,22),"Medium":(234,179,8),"Low":(34,197,94)}
            sc = sev_colors.get(sev, (100,116,180))

            # Card background
            pdf.set_fill_color(13, 17, 30)
            pdf.rect(18, y, 174, 26, 'F')
            pdf.set_draw_color(*sc)
            pdf.set_line_width(0.2)
            pdf.rect(18, y, 174, 26)
            # Left accent
            pdf.set_fill_color(*sc)
            pdf.rect(18, y, 3, 26, 'F')

            # CVE ID
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(6, 182, 212)
            pdf.set_xy(24, y + 2.5)
            pdf.cell(50, 5, str(row["cve_id"]))

            # Attack type
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(100, 116, 180)
            pdf.set_xy(75, y + 2.5)
            pdf.cell(60, 5, str(row["attack_type"]))

            # CVSS + severity
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*sc)
            pdf.set_xy(155, y + 2.5)
            pdf.cell(35, 5, f"CVSS {cvss:.1f}  {sev}", align="R")

            # Description
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(148, 163, 184)
            pdf.set_xy(24, y + 10)
            desc = str(row["cve_desc"] or "")[:95] + ("..." if len(str(row["cve_desc"] or "")) > 95 else "")
            pdf.cell(168, 5, desc)

            pdf.set_xy(18, y + 26 + 3)
            pdf.ln(3)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100, 116, 180)
        pdf.cell(0, 8, "No CVE matches found yet  -  fire some attacks to populate this section.")

    # ??????????????????????????????????????????????????????????????????
    # PAGE 5  -  RECENT EVENTS
    # ??????????????????????????????????????????????????????????????????
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(241, 245, 249)
    pdf.cell(0, 10, "Recent Attack Events", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(59, 130, 246)
    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
    pdf.ln(6)

    if recent_rows:
        # Table header
        y = pdf.get_y()
        pdf.set_fill_color(20, 25, 40)
        pdf.rect(18, y, 174, 8, 'F')
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(100, 116, 180)
        for label, x, w in [
            ("Timestamp", 20, 36), ("Attack Type", 58, 38),
            ("Risk", 98, 20), ("Field", 120, 28), ("IP", 150, 28), ("Action", 180, 12)
        ]:
            pdf.set_xy(x, y + 1.5)
            pdf.cell(w, 5, label)
        pdf.ln(9)

        ACTION_COLORS = {"Block":(239,68,68), "Sanitize":(249,115,22), "Allow":(34,197,94), "Allowed":(100,116,180)}
        RISK_COLORS   = {"Critical":(239,68,68), "High":(249,115,22), "Medium":(234,179,8), "Low":(34,197,94)}

        for i, row in enumerate(recent_rows):
            y  = pdf.get_y()
            bg = (15, 19, 32) if i % 2 == 0 else (13, 17, 28)
            pdf.set_fill_color(*bg)
            pdf.rect(18, y, 174, 8, 'F')

            ts      = str(row["timestamp"] or "")[:16]
            atype   = str(row["attack_type"] or "")[:20]
            risk    = str(row["risk_level"]  or "")
            field   = str(row["field_name"]  or "")[:14]
            ip_addr = str(row["client_ip"]   or "")[:18]
            action  = str(row["action_taken"]or "")

            rc = RISK_COLORS.get(risk,   (100,116,180))
            ac = ACTION_COLORS.get(action,(100,116,180))

            pdf.set_font("Helvetica", "", 7.5)
            for val, x, w, col in [
                (ts,      20,  36, (148,163,184)),
                (atype,   58,  38, (241,245,249)),
                (risk,    98,  20, rc),
                (field,   120, 28, (200,210,220)),
                (ip_addr, 150, 28, (148,163,184)),
                (action,  180, 12, ac),
            ]:
                pdf.set_text_color(*col)
                pdf.set_xy(x, y + 1.5)
                pdf.cell(w, 5, val)
            pdf.ln(9)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100, 116, 180)
        pdf.cell(0, 8, "No attack events recorded yet.")

    return bytes(pdf.output())
