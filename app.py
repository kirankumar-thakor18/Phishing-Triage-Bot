import os
import re
import io
import csv
import json
import time
import base64
import hashlib
import sqlite3
import ipaddress
import tempfile
import threading
from datetime import datetime, timezone
import requests
from flask import Flask, render_template, request, redirect, url_for
from dotenv import load_dotenv
import mailparser

# Load environment variables (.env file se API key uthane ke liye)
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

app = Flask(__name__)

# Upload size limit (5 MB) - bada file server ko hang/DoS kar sakta hai
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Basic per-IP rate limit (demo safety): public URL pe API quota abuse rokta hai.
app.config["RATE_LIMIT_ENABLED"] = True
app.config["RATE_LIMIT_MAX"] = 5          # max requests
app.config["RATE_LIMIT_WINDOW"] = 60      # per 60 seconds

# API quota safety: ek email mein bahut saare IOC ho sakte hain, par hum
# limited check karte hain taaki free-tier API quota khatam na ho.
MAX_URLS_TO_SCAN = 10
MAX_IPS_TO_SCAN = 3
MAX_ATTACHMENTS_TO_SCAN = 5

# Reverse proxy ke peeche sahi client IP lene ke liye (Render/Railway etc.)
if os.getenv("TRUST_PROXY", "").lower() in ("1", "true", "yes"):
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Scan history SQLite database file (Docker mein volume ke liye override ho sakta hai)
DB_PATH = os.getenv(
    "SCANS_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db"),
)

# In-memory rate limit buckets: {ip: [request_timestamps]}
_rate_lock = threading.Lock()
_rate_buckets = {}


def is_rate_limited(client_ip):
    """Simple sliding-window rate limiter. True = request block karo."""
    now = time.time()
    window = app.config["RATE_LIMIT_WINDOW"]
    limit = app.config["RATE_LIMIT_MAX"]

    with _rate_lock:
        recent = [t for t in _rate_buckets.get(client_ip, []) if now - t < window]
        if len(recent) >= limit:
            _rate_buckets[client_ip] = recent
            return True
        recent.append(now)
        _rate_buckets[client_ip] = recent
    return False


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                score INTEGER,
                verdict TEXT,
                report_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def save_scan(report):
    """Report ko DB mein save karke naya scan id return karta hai."""
    conn = get_db()
    try:
        cursor = conn.execute(
            """
            INSERT INTO scans (created_at, subject, sender, score, verdict, report_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                report["analyzed_at"],
                report["email"]["subject"],
                format_sender(report["email"]["from"]),
                report["risk"]["score"],
                report["risk"]["verdict"],
                json.dumps(report),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_scan(scan_id):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    finally:
        conn.close()


def format_sender(sender):
    """mailparser ka from_ list ko readable string mein convert karta hai."""
    if not sender:
        return ""
    parts = []
    for name, email in sender:
        parts.append(f"{name} <{email}>" if name else email)
    return ", ".join(parts)


def get_history(limit=50):
    conn = get_db()
    try:
        return conn.execute(
            """
            SELECT id, created_at, subject, sender, score, verdict
            FROM scans ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()


init_db()


@app.errorhandler(413)
def file_too_large(error):
    return render_template(
        'index.html',
        error="File too large. Maximum allowed size is 5 MB.",
    ), 413

# URL dhoondhne ke liye simple regex (http/https se shuru hone wale links)
URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
# IPv4 address dhoondhne ke liye regex
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# Authentication-Results se spf=/dkim=/dmarc= ki value nikalne ke liye
AUTH_RE = re.compile(r'\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)', re.IGNORECASE)


def extract_urls(parsed_mail):
    """
    Email ke text/plain aur text/html body se saare URLs nikalta hai.

    Note: mail-parser 4.x mein .urls attribute hata diya gaya hai, isliye
    hum khud regex se nikaal rahe hain. text_plain/text_html lists hote hain.
    """
    urls = []
    bodies = list(parsed_mail.text_plain or []) + list(parsed_mail.text_html or [])
    for body in bodies:
        if not body:
            continue
        for match in URL_RE.findall(body):
            # URL ke end mein aane wali punctuation hata dete hain
            urls.append(match.rstrip('.,;:!?'))

    # Duplicate hata ke order maintain karte hain
    return list(dict.fromkeys(urls))


def parse_auth_results(parsed_mail):
    """
    Email authentication (SPF / DKIM / DMARC) ke results nikalta hai.

    SOC concept: hum khud SPF/DKIM verify nahi karte (uske liye DNS + crypto
    chahiye). Receiving mail server pehle hi check karke
    `Authentication-Results` header likh deta hai. Hum wahi padhte hain.

    Values: pass, fail, softfail, neutral, none, temperror, permerror.
    """
    auth_header = getattr(parsed_mail, "Authentication_Results", "") or ""
    received_spf = getattr(parsed_mail, "Received_SPF", "") or ""
    dkim_signature = getattr(parsed_mail, "DKIM_Signature", "") or ""

    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for mechanism, value in AUTH_RE.findall(auth_header):
        results[mechanism.lower()] = value.lower()

    # Fallback: kuch servers sirf Received-SPF dete hain, Authentication-Results nahi
    if results["spf"] == "none" and received_spf:
        spf_match = re.match(r'\s*([a-zA-Z]+)', received_spf)
        if spf_match:
            results["spf"] = spf_match.group(1).lower()

    results["dkim_signature_present"] = bool(dkim_signature)
    results["raw"] = auth_header or received_spf or "(no authentication headers found)"
    return results


def extract_sender_ips(parsed_mail):
    """
    Received headers se public (global) IPv4 addresses nikalta hai.

    SOC concept: har email ek relay chain se aata hai. Received headers
    batate hain kaunsa server se aaya. Hum sirf public IP rakhte hain
    kyunki private (192.168.x.x, 10.x.x.x) IPs internet par meaningful nahi.
    """
    ips = []
    for raw_header in (parsed_mail.received_raw or []):
        for ip in IPV4_RE.findall(raw_header):
            try:
                obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if obj.is_global:  # sirf public routable IPs
                ips.append(ip)
    return list(dict.fromkeys(ips))


def check_ip_abuseipdb(ip):
    """
    Ek IP ki reputation AbuseIPDB se check karta hai.
    abuseConfidenceScore: 0-100 (zyada = zyada malicious reports).
    """
    if not ABUSEIPDB_API_KEY:
        return {"ip": ip, "status": "AbuseIPDB API Key missing in .env"}

    api_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=15)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": ip,
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode") or "-",
                "isp": data.get("isp") or "-",
                "status": "Checked Successfully",
            }
        else:
            return {"ip": ip, "status": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"ip": ip, "status": f"Connection Error: {str(e)}"}


def hash_attachment(attachment):
    """
    Attachment ka SHA256 hash nikalta hai (file hash IOC).
    binary bytes ho to use karte hain, warna base64 payload decode karte hain.
    """
    data = attachment.get("binary")
    if not isinstance(data, (bytes, bytearray)):
        payload = attachment.get("payload")
        if isinstance(payload, str):
            try:
                # base64 padding add karke decode
                data = base64.b64decode(payload + "=" * (-len(payload) % 4))
            except Exception:
                data = b""
        else:
            data = b""

    if not data:
        return None
    return hashlib.sha256(data).hexdigest()


def check_hash_virustotal(sha256):
    """
    Attachment ke SHA256 hash ko VirusTotal par check karta hai.
    """
    if not VT_API_KEY:
        return {"sha256": sha256, "status": "VirusTotal API Key missing in .env"}

    api_url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(api_url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "sha256": sha256,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "status": "Scanned Successfully",
            }
        elif response.status_code == 404:
            return {"sha256": sha256, "status": "Hash not found in VT database (Might be brand new)"}
        else:
            return {"sha256": sha256, "status": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"sha256": sha256, "status": f"Connection Error: {str(e)}"}


def check_url_virustotal(url):
    """
    Yeh function ek URL ko VirusTotal API par check karta hai.
    """
    if not VT_API_KEY:
        return {"error": "VirusTotal API Key missing in .env"}
    
    # VirusTotal v3 API requirements ke mutabiq URL ko base64 encode karna padta hai
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(api_url, headers=headers, timeout=15)
        if response.status_code == 200:
            result = response.json()
            # Last analysis stats nikalna (malicious, harmless, suspicious)
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "status": "Scanned Successfully"
            }
        elif response.status_code == 404:
            return {"url": url, "status": "URL not found in VT database (Might be brand new)"}
        else:
            return {"url": url, "status": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"url": url, "status": f"Connection Error: {str(e)}"}


def calculate_risk(vt_results, ip_results, attachment_results, auth_results):
    """
    Saare findings ko points mein convert karke 0-100 risk score aur verdict.

    SOC concept: triage = multiple weak signals ko combine karke decision.
    Ek indicator alone false positive ho sakta hai, par kai indicators
    saath aayen to confidence badhta hai.

    Thresholds:
        70-100 -> Malicious
        40-69  -> Suspicious
        0-39   -> Safe / Low Risk
    """
    score = 0
    findings = []

    def add(points, text, severity):
        nonlocal score
        score += points
        findings.append({"points": points, "text": text, "severity": severity})

    # 1. URL reputation (VirusTotal)
    url_hits = [r for r in vt_results if r.get("malicious", 0) > 0]
    url_susp = [r for r in vt_results
                if r.get("malicious", 0) == 0 and r.get("suspicious", 0) > 0]
    if url_hits:
        add(40, f"{len(url_hits)} malicious URL(s) flagged by VirusTotal", "high")
    elif url_susp:
        add(20, f"{len(url_susp)} suspicious URL(s) flagged by VirusTotal", "medium")

    # 2. Attachment reputation (VirusTotal file hash)
    att_hits = [a for a in attachment_results
                if a.get("vt") and a["vt"].get("malicious", 0) > 0]
    att_susp = [a for a in attachment_results
                if a.get("vt") and a["vt"].get("malicious", 0) == 0 and a["vt"].get("suspicious", 0) > 0]
    if att_hits:
        add(50, f"{len(att_hits)} malicious attachment(s) flagged by VirusTotal", "high")
    elif att_susp:
        add(25, f"{len(att_susp)} suspicious attachment(s) flagged by VirusTotal", "medium")

    # 3. Sender IP reputation (AbuseIPDB)
    max_abuse = max([r.get("abuse_confidence", 0) for r in ip_results
                     if "abuse_confidence" in r], default=0)
    if max_abuse >= 75:
        add(25, f"Sender IP has high abuse confidence ({max_abuse}%)", "high")
    elif max_abuse >= 25:
        add(10, f"Sender IP has moderate abuse confidence ({max_abuse}%)", "medium")

    # 4. Email authentication (SPF / DKIM / DMARC)
    spf = auth_results.get("spf", "none")
    dkim = auth_results.get("dkim", "none")
    dmarc = auth_results.get("dmarc", "none")
    if dmarc == "fail":
        add(20, "DMARC check failed (domain not authenticated)", "high")
    elif dmarc == "softfail":
        add(10, "DMARC softfail", "medium")
    if spf in ("fail", "permerror"):
        add(10, "SPF check failed (unauthorized sending server)", "medium")
    elif spf == "softfail":
        add(5, "SPF softfail", "low")
    if dkim == "fail":
        add(10, "DKIM signature invalid", "medium")

    score = min(score, 100)
    if score >= 70:
        verdict, badge = "Malicious", "danger"
    elif score >= 40:
        verdict, badge = "Suspicious", "warning"
    else:
        verdict, badge = "Safe / Low Risk", "success"

    if not findings:
        findings.append({"points": 0, "text": "No threat indicators found", "severity": "info"})

    return {"score": score, "verdict": verdict, "badge": badge, "findings": findings}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_email():
    # Per-IP rate limit (demo abuse protection)
    if app.config.get("RATE_LIMIT_ENABLED", True):
        client_ip = request.remote_addr or "unknown"
        if is_rate_limited(client_ip):
            return render_template(
                'index.html',
                error="Too many requests. Please wait a minute and try again.",
            ), 429

    if 'email_file' not in request.files:
        return redirect(request.url)
    
    file = request.files['email_file']
    if file.filename == '':
        return redirect(request.url)

    # Sirf .eml files allow karte hain
    if not file.filename.lower().endswith('.eml'):
        return render_template('index.html', error="Only .eml email files are allowed.")

    if file:
        # Unique temp file banate hain taaki do users ke uploads clash na karein
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".eml")
        file_path = tmp.name
        tmp.close()

        try:
            file.save(file_path)

            # Parse email
            try:
                parsed_mail = mailparser.parse_from_file(file_path)
            except Exception as e:
                return render_template('index.html', error=f"Could not parse email file: {e}")

            subject = parsed_mail.subject
            sender = parsed_mail.from_
            date = parsed_mail.date
            urls = extract_urls(parsed_mail)
            sender_ips = extract_sender_ips(parsed_mail)
            attachments = parsed_mail.attachments or []
            auth_results = parse_auth_results(parsed_mail)
        finally:
            # File parse ho jaye ya fail ho, temp file hamesha delete karni hai
            if os.path.exists(file_path):
                os.remove(file_path)

        # API quota safety ke liye limited IOC scan karte hain
        urls_to_scan = urls[:MAX_URLS_TO_SCAN]
        ips_to_scan = sender_ips[:MAX_IPS_TO_SCAN]
        attachments_to_scan = attachments[:MAX_ATTACHMENTS_TO_SCAN]

        # Har ek extracted URL ko VirusTotal par check karna
        vt_results = [check_url_virustotal(u) for u in urls_to_scan]

        # Sender ke IPs ki reputation check karna
        ip_results = [check_ip_abuseipdb(ip) for ip in ips_to_scan]

        # Attachments ka hash nikal ke VirusTotal par check karna
        attachment_results = []
        for att in attachments_to_scan:
            sha256 = hash_attachment(att)
            attachment_results.append({
                "filename": att.get("safe_filename") or att.get("filename") or "(unknown)",
                "sha256": sha256,
                "vt": check_hash_virustotal(sha256) if sha256 else None,
            })

        # Saare findings ko combine karke final risk score + verdict
        risk = calculate_risk(vt_results, ip_results, attachment_results, auth_results)

        # Poora report ek dict mein (export aur history ke liye)
        report = {
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "email": {
                "subject": subject,
                "from": sender,
                "date": str(date) if date else None,
            },
            "authentication": auth_results,
            "urls": urls,
            "url_results": vt_results,
            "sender_ips": sender_ips,
            "ip_results": ip_results,
            "attachments": attachment_results,
            "risk": risk,
            "scan_limits": {
                "urls_total": len(urls),
                "urls_scanned": len(urls_to_scan),
                "ips_total": len(sender_ips),
                "ips_scanned": len(ips_to_scan),
                "attachments_total": len(attachments),
                "attachments_scanned": len(attachments_to_scan),
            },
        }
        scan_id = save_scan(report)

        # Result ko screen par display karna
        return render_template(
            'result.html',
            subject=subject,
            sender=sender,
            date=date,
            urls=urls,
            vt_results=vt_results,
            sender_ips=sender_ips,
            ip_results=ip_results,
            attachment_results=attachment_results,
            auth_results=auth_results,
            risk=risk,
            scan_id=scan_id,
        )


@app.route('/history')
def history():
    return render_template('history.html', scans=get_history())


@app.route('/report/<int:scan_id>/json')
def download_json(scan_id):
    row = get_scan(scan_id)
    if not row:
        return "Scan not found", 404

    response = app.response_class(row["report_json"], mimetype="application/json")
    response.headers["Content-Disposition"] = f"attachment; filename=phishing_report_{scan_id}.json"
    return response


@app.route('/report/<int:scan_id>/csv')
def download_csv(scan_id):
    row = get_scan(scan_id)
    if not row:
        return "Scan not found", 404

    report = json.loads(row["report_json"])
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Field", "Value"])
    writer.writerow(["Scan ID", scan_id])
    writer.writerow(["Analyzed At", report["analyzed_at"]])
    writer.writerow(["Subject", report["email"]["subject"]])
    writer.writerow(["From", format_sender(report["email"]["from"])])
    writer.writerow(["Score", report["risk"]["score"]])
    writer.writerow(["Verdict", report["risk"]["verdict"]])
    writer.writerow([])
    writer.writerow(["Type", "Indicator", "Detail", "Malicious", "Suspicious", "Status"])

    for r in report["url_results"]:
        writer.writerow(["URL", r.get("url", ""), "", r.get("malicious", ""),
                         r.get("suspicious", ""), r.get("status", "")])
    for r in report["ip_results"]:
        writer.writerow(["IP", r.get("ip", ""), r.get("isp", ""), "",
                         r.get("abuse_confidence", ""), r.get("status", "")])
    for a in report["attachments"]:
        vt = a.get("vt") or {}
        writer.writerow(["Attachment", a.get("filename", ""), a.get("sha256") or "",
                         vt.get("malicious", ""), vt.get("suspicious", ""), vt.get("status", "")])

    response = app.response_class(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=phishing_report_{scan_id}.csv"
    return response


if __name__ == '__main__':
    # Production ke liye waitress (Windows-compatible WSGI server).
    # Local dev ke liye bhi same command: python app.py
    port = int(os.getenv("PORT", "5000"))
    try:
        from waitress import serve

        print(f"Serving on http://0.0.0.0:{port}")
        serve(app, host="0.0.0.0", port=port)
    except ImportError:
        # waitress install nahi hai to Flask dev server (debug OFF)
        print("waitress not installed, falling back to Flask server (debug off)")
        app.run(host="0.0.0.0", port=port, debug=False)