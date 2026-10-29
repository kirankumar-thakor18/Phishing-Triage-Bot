import io
import sys
import json
import base64
import pathlib

import pytest

# Project root ko sys.path mein daalte hain taaki `import app` chale
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import app as app_module  # noqa: E402


def build_eml(subject="Test Email", body="Hello world", extra_headers="", attachment_bytes=None):
    parts = [
        "From: Attacker <attacker@evil.com>\r\n",
        "To: victim@company.com\r\n",
        f"Subject: {subject}\r\n",
        "Date: Mon, 29 Oct 2026 10:00:00 +0000\r\n",
        extra_headers,
    ]

    if attachment_bytes is None:
        parts.append("Content-Type: text/plain\r\n\r\n")
        parts.append(body + "\r\n")
    else:
        b64 = base64.b64encode(attachment_bytes).decode()
        parts.append("MIME-Version: 1.0\r\n")
        parts.append("Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n")
        parts.append("--XYZ\r\nContent-Type: text/plain\r\n\r\n")
        parts.append(body + "\r\n")
        parts.append("--XYZ\r\nContent-Type: application/octet-stream; name=sample.bin\r\n")
        parts.append("Content-Transfer-Encoding: base64\r\n")
        parts.append("Content-Disposition: attachment; filename=sample.bin\r\n\r\n")
        parts.append(b64 + "\r\n")
        parts.append("--XYZ--\r\n")

    return "".join(parts).encode()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "DB_PATH", str(tmp_path / "test_scans.db"))
    monkeypatch.setattr(app_module, "_rate_buckets", {})
    app_module.init_db()
    app_module.app.config.update(TESTING=True, RATE_LIMIT_ENABLED=False)
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.fixture
def mock_intel(monkeypatch):
    monkeypatch.setattr(
        app_module, "check_url_virustotal",
        lambda u: {"url": u, "malicious": 3, "suspicious": 0, "harmless": 20, "status": "Scanned"},
    )
    monkeypatch.setattr(
        app_module, "check_ip_abuseipdb",
        lambda ip: {"ip": ip, "abuse_confidence": 80, "total_reports": 5,
                    "country": "RU", "isp": "BadHost", "status": "Checked"},
    )
    monkeypatch.setattr(
        app_module, "check_hash_virustotal",
        lambda h: {"sha256": h, "malicious": 7, "suspicious": 0, "harmless": 2, "status": "Scanned"},
    )


# ---------- Unit tests ----------

def test_extract_urls_dedup():
    class FakeMail:
        text_plain = ["Visit http://evil.com/a and http://evil.com/a"]
        text_html = ['<a href="https://bad.com/x">click</a>']

    urls = app_module.extract_urls(FakeMail())
    assert urls == ["http://evil.com/a", "https://bad.com/x"]


def test_parse_auth_results():
    class FakeMail:
        Authentication_Results = "mx.corp.com; spf=pass; dkim=fail; dmarc=softfail"
        Received_SPF = ""
        DKIM_Signature = "v=1; b=fake"

    result = app_module.parse_auth_results(FakeMail())
    assert result["spf"] == "pass"
    assert result["dkim"] == "fail"
    assert result["dmarc"] == "softfail"
    assert result["dkim_signature_present"] is True


def test_parse_auth_results_fallback_to_received_spf():
    class FakeMail:
        Authentication_Results = ""
        Received_SPF = "softfail (domain does not designate)"
        DKIM_Signature = ""

    result = app_module.parse_auth_results(FakeMail())
    assert result["spf"] == "softfail"
    assert result["dkim_signature_present"] is False


def test_risk_malicious():
    risk = app_module.calculate_risk(
        vt_results=[{"url": "http://bad.com", "malicious": 5, "suspicious": 0}],
        ip_results=[{"ip": "1.1.1.1", "abuse_confidence": 90}],
        attachment_results=[{"filename": "a.exe", "vt": {"malicious": 10, "suspicious": 0}}],
        auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
    )
    assert risk["score"] == 100
    assert risk["verdict"] == "Malicious"
    assert risk["badge"] == "danger"


def test_risk_safe():
    risk = app_module.calculate_risk([], [], [], {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
    assert risk["score"] == 0
    assert risk["verdict"] == "Safe / Low Risk"


def test_risk_suspicious():
    risk = app_module.calculate_risk(
        vt_results=[{"url": "http://maybe.com", "malicious": 0, "suspicious": 3}],
        ip_results=[],
        attachment_results=[],
        auth_results={"spf": "pass", "dkim": "fail", "dmarc": "softfail"},
    )
    assert risk["verdict"] == "Suspicious"


# ---------- Endpoint / integration tests ----------

def test_rejects_non_eml(client):
    resp = client.post(
        "/analyze",
        data={"email_file": (io.BytesIO(b"hello"), "evil.txt")},
        content_type="multipart/form-data",
    )
    assert b"Only .eml" in resp.data


def test_analyze_saves_scan_and_renders(client, mock_intel):
    eml = build_eml(
        subject="Urgent Invoice",
        body="Pay here http://evil.com/pay",
        extra_headers=(
            "Received: from x (x [8.8.8.8])\r\n\tby mx.corp.com with ESMTP; "
            "Mon, 29 Oct 2026 10:00:00 +0000\r\n"
            "Authentication-Results: mx.corp.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        ),
        attachment_bytes=b"fake malware payload",
    )
    resp = client.post(
        "/analyze",
        data={"email_file": (io.BytesIO(eml), "sample.eml")},
        content_type="multipart/form-data",
    )
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "Verdict: Malicious" in html
    assert "Risk Findings" in html
    assert "evil.com" in html

    history = app_module.get_history()
    assert len(history) == 1
    assert history[0]["subject"] == "Urgent Invoice"


def test_history_page(client, mock_intel):
    client.post(
        "/analyze",
        data={"email_file": (io.BytesIO(build_eml(subject="Hist Test")), "a.eml")},
        content_type="multipart/form-data",
    )
    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"Hist Test" in resp.data


def test_json_and_csv_download(client, mock_intel):
    client.post(
        "/analyze",
        data={"email_file": (io.BytesIO(build_eml(body="http://bad.com/x")), "a.eml")},
        content_type="multipart/form-data",
    )
    scan_id = app_module.get_history()[0]["id"]

    json_resp = client.get(f"/report/{scan_id}/json")
    assert json_resp.status_code == 200
    report = json.loads(json_resp.get_data(as_text=True))
    assert report["risk"]["verdict"] in ("Malicious", "Suspicious", "Safe / Low Risk")
    assert "attachment" in json_resp.headers.get("Content-Disposition", "")

    csv_resp = client.get(f"/report/{scan_id}/csv")
    assert csv_resp.status_code == 200
    assert b"Type,Indicator,Detail" in csv_resp.data


def test_missing_report_returns_404(client):
    assert client.get("/report/99999/json").status_code == 404
    assert client.get("/report/99999/csv").status_code == 404


def test_rate_limit_blocks_after_limit(client, mock_intel, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setitem(app_module.app.config, "RATE_LIMIT_MAX", 2)
    monkeypatch.setattr(app_module, "_rate_buckets", {})

    eml = build_eml(subject="Rate Limit Test")
    for _ in range(2):
        resp = client.post(
            "/analyze",
            data={"email_file": (io.BytesIO(eml), "a.eml")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200

    blocked = client.post(
        "/analyze",
        data={"email_file": (io.BytesIO(eml), "a.eml")},
        content_type="multipart/form-data",
    )
    assert blocked.status_code == 429
    assert b"Too many requests" in blocked.data
