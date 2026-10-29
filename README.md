# Phishing Triage & Threat Intelligence Bot

A Flask-based phishing email triage tool that automates the first steps a SOC analyst
performs on a suspicious email: parse it, extract IOCs, enrich them with threat
intelligence, check email authentication, and produce a risk verdict with a downloadable report.

> Educational / defensive security project. Use it only on emails you are authorized to analyze.

---

## Features

- **Email parsing** — extracts subject, sender, date, URLs, attachments and Received headers from `.eml` files.
- **URL intelligence** — checks extracted URLs against VirusTotal.
- **Attachment intelligence** — computes SHA256 hashes and checks them against VirusTotal.
- **Sender IP reputation** — extracts public IPs from `Received` headers and checks them with AbuseIPDB.
- **Email authentication** — parses SPF / DKIM / DMARC results from `Authentication-Results` (with `Received-SPF` fallback).
- **Risk scoring** — combines all indicators into a 0–100 score and a verdict (`Malicious` / `Suspicious` / `Safe`).
- **Explainable findings** — shows exactly which indicators contributed how many points.
- **Scan history** — stores every scan in SQLite.
- **Report export** — download reports as JSON or CSV.
- **Basic safety limits** — max upload size, `.eml`-only uploads, limited IOC scans per email.
- **Rate limiting** — per-IP request limit to protect API quota on public demos.
- **Production server** — runs with waitress (not the Flask dev server).

---

## How it works

```
.eml upload
    |
    v
mailparser  ->  subject / sender / date / URLs / attachments / Received headers
    |
    +--> URL extraction  ----------> VirusTotal (URLs)
    +--> Received headers ---------> AbuseIPDB (sender IPs)
    +--> Attachment bytes ---------> SHA256 -> VirusTotal (file hashes)
    +--> Auth headers -------------> SPF / DKIM / DMARC results
    |
    v
calculate_risk()  ->  score (0-100) + verdict + findings
    |
    +--> render result page
    +--> save to SQLite history
    +--> export JSON / CSV
```

---

## Project structure

```
phishing-triage-bot/
├── app.py                 # Flask app, parsing, enrichment, scoring, routes
├── templates/
│   ├── index.html         # Upload form
│   ├── result.html        # Analysis result + findings + downloads
│   └── history.html       # Past scans
├── tests/
│   └── test_app.py        # pytest unit + integration tests
├── requirements.txt       # Runtime dependencies
├── requirements-dev.txt   # Dev dependencies (pytest)
├── Dockerfile             # Container image (waitress, non-root user)
├── docker-compose.yml     # Compose stack (app + persistent data volume)
├── DOCKER_SETUP.md        # Docker setup guide (Windows)
├── .dockerignore          # Files excluded from the build context
├── .env.example           # Sample environment variables
└── README.md
```

---

## Risk scoring

| Indicator | Points | Severity |
|---|---|---|
| Malicious URL (VirusTotal) | +40 | HIGH |
| Suspicious URL (VirusTotal) | +20 | MED |
| Malicious attachment (VirusTotal) | +50 | HIGH |
| Suspicious attachment (VirusTotal) | +25 | MED |
| Sender IP abuse confidence >= 75% | +25 | HIGH |
| Sender IP abuse confidence 25–74% | +10 | MED |
| DMARC fail / softfail | +20 / +10 | HIGH / MED |
| SPF fail / softfail | +10 / +5 | MED / LOW |
| DKIM fail | +10 | MED |

Score is capped at 100.

| Score | Verdict |
|---|---|
| 70–100 | Malicious |
| 40–69 | Suspicious |
| 0–39 | Safe / Low Risk |

---

## Setup

### 1. Clone and create a virtual environment

```powershell
git clone <your-repo-url>
cd phishing-triage-bot
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
# for running tests:
pip install -r requirements-dev.txt
```

### 3. Configure API keys

```powershell
Copy-Item .env.example .env
```

Edit `.env` and add:

```
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
```

Get free keys from:
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AbuseIPDB: https://www.abuseipdb.com/account/api

### 4. Run the app

```powershell
python app.py
```

This starts a **waitress** WSGI server (production-style, debug off) on port 5000.
Set a different port with the `PORT` environment variable.

Open http://127.0.0.1:5000

---

## Docker (recommended for demo deployment)

Build and run with Docker:

```powershell
docker build -t phishing-bot .
docker run -p 5000:5000 --env-file .env -e SCANS_DB=/app/data/scans.db -v phishing_data:/app/data phishing-bot
```

Or with Docker Compose (reads `.env`, persists history in a named volume):

```powershell
docker compose up --build
```

Notes:
- API keys are **not** baked into the image. They are passed at runtime with `--env-file .env`.
- `SCANS_DB` points to `/app/data/scans.db`; the `phishing_data` volume keeps history across restarts.
- If you put the app behind a reverse proxy (Render/Railway/Fly), set `TRUST_PROXY=1` so the real client IP is used for rate limiting.
- The container runs as a non-root user and uses waitress instead of the Flask dev server.

---

## Usage

1. Upload a suspicious `.eml` file.
2. Review the verdict, risk score and findings.
3. Inspect URL, IP, attachment and authentication details.
4. Download the JSON/CSV report or view scan history.

---

## API / Routes

| Method | Route | Description |
|---|---|---|
| GET | `/` | Upload form |
| POST | `/analyze` | Analyze uploaded `.eml` |
| GET | `/history` | Scan history |
| GET | `/report/<id>/json` | Download JSON report |
| GET | `/report/<id>/csv` | Download CSV report |

---

## Testing

```powershell
.\venv\Scripts\python.exe -m pytest -q
```

Tests mock the external APIs, so no API calls or keys are needed to run them.

---

## Safety and limitations

> ⚠️ **Demo tool.** Do not upload real sensitive emails to a public deployment. Analysis results are stored in the scan-history database.

- This is a **portfolio/demo** project, not a hardened multi-user product. There is **no user authentication**.
- External API calls are subject to free-tier limits; the app scans a limited number of IOCs per email and applies a per-IP rate limit.
- Using free-tier VirusTotal/AbuseIPDB keys for a public multi-user service may violate their Terms of Service.
- SPF/DKIM/DMARC are **not** verified cryptographically by this app — it trusts the receiving mail server's `Authentication-Results` header.
- `Received` headers can be forged; IP reputation is one signal, not proof.
- The score is a heuristic aid for triage, not a replacement for analyst judgment.
- A "Safe" verdict means no known indicators were found, not that the email is guaranteed benign.
- SQLite is fine for a demo; a real multi-user deployment should use Postgres and a persistent volume.

---

## Tech stack

- Python 3, Flask
- mail-parser
- VirusTotal API v3, AbuseIPDB API v2
- SQLite
- waitress (WSGI server)
- Docker / Docker Compose
- Bootstrap 5
- pytest
