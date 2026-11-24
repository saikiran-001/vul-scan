# VulnScan Lite

A **passive web vulnerability scanner** built for the Persevex Cybersecurity brief.
Enter a URL, get a security health report: a 0-100 score, a letter grade, every
passed/failed check, copy-paste fixes, and a downloadable PDF.

> **Only scan websites you own. This tool performs passive analysis only.**
> It makes one normal HTTP request and one TLS handshake. It never attacks,
> fuzzes, logs in, or exploits anything.

---

## Quick start (Windows PowerShell)

```powershell
cd C:\Users\saiki\OneDrive\Desktop\vulnscan-lite
python -m pip install -r requirements.txt
python run.py
```

Your browser opens at **http://127.0.0.1:8000**. Type a URL, press **Run scan**.

Full instructions, troubleshooting and how each screen works: **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.

---

## The four weeks, and where each one lives

| Week | Brief goal | Code | Verify with |
|------|-----------|------|-------------|
| **1** | Scanner core: fetch headers, check SSL, parse HTML, output JSON | `scanner/` | `python -m scanner.cli https://example.com` |
| **2** | Async architecture: Redis + Celery, `POST /api/scan`, `GET /api/scan/:id/status`, React frontend | `api/jobs.py`, `api/tasks.py`, `api/store.py`, `api/main.py` | `python week2_async_architecture/checkpoint.py` |
| **3** | Report interface: results page, 0-100 scoring, remediation database | `web/app.jsx`, `scanner/scoring.py`, `scanner/remediation.py` | `python week3_report_interface/checkpoint.py` |
| **4** | PDF export, scan history, rate limiting, polish | `api/pdf_report.py`, `api/history.py`, `api/auth.py`, `api/ratelimit.py` | `python week4_pdf_and_polish/checkpoint.py` |

Each `weekN_*/README.md` explains what that week added, which files to read in
what order, and the concept you should take away. The verification scripts talk
to the running server (start it first with `python run.py --no-open`).

---

## Project structure

```
vulnscan-lite/
├── run.py                     # one command to start the app
├── requirements.txt
├── scanner/                   # WEEK 1 -- the engine (no web code at all)
│   ├── models.py              #   shared data shapes (CheckResult, ScanResult)
│   ├── url_guard.py           #   SSRF protection: rejects private IPs
│   ├── fetch.py               #   the single safe HTTP request
│   ├── headers_check.py       #   Module 1: CSP, X-Frame-Options, HSTS
│   ├── ssl_check.py           #   Module 2: certificate, expiry, TLS, cipher
│   ├── cms_check.py           #   Module 3: WordPress/Drupal/Joomla detection
│   ├── scoring.py             #   weighted 0-100 score + letter grade
│   ├── remediation.py         #   WEEK 3 "how to fix it" database
│   ├── engine.py              #   runs the modules in order, reports progress
│   └── cli.py                 #   terminal interface for Week 1
├── api/                       # WEEKS 2-4 -- the web layer
│   ├── main.py                #   routes, static files, error handling
│   ├── jobs.py                #   enqueue + execute a scan (celery or thread)
│   ├── celery_app.py          #   Celery configuration
│   ├── tasks.py               #   the Celery task
│   ├── store.py               #   job status in Redis, with an in-memory fallback
│   ├── settings.py            #   all configuration in one place
│   ├── auth.py                #   register / login / bearer tokens
│   ├── history.py             #   SQLite: users, sessions, past scans
│   ├── ratelimit.py           #   sliding-window rate limit (429)
│   ├── pdf_report.py          #   ReportLab PDF generator
│   └── errors.py              #   ApiError -> {"detail": ...}
├── web/                       # WEEK 3 frontend (React, no build step)
│   ├── index.html
│   ├── app.jsx
│   ├── styles.css
│   └── vendor/                # React + Babel served locally (works offline)
├── week1_scanner_core/        # per-week notes + checkpoint script
├── week2_async_architecture/
├── week3_report_interface/
├── week4_pdf_and_polish/
├── docs/scanning-logic.md     # deliverable 3: what we look for and why
└── data/                      # created at runtime: vulnscan.db, reports/*.pdf
```

---

## How a scan works

```
Browser                Flask API                 Worker (Celery or thread)
   |  POST /api/scan       |                              |
   |---------------------->| validate URL (SSRF guard)     |
   |<--- 202 {id} ---------| create job in Redis           |
   |                       |------ enqueue -------------->|
   |  GET /status (2s)     |                              | fetch page (1 request)
   |---------------------->|                              | headers module
   |<-- {progress: 40} ----|                              | ssl module
   |                       |                              | cms module
   |<-- {progress: 100} ---|                              | score + grade
   |  GET /report.pdf      |                              |
   |---------------------->| generate PDF (cached)         |
```

The browser never waits for the scan: it polls, exactly as the brief requires.

### Scoring

```
final score = headers x 0.40 + ssl x 0.40 + cms x 0.20
```

* **Headers (0-100)** -- starts at 50. Each required header present `+10`,
  missing `-10` (the brief's rule). Bonus headers `+5`, HTTPS `+5`.
* **SSL/TLS (0-100)** -- HTTPS available 25, certificate trusted 30,
  expiry 20, TLS version 15, cipher strength 10.
* **CMS (0-100)** -- version up to date 80, server version disclosure 20.

Letter grades: `93+ A`, `90 A-`, `87 B+`, `83 B`, `80 B-`, `77 C+`, `73 C`,
`70 C-`, `67 D+`, `63 D`, `60 D-`, below 60 `F`.

Full details: [docs/scanning-logic.md](docs/scanning-logic.md).

---

## API

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/health` | version, queue mode, Redis status |
| `POST` | `/api/scan` | body `{"url": "..."}` -> `202 {id, status_url}` |
| `GET` | `/api/scan/<id>/status` | `queued` / `running` / `done` / `error` + progress + result |
| `GET` | `/api/scan/<id>/report.pdf` | PDF report (cached after first generation) |
| `POST` | `/api/auth/register` | body `{"email","password"}` -> `{token, user}` |
| `POST` | `/api/auth/login` | same body -> `{token, user}` |
| `GET` | `/api/auth/me` | requires `Authorization: Bearer <token>` |
| `GET` | `/api/history` | the logged-in user's scans |

Example with `curl` (or `Invoke-RestMethod` in PowerShell):

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
     -H "Content-Type: application/json" \
     -d "{\"url\": \"https://example.com\"}"
```

---

## Deliverables checklist (from the brief)

- [x] **GitHub repository** with a dedicated `/scanner` package and the API.
- [x] **Live application** with a prominent "only scan websites you own" banner.
- [x] **Scanning logic documentation** -- see `docs/scanning-logic.md`.
- [x] Async worker (Celery/Redis, with a thread fallback when Redis is absent).
- [x] Header / SSL / CMS modules with JSON output.
- [x] Gauge chart, pass/fail table, remediation snippets.
- [x] Polling status endpoint every 2 seconds.
- [x] PDF export.
- [x] Scan history for logged-in users.
- [x] Rate limiting.

---

## Safety and limitations (read this)

* **Passive only.** One GET request, no payloads, no authentication attempts.
* **SSRF protection.** `scanner/url_guard.py` resolves the hostname and rejects
  loopback, private, link-local, reserved, multicast and unspecified addresses,
  and re-checks every redirect hop.
* **Known limitation:** DNS rebinding (the name resolves to a public IP during
  our check, then to `127.0.0.1` when `requests` connects) is not fully solved.
  A production deployment should pin the validated IP, or run the scanner in a
  network namespace with no access to internal services.
* **Version table is a snapshot.** `scanner/cms_check.py` compares against
  hard-coded latest versions; a real product would refresh them daily.
* **Passive checks cannot prove a site is secure.** They detect common
  misconfigurations, not vulnerabilities that need authentication or active
  testing.

## Deploying

The Flask development server is fine for local use and a demo. For a public
deployment use a production WSGI server and put the worker in its own process:

```bash
# Windows
python -m pip install waitress
waitress-serve --listen=0.0.0.0:8000 api.main:app

# Linux
python -m pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 api.main:app

# Celery worker (separate terminal, needs Redis)
celery -A api.celery_app.celery_app worker --loglevel=info --pool=solo
```

Set `REDIS_URL` and `VULNSCAN_QUEUE=celery` in the environment to force the
queue path.
