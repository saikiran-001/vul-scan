# How to run and use VulnScan Lite

A complete walkthrough for Windows. No Node.js, no Redis and no Docker are
required to get started.

---

## 0. What you need

* **Python 3.10 or newer** -- you already have 3.15 on this machine.
* A terminal. On Windows, press `Win`, type **PowerShell**, press Enter.
* An internet connection for the scans themselves.

Check Python:

```powershell
python --version
```

If that prints `Python 3.x.x`, you are ready. If it opens the Microsoft Store,
install Python from python.org and tick **"Add python.exe to PATH"**.

---

## 1. One-time setup

Open PowerShell and go to the project folder:

```powershell
cd C:\Users\saiki\OneDrive\Desktop\vulnscan-lite
```

Install the dependencies (one time only):

```powershell
python -m pip install -r requirements.txt
```

You should see `Successfully installed ...`. Warnings about `Scripts` not being
on PATH are harmless -- we always run Python with `python -m ...`.

---

## 2. Start the app

```powershell
python run.py
```

You will see:

```
 __     __    _       ____ ...
  Only scan websites you own. This tool performs passive analysis only.

  Local URL   : http://127.0.0.1:8000
  API health  : http://127.0.0.1:8000/api/health

  Press Ctrl+C to stop the server.
```

**Your browser opens automatically** at `http://127.0.0.1:8000`.
If it does not, open it manually and paste the URL.

> Keep this PowerShell window open. Closing it stops the server.
> To stop it on purpose, click the window and press `Ctrl + C`.

Useful flags:

```powershell
python run.py --no-open          # do not open a browser
python run.py --port 9000        # use another port (http://127.0.0.1:9000)
python run.py --reload           # restart automatically when you edit Python code
```

---

## 3. Your first scan

On the page:

1. The URL box already contains `https://example.com`. You can type any site
   **you own or have permission to test**.
2. Click **Run scan**.
3. A progress bar appears and the page asks `/api/scan/<id>/status` every
   2 seconds. A real scan takes roughly 2-15 seconds.
4. When it finishes you get:
   * a **gauge** with the score and letter grade,
   * three **module cards** (Headers, SSL/TLS, CMS) with their own scores,
   * a list of every **check** with a green/amber/red pill.

### Reading a check

Click any row to expand it:

* **What we saw** -- the raw header value, cipher name, certificate subject...
* **Why it matters** -- the attack this misconfiguration enables.
* **How to fix** -- plain English plus a copy-paste snippet (nginx/Apache/WP-CLI).
* **Read the documentation** -- the official reference.

Example: a site missing `Content-Security-Policy` shows the exact nginx line to
add. That is the Week 3 "remediation database" in action.

---

## 4. Download the PDF

Click **Download PDF** in the score card.

The first click generates the file with ReportLab (about a second); later
clicks reuse the cached file in `data/reports/`. The PDF contains the score,
the module table, every check, and a "How to fix" section with the snippets.

---

## 5. Create an account and keep history

The account is only used to save your scan history in a local SQLite database.

1. In the top bar, type an email and a password (8+ characters).
2. Click **Create account** (first time) or **Log in** (later).
3. The button row changes to `your@email` + **Log out**.
4. Run a scan while logged in.
5. A **Your scan history** panel appears below the results, with:
   * each past score and grade,
   * the scan date,
   * a small line chart of your score over time,
   * a **PDF** button for every old scan.

The token is stored in your browser's `localStorage`; logging out removes it.

---

## 6. Run each week's milestone

These are the checkpoints you can show in a review.

**Week 1 -- scanner core (no server needed):**

```powershell
python -m scanner.cli https://example.com
python -m scanner.cli example.com --json
python -m scanner.cli example.com --show-fixes
```

`--json` prints the exact object the API returns. `--show-fixes` prints the
remediation snippets in the terminal.

**Weeks 2-4 -- with the server running** (`python run.py --no-open` in another
terminal):

```powershell
python week2_async_architecture\checkpoint.py
python week3_report_interface\checkpoint.py
python week4_pdf_and_polish\checkpoint.py
```

Each script checks that week's features and prints PASS/FAIL lines.

---

## 7. Optional: real Redis + Celery

The app works without Redis: it uses a background thread. To exercise the real
async architecture from the brief:

1. Install Redis for Windows (Memurai, or Redis in WSL/Docker).
2. Start it so `127.0.0.1:6379` answers.
3. In one terminal start the worker:

   ```powershell
   celery -A api.celery_app.celery_app worker --loglevel=info --pool=solo
   ```

   `--pool=solo` is required on Windows (Celery's default pool uses `fork`,
   which Windows does not have).

4. In another terminal start the web app:

   ```powershell
   $env:VULNSCAN_QUEUE = "celery"
   python run.py
   ```

5. The footer of the page now shows `queue: celery (Redis connected)`.

If Redis is not running, the app automatically falls back to the thread worker
so it never breaks.

---

## 8. Stop the server

Click the PowerShell window that runs the server and press `Ctrl + C`.
If the port stays busy, find and stop the process:

```powershell
Get-NetTCPConnection -LocalPort 8000 | Select-Object OwningProcess
Stop-Process -Id <the id from above>
```

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `python` is not recognized | Install Python from python.org and enable "Add to PATH", or use the `py` launcher. |
| `ModuleNotFoundError: flask` | You skipped step 1. Run `python -m pip install -r requirements.txt`. |
| Port 8000 already in use | `python run.py --port 9000` and open the new URL. |
| Browser shows "can't reach this page" | The server window was closed, or you used a different port. Check the printed URL. |
| Scan fails with "Could not resolve" | The domain is wrong, or your internet/DNS is down. |
| Scan fails with "non-public address" | That is the SSRF guard working: `localhost`, `192.168.*`, `10.*` etc. are blocked on purpose. |
| "Certificate validation failed" for a site that loads in your browser | The site has a broken chain; open it and check the padlock. The report is telling the truth. |
| PDF button says "Could not generate the PDF" | Look at the server window; usually ReportLab was not installed. |
| Everything works but there is no history | You must be logged in **before** starting the scan. |
| `celery` worker crashes on Windows | Add `--pool=solo`. |

---

## 10. Where the data lives

| Path | Contents |
|------|----------|
| `data/vulnscan.db` | users, sessions, saved scans (SQLite) |
| `data/reports/*.pdf` | generated PDFs (safe to delete) |
| browser `localStorage` | your login token |

To reset everything: stop the server, delete the `data` folder, start again.
The tables are recreated automatically.

---

## 11. What to learn next (reading order)

1. `scanner/fetch.py` -- how one safe HTTP request is made.
2. `scanner/headers_check.py` -- the simplest check module.
3. `scanner/ssl_check.py` -- talking TLS with the `ssl` module.
4. `scanner/engine.py` -- how modules are combined and scored.
5. `api/jobs.py` -- the queue abstraction (Celery vs thread).
6. `api/main.py` -- the HTTP API and polling pattern.
7. `web/app.jsx` -- React state + the 2-second polling effect.
8. `api/pdf_report.py` -- turning JSON into a PDF.

Every line in those files has a comment explaining what it does and why.
