# Deploying VulnScan Lite on Render

## The three fields Render asks for

When you create the Web Service, use exactly this:

| Field | Value |
|-------|-------|
| **Root Directory** | *(leave empty)* |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `python start.py` |

`start.py` runs gunicorn when it is installed and automatically falls back to
Flask's server when it is not, so a stale `requirements.txt` can no longer
produce `gunicorn: command not found`.

Equivalent explicit command (only after `gunicorn` is in `requirements.txt`):

```
gunicorn -w 1 --threads 8 --timeout 120 -b 0.0.0.0:$PORT api.main:app
```

### Root Directory -- when it is not empty

Render's "Root Directory" is the folder **inside your GitHub repo** that
contains `requirements.txt` and `run.py`.

* If the repo root already looks like this project (`api/`, `scanner/`, `web/`,
  `run.py`), leave it **empty**.
* If you pushed a parent folder, for example the repo contains
  `vulnscan-lite/requirements.txt`, then set it to `vulnscan-lite`.

You can see which one you have by opening the repo on GitHub: if
`requirements.txt` is visible on the first page, Root Directory is empty.

---

## Why exactly one worker

`-w 1 --threads 8` is not an accident:

* A scan runs in a **background thread** of the web process, and its status is
  kept in an **in-memory dict**.
* With `-w 2` or more, the browser's poll request can land on a different
  worker that has never heard of the scan, and you get `404 Scan not found`.
* Threads (not processes) still let the server handle the polling request while
  a scan is running.

If you want several workers, you must add Redis and switch to the Celery
worker (see below), because then the job status lives in Redis, shared by all
processes.

---

## Environment variables (Render → Environment)

| Key | Value | Why |
|-----|-------|-----|
| `PYTHON_VERSION` | `3.12.7` | The version this project was tested with. |
| `VULNSCAN_QUEUE` | `thread` | Use the built-in worker (no Redis needed). |
| `VULNSCAN_RATE_LIMIT` | `30` | Scans per hour per user/IP. |
| `VULNSCAN_DATA_DIR` | `/var/data` | **Only if** you attach a persistent disk (see below). |
| `VULNSCAN_TRUST_PROXY` | `1` | Optional. Already automatic on Render (any `RENDER*` variable enables it). Set it on other PaaS providers. |

Render injects `$PORT` automatically -- never hard-code 8000 in production.

`VULNSCAN_TRUST_PROXY` makes the app read the real client IP from
`X-Forwarded-For`. Without it every visitor looks like the proxy's IP, so the
rate limiter would treat the whole internet as a single user (30 scans per hour
in total). The app enables this automatically when it sees Render's
environment variables.

---

## Data does not survive a redeploy (by default)

Render's filesystem is ephemeral. Without a disk:

* accounts and scan history in `data/vulnscan.db` are lost on every deploy,
* generated PDFs are lost too.

To keep them:

1. Render → your service → **Disks** → Add Disk.
2. Mount path: `/var/data`, size 1 GB is plenty.
3. Add env var `VULNSCAN_DATA_DIR` = `/var/data`.

`api/settings.py` already reads that variable.

---

## Optional: real Celery + Redis

Only needed if you want the full queue architecture or more than one web
worker.

1. Create a **Key Value** (Redis) instance in Render, copy its internal URL.
2. On the web service set:
   * `REDIS_URL` = the internal Redis URL
   * `VULNSCAN_QUEUE` = `celery`
   * Start Command becomes:
     `gunicorn -w 2 --threads 4 --timeout 120 -b 0.0.0.0:$PORT api.main:app`
3. Create a second service of type **Background Worker**, same repo, with:
   * Build Command: `pip install -r requirements.txt`
   * Start Command: `celery -A api.celery_app.celery_app worker --loglevel=info --concurrency=2`
   * The same `REDIS_URL` variable.

---

## First deploy checklist

- [ ] Repo pushed to GitHub (the project folder, not the whole Desktop).
- [ ] `render.yaml` is at the repo root (optional -- it fills the form for you).
- [ ] Build Command and Start Command exactly as above.
- [ ] `PYTHON_VERSION=3.12.7`.
- [ ] After deploy, open `https://<your-service>.onrender.com/api/health`
      → should return `{"status":"ok", ...}`.
- [ ] Open the site, run one scan, click **Download PDF**.
- [ ] The disclaimer banner must stay visible.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `bash: line 1: gunicorn: command not found` | The deployed repo's `requirements.txt` has no `gunicorn`. Either set Start Command to `python start.py`, or add `gunicorn>=21.2` to `requirements.txt`, push, then **Manual Deploy → Clear build cache & deploy**. |
| Build fails on `reportlab` | Set `PYTHON_VERSION` to `3.12.7` and redeploy (clear build cache). |
| Site loads, but scans stay at 0% | Start Command has more than one worker (`-w 2`+). Use `-w 1`. |
| `404 Scan not found` while polling | Same cause: multiple workers with the in-memory store. |
| Free instance is slow on first visit | Render free services sleep after inactivity; the first request wakes it (~30s). |
| History is empty after a redeploy | No persistent disk attached (see above). |
| `502 Bad Gateway` | Check the Render logs: usually a Python import error at startup. |

---

## Quick local check before deploying

```powershell
cd C:\Users\saiki\OneDrive\Desktop\vulnscan-lite
python -m pip install -r requirements.txt
python -m scanner.cli https://example.com     # engine works
python run.py                                  # UI works
```
