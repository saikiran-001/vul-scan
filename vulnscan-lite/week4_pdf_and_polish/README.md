# Week 4 -- PDF, History and Polish

> **Goal:** delivery. Build the PDF generator, add rate limiting (to prevent
> abuse) and finish deployment.

---

## What was built

| File | Responsibility |
|------|----------------|
| `api/pdf_report.py` | ReportLab PDF: score banner, module table, every check, remediation. |
| `api/history.py` | SQLite schema + `save_scan`, `list_scans`, `get_scan`. |
| `api/auth.py` | Register / login with PBKDF2, opaque bearer tokens. |
| `api/ratelimit.py` | Thread-safe sliding-window limiter -> HTTP 429 + `Retry-After`. |
| `api/main.py` | `/report.pdf`, `/api/auth/*`, `/api/history`. |
| `web/app.jsx` | Download button, login panel, history panel, score sparkline. |

---

## The PDF

ReportLab lays out **flowables** -- paragraphs, tables and spacers -- from top
to bottom, starting a new page automatically when one fills up. The generator
is fed the exact dict that `/status` returns, so the PDF can never disagree
with the web report.

Structure:

1. title + URL,
2. score banner (number, grade, timestamp, HTTP status, duration),
3. module table (score + weight + what it covers),
4. check table (status, finding) with a repeating header row,
5. "How to fix the findings" with a shaded code block per problem,
6. footer on every page: disclaimer + page number.

Generated files are cached in `data/reports/<scan-id>.pdf`; the second download
is instant.

---

## Accounts and history

The brief asks for scan history **for logged-in users**. The implementation is
deliberately small but not fake:

| Concern | Implementation |
|---------|----------------|
| Password storage | `hashlib.pbkdf2_hmac("sha256", ..., 200_000 rounds)` with a per-user random salt. Never the password itself. |
| Comparison | `hmac.compare_digest` (constant time). |
| Session | `secrets.token_urlsafe(32)`, stored in the `sessions` table, sent as `Authorization: Bearer ...`. |
| Email enumeration | Login returns the same message for unknown email and wrong password. |
| Storage | SQLite file `data/vulnscan.db`; scans keep the full JSON so old PDFs can be regenerated. |

History is attached to a scan **only when the request carried a valid token**.
Anonymous scans still work, they just are not saved.

---

## Rate limiting

A sliding window per user (or per IP when anonymous):

* keep the timestamps of recent scans in a `deque`,
* drop entries older than the window (default 1 hour),
* if the deque is full, return `429` with `Retry-After`.

A fixed counter would let someone send 30 scans at 12:59 and 30 more at 13:01;
a sliding window cannot be gamed that way. For multiple servers you would move
the deque into Redis (the code already has a Redis client available).

Default: **30 scans per hour** per user/IP. Change it with
`VULNSCAN_RATE_LIMIT` and `VULNSCAN_RATE_WINDOW`.

---

## Deployment checklist

- [ ] `python -m pip install -r requirements.txt` on the server.
- [ ] Run behind a production WSGI server (`waitress-serve` on Windows,
      `gunicorn` on Linux) instead of Flask's development server.
- [ ] Set `VULNSCAN_QUEUE=celery` and `REDIS_URL` for the real queue.
- [ ] Start the Celery worker as a separate service with `--pool=solo` on Windows.
- [ ] Put HTTPS in front (Caddy/nginx) so tokens are not sent in clear text.
- [ ] Back up `data/vulnscan.db`.
- [ ] Keep the disclaimer banner visible on the deployed page.
- [ ] Restrict outbound traffic from the scanner host (defence in depth
      against SSRF/DNS rebinding).

---

## Checkpoint

```powershell
python week4_pdf_and_polish\checkpoint.py
```

It creates a throwaway account, runs a scan with the token, verifies the scan
appears in history, downloads the PDF and checks the `%PDF` signature, and
confirms that history requires authentication.

---

## Exercises

1. **Delete a scan** from history (`DELETE /api/history/<id>`) with an ownership
   check -- the classic IDOR bug to avoid.
2. **Expire sessions**: add `expires_at` to the `sessions` table and reject old
   tokens.
3. **Better PDF**: add a bar chart of module scores using ReportLab's
   `graphics` module.
4. **Rate limit by route**: allow more status polls than new scans.
5. **CVE feed**: replace the static CMS version table with a daily refresh from
   the NVD API, and cache the response.
