# Week 1 -- The Scanner Core

> **Goal:** the scripts. Write the Python functions to fetch headers, check SSL
> and parse HTML, and output the results as a JSON object.

This week has **no web server**. Everything here can be run from a terminal.

---

## What was built

| File | Responsibility |
|------|----------------|
| `scanner/models.py` | The data shapes: `CheckResult`, `ModuleResult`, `ScanResult`, `ScanError`. |
| `scanner/url_guard.py` | SSRF protection: URL normalisation + private-IP rejection. |
| `scanner/fetch.py` | The single safe HTTP request (redirects, size cap, timeout, TLS retry). |
| `scanner/headers_check.py` | Module 1: CSP, X-Frame-Options, HSTS (+ 3 bonus headers, HTTPS). |
| `scanner/ssl_check.py` | Module 2: certificate trust, expiry, TLS version, cipher. |
| `scanner/cms_check.py` | Module 3: CMS fingerprint + version comparison + server disclosure. |
| `scanner/scoring.py` | Weighted 0-100 score and letter grade. |
| `scanner/remediation.py` | The "how to fix it" database (used from Week 3 onward). |
| `scanner/engine.py` | Runs the three modules in order, survives module crashes, emits progress. |
| `scanner/cli.py` | Terminal interface and the Week 1 deliverable: JSON output. |

---

## The flow, in order

```
url_guard.assert_url_is_public()
        |
        v
fetch.safe_get()  ------------------> one HTTP response
        |                                      |
        |                                      +--> headers_check.run()
        |                                      +--> ssl_check.run()
        |                                      +--> cms_check.run()
        v
scoring.overall_score() + grade_for()
        |
        v
ScanResult.to_dict()  ----------------> JSON
```

Each module receives the same `FetchResult`, so the network is touched once.

---

## Run it

```powershell
# human-readable report
python -m scanner.cli https://example.com

# the exact JSON the API will return later
python -m scanner.cli https://example.com --json

# include remediation snippets
python -m scanner.cli https://example.com --show-fixes
```

Example (shortened):

```
 Score : 70/100   Grade: C-
 HTTP  : 200   Server: cloudflare

-- Security Headers (25/100) --------------------
  [FAIL] Content-Security-Policy (CSP)
         Header is missing. ...
  [ OK ] HTTPS enabled

-- SSL / TLS (100/100) --------------------------
  [ OK ] Certificate trusted
  [ OK ] TLS version  (TLSv1.3)

-- CMS Detection (100/100) ----------------------
  [INFO] CMS version
```

---

## Concepts you should be able to explain afterwards

1. **Security headers are server instructions to the browser.** They are not
   enforced by the server; the browser is the one that obeys them.
2. **`ssl.create_default_context()`** does three jobs at once: loads the CA
   store, enables hostname checking and disables obsolete protocols.
3. **`getpeercert()` returns a dict**, not an object; `notAfter` is a string in
   a very specific format, which is why `ssl.cert_time_to_seconds()` exists.
4. **BeautifulSoup turns HTML into a tree** you can query
   (`soup.find("meta", ...)`), which is far safer than regexing raw HTML.
5. **A dataclass is a typed dict.** Converting it with `asdict()` is what makes
   the JSON output trivial.
6. **SSRF** is the reason `url_guard.py` exists: a scanner is an HTTP client
   controlled by strangers, which is exactly the shape of an SSRF gadget.

---

## Checkpoint

```powershell
python week1_scanner_core\checkpoint.py
python week1_scanner_core\checkpoint.py https://your-own-site.com
```

The script asserts that the result has the expected keys, three modules, a
score in range and remediation attached to every check.

---

## Exercises

1. Add a `Cookie` check: look at `Set-Cookie`, require `Secure`, `HttpOnly` and
   `SameSite`. Add its remediation entry.
2. Make `--json` pretty-print with sorted keys and compare the output to
   `/api/scan/<id>/status` from Week 2.
3. Add `--timeout` validation (reject values above 30) and explain why a very
   long timeout is dangerous for a queue worker.
