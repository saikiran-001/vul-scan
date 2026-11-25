# Scanning logic

This document is deliverable 3 of the brief: **exactly what VulnScan Lite looks
for, why it matters, and how the score is produced.** If you are reviewing the
project, this file answers "is the scanner doing something sensible, or is it
guessing?"

---

## 1. The one rule: passive only

A scan consists of:

1. **one HTTP GET** to the final URL (redirects are followed manually, max 3),
2. **one TLS handshake** on port 443,
3. local analysis of the response we already received.

There is no fuzzing, no payload injection, no login attempt, no directory
brute-force and no exploitation. That keeps the tool legal to run and safe for
the target. It also means the tool **cannot** find vulnerabilities that require
authentication or active testing -- and it never claims to.

Before any request, `scanner/url_guard.py`:

* accepts only `http` / `https`,
* rejects URLs containing credentials (`user:pass@host`),
* rejects URLs with an invalid port (for example `:99999` or `:abc`),
* lower-cases the hostname so `EXAMPLE.com` and `example.com` are one site,
* resolves the hostname and rejects **loopback, private, link-local, reserved,
  multicast and unspecified** addresses,
* repeats the same validation on every redirect hop.

One deliberate exception: **NAT64** addresses (`64:ff9b::/96`) are globally
routable IPv6 addresses that wrap an IPv4 address. Python flags them as
"reserved", which produced false "non-public address" errors on real websites.
The guard therefore inspects the embedded IPv4 address instead -- so
`64:ff9b::59fd:ed5e` (a public host) is allowed, while `64:ff9b::7f00:1`
(which wraps `127.0.0.1`) is still blocked.

That is SSRF protection: without it, `http://127.0.0.1:8000/` or the cloud
metadata address `169.254.169.254` would let an attacker use our server to
reach internal systems.

---

## 2. Module 1 -- security headers

Source: `scanner/headers_check.py`

### Required headers (the brief's three)

| Header | What it prevents | Weight |
|--------|------------------|--------|
| `Content-Security-Policy` | Cross-site scripting (XSS): injected scripts cannot run or load external code. | ±10 |
| `X-Frame-Options` | Clickjacking: another site cannot embed yours in a hidden iframe. | ±10 |
| `Strict-Transport-Security` | Protocol downgrade / SSL-stripping: the browser refuses plain HTTP for this domain. | ±10 |

Grading follows the brief literally: the module starts at **50 points**, adds
**+10 for each header present**, and subtracts **-10 for each one missing**.

### Bonus headers (not required by the brief)

| Header | What it prevents | Weight |
|--------|------------------|--------|
| `X-Content-Type-Options: nosniff` | MIME sniffing: an uploaded file cannot be executed as JavaScript. | +5 |
| `Referrer-Policy` | Leaking full URLs (and tokens inside them) to third parties. | +5 |
| `Permissions-Policy` | Third-party scripts silently using camera / microphone / location. | +5 |

### Quality warnings (points kept, status becomes "Warning")

The header is present, but configured weakly:

* **HSTS** with `max-age` below `15552000` seconds (6 months), or with no
  `max-age` at all.
* **CSP** containing `'unsafe-inline'`, which re-allows injected inline scripts.
* **X-Frame-Options** with a value other than `DENY` / `SAMEORIGIN`.

### HTTPS

`+5` when the final URL is `https://`. A site on plain HTTP also fails the SSL
module, so the penalty is real, not cosmetic.

**Range:** 0 to 100 (50 baseline + 30 required + 15 bonus + 5 HTTPS).

---

## 3. Module 2 -- SSL / TLS

Source: `scanner/ssl_check.py`

A verified handshake is attempted first with `ssl.create_default_context()`
plus the `certifi` CA bundle. If verification fails, a second unverified probe
still reads the protocol version and cipher, so the report can describe the
problem instead of giving up.

| Check | How it is measured | Points |
|-------|--------------------|--------|
| HTTPS available | TLS handshake succeeds on `host:443` | 25 |
| Certificate trusted | Chain validates against the CA store **and** the hostname matches | 30 |
| Certificate expiry | Days from `notAfter`: `>= 30` full, `7-29` half, `< 7` zero | 20 |
| TLS version | `TLSv1.3` full, `TLSv1.2` 12/15, older zero | 15 |
| Cipher strength | `sock.cipher()` secret bits `>= 128` and not RC4 | 10 |

**Range:** 0 to 100.

Notes:

* An expired certificate is reported as "certificate not trusted" because the
  chain validation fails first; the detail text includes the OpenSSL reason.
* If a site serves HTTP only, the module returns 0 with an explicit
  "could not open a TLS connection" finding.

---

## 4. Module 3 -- CMS detection

Source: `scanner/cms_check.py`

All detection uses the page we already downloaded -- no extra requests.

### Fingerprints

| CMS | Signals |
|-----|---------|
| WordPress | `<meta name="generator" content="WordPress 6.4.2">`, `X-Powered-By`, `/wp-content/`, `/wp-includes/`, `wp-json` |
| Drupal | `generator` meta, `X-Powered-By`, `/sites/default/files`, `Drupal.settings`, `data-drupal` |
| Joomla | `generator` meta, `X-Powered-By`, `/media/system/js/`, `com_content`, `joomla!` |

The first match wins, and the version is extracted with the regex
`(\d+)\.(\d+)(?:\.(\d+))?`.

### Version table

`KNOWN_LATEST` is a **snapshot** of the latest stable releases:

| CMS | Latest known |
|-----|--------------|
| WordPress | 6.8.2 |
| Drupal | 11.1.7 |
| Joomla | 5.2.3 |

In a real product this table would be refreshed daily from the vendor feed or a
CVE database. Update it in `scanner/cms_check.py` before a demo if the numbers
are stale.

### Scoring

| Situation | Points |
|-----------|--------|
| No known CMS found | 80 (no penalty: nothing to compare) |
| CMS found, version up to date | 80 |
| CMS found, version hidden | 55 |
| CMS found, version older than latest | 0 |
| Server header does **not** reveal a version | +20 |
| `Server: nginx/1.18.0` (version disclosed) | 0 for that check |

**Range:** 0 to 100.

---

## 5. Final score

Source: `scanner/scoring.py`

```
final = headers x 0.40 + ssl x 0.40 + cms x 0.20
```

Why these weights? TLS and headers affect every visitor and are fully under the
site owner's control; CMS version only matters if a CMS is used. Rounding is to
the nearest integer.

| Score | Grade | | Score | Grade |
|-------|-------|-|-------|-------|
| 93-100 | A | | 73-76 | C |
| 90-92 | A- | | 70-72 | C- |
| 87-89 | B+ | | 67-69 | D+ |
| 83-86 | B | | 63-66 | D |
| 80-82 | B- | | 60-62 | D- |
| 77-79 | C+ | | 0-59 | F |

---

## 6. What the scanner deliberately does **not** check

| Not checked | Why |
|-------------|-----|
| SQL injection, XSS payloads, RCE | Requires active testing; out of scope and unsafe without permission. |
| Login / authentication flows | Needs credentials; also not passive. |
| Open ports, service versions beyond `Server` | Port scanning is a different tool class and can be illegal without permission. |
| DNS / mail security (SPF, DKIM, DMARC) | Separate domain; a good "next module" exercise. |
| JavaScript-rendered content | We do not run a browser; only the initial HTML is analysed. |
| Cookie flags (`Secure`, `HttpOnly`, `SameSite`) | A natural fourth header check -- see the exercise below. |

---

## 7. Known limitations

* **DNS rebinding:** the hostname is validated once, then `requests` resolves it
  again. A malicious DNS server could return a public IP to our check and a
  private IP to the actual request. Production mitigation: connect to the
  validated IP directly (with the correct `Host` header and SNI), or run the
  scanner in a network namespace with no internal routes.
* **Single page:** only the submitted URL is fetched. Other pages may be
  configured differently.
* **Header values are trusted as text:** we do not execute the CSP to see
  whether it actually blocks anything.
* **Static version table:** see the CMS section above.
* **One request per scan:** no retries, so a transient network error becomes a
  failed scan (the UI shows the reason).

---

## 8. Adding your own check (exercise)

1. Add the finding to `scanner/headers_check.py` (or a new module in
   `scanner/`).
2. Add an entry to `scanner/remediation.py` keyed by the check `id` -- the
   engine attaches it automatically, and both the UI and the PDF will show it.
3. If the module is new, register it in `scanner/engine.py` and give it a
   weight in `scanner/scoring.py`.
4. Add a line to this document. That is the whole contract.

A good first exercise: **cookie security flags**. Parse `Set-Cookie` from
`fetch_result.headers`, check for `Secure`, `HttpOnly` and `SameSite`, and add
a `cookie` entry to the remediation database.
