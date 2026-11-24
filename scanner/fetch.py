"""
fetch.py -- the single HTTP request that every check depends on.

WHY THIS FILE EXISTS
--------------------
The brief says the scan must be PASSIVE: one normal GET request, no payloads,
no fuzzing, no login attempts. This module performs that one request in the
safest way we can:

  * it validates every redirect hop against url_guard (SSRF),
  * it stops reading after 512 KB (a 2 GB file would freeze our server),
  * it uses a short timeout (a dead site must not block a worker forever),
  * if the TLS certificate is broken it remembers that fact and retries
    WITHOUT verification, so the header/CMS checks can still run.
"""

import time                                    # perf_counter gives a high-resolution stopwatch
import warnings                                # used to silence urllib3's "unverified HTTPS" warning

import requests                                # the friendly HTTP library
from urllib.parse import urljoin               # turns "/login" into "https://site.com/login"

from .url_guard import assert_url_is_public    # our SSRF guard
from .models import ScanError                  # our error type

# Identify ourselves honestly. Some sites block unknown clients; that is fine,
# we then report what we can and explain the block in the result.
USER_AGENT = "VulnScanLite/1.0 (passive security check; +https://github.com/your-name/vulnscan-lite)"

MAX_BODY_BYTES = 512 * 1024     # 512 KB of HTML is more than enough to fingerprint a site
REDIRECT_CODES = (301, 302, 303, 307, 308)   # every HTTP status that means "look over there"


class FetchResult:
    """A tiny container for what the request produced. No dataclass needed."""

    def __init__(self, requested_url, final_url, status_code, headers, body,
                 redirects, tls_error, elapsed_ms):
        self.requested_url = requested_url    # what the user asked for
        self.final_url = final_url            # where we ended after redirects
        self.status_code = status_code        # HTTP status of the last response
        self.headers = headers                # dict with lower-case keys, so headers["x-frame-options"] always works
        self.body = body                      # first 512 KB of the HTML, decoded to text
        self.redirects = redirects            # list of URLs we visited
        self.tls_error = tls_error            # None, or the certificate error message
        self.elapsed_ms = elapsed_ms          # total request time


def _read_limited(response) -> bytes:
    """Read at most MAX_BODY_BYTES from a streaming response."""

    chunks = []                                   # collect raw bytes here
    total = 0                                     # how many bytes we have so far
    for chunk in response.iter_content(16 * 1024):   # 16 KB at a time keeps memory flat
        if not chunk:                             # keep-alive chunks can be empty
            continue
        chunks.append(chunk)                      # store the piece
        total += len(chunk)                       # update the counter
        if total >= MAX_BODY_BYTES:               # enough data -> stop downloading
            break
    return b"".join(chunks)[:MAX_BODY_BYTES]      # join and hard-cap the result


def _do_request(url: str, timeout: float):
    """One GET request with no redirect following. Returns (response, tls_error)."""

    tls_error = None                              # assume the certificate is fine

    try:
        # allow_redirects=False: WE follow redirects manually so that every hop
        # passes through our SSRF guard. verify=True checks the certificate chain.
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
            timeout=timeout,
            allow_redirects=False,
            stream=True,                          # body is downloaded lazily, under our control
            verify=True,
        )
    except requests.exceptions.SSLError as exc:
        # A broken/expired/self-signed certificate raises here.
        # We record the reason, then retry without verification so the rest of
        # the scan still works (the SSL module will report the failure properly).
        tls_error = str(exc)
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")   # silence urllib3 noise
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            verify=False,                         # insecure on purpose: we already know it is broken
        )

    return response, tls_error                    # hand both back to the caller


def safe_get(url: str, timeout: float = 8.0, max_redirects: int = 3) -> FetchResult:
    """Fetch a public URL safely and return everything the checks need."""

    started = time.perf_counter()                 # start the stopwatch
    current = assert_url_is_public(url)           # validate before the very first request
    redirects = []                                # history of URLs we visited
    tls_error = None                              # remember the first certificate problem we see

    for _hop in range(max_redirects + 1):         # a redirect loop cannot run forever
        redirects.append(current)                 # record this hop

        try:
            response, hop_tls_error = _do_request(current, timeout)   # the actual network call
        except requests.exceptions.Timeout as exc:
            raise ScanError(f"The site did not answer within {timeout:.0f}s.", code="timeout") from exc
        except requests.exceptions.ConnectionError as exc:
            raise ScanError(f"Could not connect to {current}: {exc}", code="connection_error") from exc
        except requests.exceptions.RequestException as exc:
            raise ScanError(f"Request failed: {exc}", code="request_error") from exc

        if hop_tls_error and not tls_error:       # keep the first TLS problem for the report
            tls_error = hop_tls_error

        location = response.headers.get("Location")   # present only on 3xx responses
        if response.status_code in REDIRECT_CODES and location:
            response.close()                      # we do not need this body
            # urljoin handles both absolute ("https://x/y") and relative ("/y") Locations.
            next_url = urljoin(current, location)
            current = assert_url_is_public(next_url)   # validate the NEW host before following it
            continue                              # go to the next loop iteration

        # Not a redirect -> this is our final response.
        raw = _read_limited(response)             # download at most 512 KB
        response.close()                          # release the socket immediately

        encoding = response.encoding or "utf-8"   # charset from Content-Type, fallback utf-8
        try:
            body = raw.decode(encoding, errors="replace")   # never crash on weird bytes
        except LookupError:
            body = raw.decode("utf-8", errors="replace")    # unknown charset name -> utf-8

        headers = {k.lower(): v for k, v in response.headers.items()}   # normalise keys once

        elapsed_ms = int((time.perf_counter() - started) * 1000)        # stop the stopwatch
        return FetchResult(
            requested_url=url,
            final_url=current,
            status_code=response.status_code,
            headers=headers,
            body=body,
            redirects=redirects,
            tls_error=tls_error,
            elapsed_ms=elapsed_ms,
        )

    raise ScanError("Too many redirects (more than 3).", code="too_many_redirects")
