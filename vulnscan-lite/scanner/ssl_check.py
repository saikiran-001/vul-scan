"""
ssl_check.py -- Module 2 of the scanner (Week 1 deliverable).

WHAT IT DOES
------------
Opens a raw TLS connection (no HTTP) with Python's built-in `ssl` module and
inspects four things:

  1. Does HTTPS work at all?                (25 points)
  2. Is the certificate trusted?            (30 points)
  3. Is it far from expiring?               (20 points)
  4. Is the protocol/cipher modern?         (15 + 10 points)

`ssl.create_default_context()` is the important line: it uses the operating
system's trust store, checks the hostname, and refuses weak protocols. If that
connection succeeds, the certificate is genuinely valid for this hostname.
"""

import socket                 # low-level TCP connection
import ssl                    # TLS handshake, certificate parsing
from datetime import datetime, timezone   # to compute days until expiry
from urllib.parse import urlsplit         # to get host and port from the URL

from .models import CheckResult, ModuleResult, PASS, WARN, FAIL


def _connect(hostname: str, port: int, timeout: float, verify: bool) -> dict:
    """Open a TLS connection and return certificate + protocol information."""

    if verify:
        context = ssl.create_default_context()          # strict: system CA store + hostname check
        # On Windows, Python's default CA store is sometimes empty, which would
        # report every valid certificate as "untrusted". certifi ships the same
        # Mozilla bundle that requests uses, so load it explicitly.
        try:
            import certifi                              # installed as a dependency of requests
            context.load_verify_locations(certifi.where())   # add certifi's cacert.pem
        except Exception:
            pass                                        # no certifi -> keep the system store
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)   # manual context, because we skip checks
        context.check_hostname = False                  # do not compare the name
        context.verify_mode = ssl.CERT_NONE             # do not validate the chain

    with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:   # plain TCP first
        with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:   # upgrade to TLS
            # server_hostname is what makes SNI and hostname verification work.
            return {
                "cert": tls_sock.getpeercert(),          # dict of certificate fields (empty when unverified)
                "version": tls_sock.version(),           # "TLSv1.3", "TLSv1.2", ...
                "cipher": tls_sock.cipher(),             # (name, protocol, secret_bits)
            }


def _days_until_expiry(cert: dict) -> int:
    """Convert the certificate's notAfter field into a number of days."""

    not_after = cert.get("notAfter")                     # e.g. "Jun  1 12:00:00 2027 GMT"
    if not not_after:                                    # unverified certs expose no fields
        return -1                                        # -1 means "unknown"
    expires_at = ssl.cert_time_to_seconds(not_after)     # convert to a Unix timestamp
    now = datetime.now(timezone.utc).timestamp()         # current time, also Unix seconds
    return int((expires_at - now) // 86400)              # 86400 seconds per day


def run(final_url: str, timeout: float = 8.0) -> ModuleResult:
    """Inspect the TLS configuration of the scanned site."""

    parts = urlsplit(final_url)                  # split "https://example.com/x?y"
    hostname = parts.hostname or ""              # the host to connect to
    # A plain-http scan still probes 443 (the standard HTTPS port). An explicit
    # port in an https URL (e.g. :8443) must be respected, otherwise the module
    # would wrongly report "HTTPS unavailable".
    tls_port = (parts.port or 443) if parts.scheme == "https" else 443

    checks = []                                  # collected CheckResult objects
    score = 0                                    # SSL module starts at zero and earns points

    # ------------------------------------------------------------------
    # Attempt 1: a fully verified handshake.
    # ------------------------------------------------------------------
    info = None                                  # will hold the probe result
    trusted = False                              # assume untrusted until proven otherwise
    verify_error = ""                            # message for the report

    try:
        info = _connect(hostname, tls_port, timeout, verify=True)   # verified handshake
        trusted = True                                        # handshake + validation succeeded
    except ssl.SSLCertVerificationError as exc:               # expired, self-signed, wrong hostname...
        verify_error = str(exc)
    except (ssl.SSLError, socket.timeout, OSError) as exc:    # no TLS at all, or timeout
        verify_error = str(exc)

    # ------------------------------------------------------------------
    # Attempt 2: if verification failed, retry without it.
    # We still want to know the protocol version and cipher, and the site
    # may simply have an expired certificate that we should describe.
    # ------------------------------------------------------------------
    if info is None:
        try:
            info = _connect(hostname, tls_port, timeout, verify=False)   # insecure probe, read-only
        except (ssl.SSLError, socket.timeout, OSError):
            info = None                                            # HTTPS is completely unavailable

    # ------------------------------------------------------------------
    # Check 1: is HTTPS available? (25 points)
    # ------------------------------------------------------------------
    if info is None:
        checks.append(CheckResult(
            id="https", title="HTTPS available", status=FAIL,
            points=0, max_points=25,
            detail=f"Could not open a TLS connection to {hostname}:{tls_port}. {verify_error}",
            evidence="",
        ))
        # Nothing else can be measured without a TLS connection, so return early.
        return ModuleResult(id="ssl", title="SSL / TLS", score=0, weight=0.40, checks=checks)

    score += 25                                  # TLS handshake worked
    checks.append(CheckResult(
        id="https", title="HTTPS available", status=PASS,
        points=25, max_points=25,
        detail="The server completed a TLS handshake on port 443.",
        evidence=info["version"] or "",
    ))

    # ------------------------------------------------------------------
    # Check 2: is the certificate trusted? (30 points)
    # ------------------------------------------------------------------
    if trusted:
        score += 30
        checks.append(CheckResult(
            id="cert", title="Certificate trusted", status=PASS,
            points=30, max_points=30,
            detail="The certificate chain validates against the system trust store and matches the hostname.",
            evidence=_cert_subject(info["cert"]),
        ))
    else:
        checks.append(CheckResult(
            id="cert", title="Certificate trusted", status=FAIL,
            points=0, max_points=30,
            detail=f"Certificate validation failed: {verify_error}",
            evidence=_cert_subject(info["cert"]),
        ))

    # ------------------------------------------------------------------
    # Check 3: how long until it expires? (20 points)
    # ------------------------------------------------------------------
    days = _days_until_expiry(info["cert"])      # -1 when the certificate fields are unavailable

    if days < 0:
        checks.append(CheckResult(
            id="expiry", title="Certificate expiry", status=WARN,
            points=0, max_points=20,
            detail="Expiry date could not be read because the certificate is not trusted.",
            evidence="unknown",
        ))
    elif days < 7:
        checks.append(CheckResult(
            id="expiry", title="Certificate expiry", status=FAIL,
            points=0, max_points=20,
            detail=f"The certificate expires in {days} day(s). Browsers will soon show a warning.",
            evidence=f"{days} days",
        ))
    elif days < 30:
        score += 10                              # partial credit: renew soon
        checks.append(CheckResult(
            id="expiry", title="Certificate expiry", status=WARN,
            points=10, max_points=20,
            detail=f"The certificate expires in {days} days. Renew it now.",
            evidence=f"{days} days",
        ))
    else:
        score += 20                              # healthy
        checks.append(CheckResult(
            id="expiry", title="Certificate expiry", status=PASS,
            points=20, max_points=20,
            detail=f"The certificate is valid for another {days} days.",
            evidence=f"{days} days",
        ))

    # ------------------------------------------------------------------
    # Check 4: TLS protocol version (15 points)
    # ------------------------------------------------------------------
    version = info["version"] or "unknown"       # e.g. "TLSv1.3"

    if version == "TLSv1.3":
        score += 15
        checks.append(CheckResult(
            id="tls", title="TLS version", status=PASS,
            points=15, max_points=15,
            detail="TLS 1.3 is the newest and fastest protocol version.",
            evidence=version,
        ))
    elif version == "TLSv1.2":
        score += 12                              # still acceptable, slightly older
        checks.append(CheckResult(
            id="tls", title="TLS version", status=PASS,
            points=12, max_points=15,
            detail="TLS 1.2 is acceptable; TLS 1.3 is recommended.",
            evidence=version,
        ))
    else:
        checks.append(CheckResult(
            id="tls", title="TLS version", status=FAIL,
            points=0, max_points=15,
            detail=f"{version} is deprecated and considered insecure.",
            evidence=version,
        ))

    # ------------------------------------------------------------------
    # Check 5: cipher strength (10 points)
    # ------------------------------------------------------------------
    cipher_name, _protocol, bits = info["cipher"] or ("unknown", "", 0)   # tuple from sock.cipher()

    if bits >= 128 and "RC4" not in cipher_name.upper():
        score += 10
        checks.append(CheckResult(
            id="cipher", title="Cipher strength", status=PASS,
            points=10, max_points=10,
            detail="The negotiated cipher offers strong encryption.",
            evidence=f"{cipher_name} ({bits} bits)",
        ))
    else:
        checks.append(CheckResult(
            id="cipher", title="Cipher strength", status=FAIL,
            points=0, max_points=10,
            detail="The negotiated cipher is weak.",
            evidence=f"{cipher_name} ({bits} bits)",
        ))

    score = max(0, min(100, score))              # keep the score inside 0-100

    return ModuleResult(id="ssl", title="SSL / TLS", score=score, weight=0.40, checks=checks)


def _cert_subject(cert: dict) -> str:
    """Build a short readable summary of the certificate subject."""

    if not cert:                                  # unverified certificate -> no fields
        return "unverified certificate"
    subject = dict(item[0] for item in cert.get("subject", ()))   # ((('commonName','x'),),) -> dict
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    common_name = subject.get("commonName", "?")  # the name the certificate was issued for
    issuer_name = issuer.get("organizationName") or issuer.get("commonName", "?")
    return f"CN={common_name}, issuer={issuer_name}"
