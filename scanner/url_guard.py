"""
url_guard.py -- the "do not let our scanner become a weapon" module.

WHY THIS FILE EXISTS (SSRF protection)
--------------------------------------
Our server makes HTTP requests to a URL chosen by the user. Without checks,
an attacker could submit http://127.0.0.1:8000/ or http://169.254.169.254/
(the cloud metadata endpoint) and use OUR server to reach internal systems.
That attack is called SSRF: Server-Side Request Forgery.

So before any request we:
  1. clean the URL the user typed into a real http(s) URL,
  2. resolve the hostname to IP addresses,
  3. reject every address that is private / loopback / link-local / reserved.
"""

import ipaddress          # standard library that knows what "private IP" means
import socket             # used to turn a hostname into IP addresses (DNS lookup)
from urllib.parse import urlsplit, urlunsplit   # safe URL splitting/joining

from .models import ScanError                   # our own error type (the . means "same package")


# Hostnames that are dangerous even before DNS resolution happens.
BLOCKED_HOSTNAMES = {
    "localhost",              # always the local machine
    "localhost.localdomain",  # common Linux alias for localhost
    "metadata.google.internal",   # GCP metadata service alias
    "instance-data",          # AWS EC2 legacy metadata alias
}


def normalize_url(raw: str) -> str:
    """Turn what the user typed into a clean, absolute http(s) URL."""

    value = (raw or "").strip()                      # remove accidental spaces/newlines from copy-paste
    if not value:                                    # empty input -> nothing we can scan
        raise ScanError("Please enter a URL.", code="empty_url")

    if "://" not in value:                           # "myblog.com" has no scheme
        value = "https://" + value                   # default to HTTPS (the safer assumption)

    parts = urlsplit(value)                          # split into scheme / netloc / path / query
    scheme = parts.scheme.lower()                    # normalise HTTP vs http
    if scheme not in ("http", "https"):              # file://, ftp://, gopher:// are all rejected
        raise ScanError("Only http:// and https:// URLs can be scanned.", code="bad_scheme")

    hostname = (parts.hostname or "").strip().lower()   # .hostname strips the port and lowercases
    if not hostname:                                     # "https:///path" has no host
        raise ScanError("That URL has no hostname.", code="bad_url")

    if "@" in parts.netloc:                          # user:pass@host tricks can hide the real host
        raise ScanError("URLs containing credentials are not allowed.", code="bad_url")

    # Rebuild the URL from validated pieces. urlunsplit keeps path/query intact
    # but guarantees the scheme and host we just approved.
    cleaned = urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))   # drop the #fragment: servers never see it
    return cleaned


def resolve_public_ips(hostname: str) -> list:
    """Return every IP address the hostname points to, after rejecting unsafe ones."""

    if hostname in BLOCKED_HOSTNAMES:                                  # cheap check first
        raise ScanError(f"Refusing to scan internal host '{hostname}'.", code="blocked_host")

    try:
        # getaddrinfo returns IPv4 and IPv6 records: [(family, type, proto, canon, sockaddr), ...]
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:                                     # DNS said "no such host"
        raise ScanError(f"Could not resolve '{hostname}': {exc}", code="dns_error") from exc

    addresses = []                                    # we collect the unique IPs here
    for info in infos:                                # one entry per record
        ip_text = info[4][0]                          # sockaddr[0] is the IP string
        if ip_text in addresses:                      # skip duplicates (getaddrinfo often repeats)
            continue
        addresses.append(ip_text)

    if not addresses:                                 # a hostname that resolves to nothing is unusable
        raise ScanError(f"'{hostname}' did not resolve to any address.", code="dns_error")

    for ip_text in addresses:                         # inspect every single address
        ip = ipaddress.ip_address(ip_text)            # parse "10.0.0.5" or "::1" into an object
        # Any of these flags means the address belongs to an internal network or
        # a special range that a public scanner must never touch.
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ScanError(
                f"'{hostname}' resolves to the non-public address {ip_text}. "
                "Only publicly reachable websites can be scanned.",
                code="blocked_ip",
            )

    return addresses                                  # safe: every address is public


def assert_url_is_public(url: str) -> str:
    """Validate a URL end-to-end. Returns the cleaned URL, raises ScanError otherwise."""

    cleaned = normalize_url(url)                      # step 1: syntax + scheme
    hostname = urlsplit(cleaned).hostname or ""       # step 2: extract the host again
    resolve_public_ips(hostname)                      # step 3: DNS + IP range checks (raises if unsafe)
    return cleaned                                    # caller may now request this URL
