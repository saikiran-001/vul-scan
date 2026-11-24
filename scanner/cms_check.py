"""
cms_check.py -- Module 3 of the scanner (Week 1 deliverable).

WHAT IT DOES
------------
Figures out which Content Management System (WordPress, Drupal, Joomla) a
site runs, and whether that version is old. Old CMS versions are the single
most common way small sites get hacked, because the vulnerabilities are
public and the exploits are one Google search away.

HOW WE DETECT (all passive -- we only read the page we already downloaded):
  * <meta name="generator" content="WordPress 6.4.2">
  * the X-Powered-By response header
  * well-known file paths in the HTML, e.g. /wp-content/, /sites/default/
  * the Server header, to spot version disclosure ("nginx/1.18.0")

NOTE ON THE VERSION TABLE
-------------------------
The "latest" numbers below are a snapshot. In a real product you would fetch
them from the vendor's release feed (or a CVE database) once a day.
"""

import re                                            # regular expressions for version numbers

from bs4 import BeautifulSoup                        # HTML parser (installed as beautifulsoup4)

from .models import CheckResult, ModuleResult, PASS, WARN, FAIL, INFO

# Latest stable releases at the time this project was written.
# Compare a detected version against these tuples.
KNOWN_LATEST = {
    "wordpress": (6, 8, 2),
    "drupal": (11, 1, 7),
    "joomla": (5, 2, 3),
}

CMS_NAMES = {
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
}

# Text fragments that almost certainly mean "this site runs <CMS>".
BODY_MARKERS = {
    "wordpress": ("/wp-content/", "/wp-includes/", "wp-json"),
    "drupal": ("/sites/default/files", "drupal.settings", "data-drupal"),
    "joomla": ("/media/system/js/", "com_content", "joomla!"),
}

VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")   # matches 6.4.2 / 6.4 / 11.1


def _parse_version(text: str):
    """Find the first version-looking number in a string and return a tuple of ints."""

    match = VERSION_RE.search(text or "")             # search anywhere in the text
    if not match:                                     # no digits.version pattern
        return None
    parts = [int(p) for p in match.groups() if p is not None]   # ("6","4","2") -> [6,4,2]
    return tuple(parts)                               # hashable and comparable


def _version_is_older(detected: tuple, latest: tuple) -> bool:
    """Compare two version tuples, padding the shorter one with zeros."""

    length = max(len(detected), len(latest))          # compare equal lengths
    left = detected + (0,) * (length - len(detected))   # (6,4) -> (6,4,0)
    right = latest + (0,) * (length - len(latest))    # pad the other side too
    return left < right                               # tuple comparison is element by element


def _detect(soup, headers: dict, body_lower: str):
    """Return (cms_key, version_or_None, evidence) or None when nothing matches."""

    # ---- 1. <meta name="generator"> ------------------------------------
    generator_tag = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    generator = (generator_tag.get("content", "") if generator_tag else "").strip()
    if generator:
        lowered = generator.lower()                   # "WordPress 6.4.2" -> "wordpress 6.4.2"
        for key in CMS_NAMES:                         # check every CMS we know
            if key in lowered:                        # e.g. "wordpress" in the text
                return key, _parse_version(generator), f'meta generator: "{generator}"'

    # ---- 2. X-Powered-By header ----------------------------------------
    powered_by = headers.get("x-powered-by", "")      # e.g. "PHP/8.2.1" or "WordPress"
    lowered = powered_by.lower()
    for key in CMS_NAMES:
        if key in lowered:
            return key, _parse_version(powered_by), f'X-Powered-By: "{powered_by}"'

    # ---- 3. Body markers ------------------------------------------------
    for key, markers in BODY_MARKERS.items():         # CMS -> list of strings
        for marker in markers:                        # check each marker
            if marker in body_lower:                  # already lower-cased once
                return key, _parse_version(body_lower), f'HTML contains "{marker}"'

    return None                                       # no fingerprint found


def run(fetch_result) -> ModuleResult:
    """Analyse the downloaded HTML/headers and score the CMS posture."""

    soup = BeautifulSoup(fetch_result.body or "", "html.parser")   # parse HTML; never crashes on junk
    body_lower = (fetch_result.body or "").lower()                  # lower-case copy for cheap searches

    checks = []                                       # collected checks
    detected = _detect(soup, fetch_result.headers, body_lower)      # None or (key, version, evidence)

    # ------------------------------------------------------------------
    # Check 1: CMS version (80 points)
    # ------------------------------------------------------------------
    if detected is None:
        checks.append(CheckResult(
            id="cms", title="CMS version", status=INFO,
            points=80, max_points=80,
            detail="No known CMS fingerprint was found. Nothing to compare, so no penalty.",
            evidence="",
        ))
    else:
        key, version, evidence = detected             # unpack the detection
        name = CMS_NAMES[key]                         # "WordPress"
        latest = KNOWN_LATEST[key]                    # (6, 8, 2)

        if version is None:
            checks.append(CheckResult(
                id="cms", title="CMS version", status=WARN,
                points=55, max_points=80,             # partial credit: we know the CMS, not the version
                detail=f"{name} detected but the exact version is hidden. Hiding it is good, "
                       f"but you cannot confirm you are patched.",
                evidence=evidence,
            ))
        elif _version_is_older(version, latest):
            checks.append(CheckResult(
                id="cms", title="CMS version", status=FAIL,
                points=0, max_points=80,
                detail=f"{name} {'.'.join(map(str, version))} is older than the latest known "
                       f"{'.'.join(map(str, latest))}. Public exploits likely exist.",
                evidence=evidence,
            ))
        else:
            checks.append(CheckResult(
                id="cms", title="CMS version", status=PASS,
                points=80, max_points=80,
                detail=f"{name} {'.'.join(map(str, version))} is up to date.",
                evidence=evidence,
            ))

    # ------------------------------------------------------------------
    # Check 2: Server header version disclosure (20 points)
    # ------------------------------------------------------------------
    server = fetch_result.headers.get("server", "")   # e.g. "nginx/1.18.0" or "cloudflare"
    has_version = bool(re.search(r"\d+\.\d+", server))   # a version number is visible

    if has_version:
        checks.append(CheckResult(
            id="server", title="Server version disclosure", status=WARN,
            points=0, max_points=20,
            detail=f"The Server header reveals the software version ('{server}'). "
                   "Attackers use it to pick exploits. Turn off server_tokens in nginx.",
            evidence=server,
        ))
    else:
        checks.append(CheckResult(
            id="server", title="Server version disclosure", status=PASS,
            points=20, max_points=20,
            detail="The Server header does not reveal a version number.",
            evidence=server or "(no Server header)",
        ))

    score = sum(c.points for c in checks)             # 80 + 20 = 100 maximum
    score = max(0, min(100, score))                   # clamp

    return ModuleResult(
        id="cms",
        title="CMS Detection",
        score=score,
        weight=0.20,                                  # CMS is 20% of the final score
        checks=checks,
    )
