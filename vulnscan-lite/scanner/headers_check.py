"""
headers_check.py -- Module 1 of the scanner (Week 1 deliverable).

WHAT IT DOES
------------
Security headers are instructions the server sends with every response.
They tell the browser: "only run scripts from me" (CSP), "never put me in a
frame" (X-Frame-Options), "always use HTTPS for a year" (HSTS), ...

The brief's grading rule is: +10 points when a header is present,
-10 when it is missing. We implement that literally on top of a 50-point
baseline, and add a few bonus headers so a perfect site can reach 100.

  required headers : 3 x 10  -> +30 when all present
  bonus headers    : 3 x 5   -> +15 when all present
  https            : +5
  baseline         : 50
  maximum          : 100
"""

from .models import CheckResult, ModuleResult, PASS, WARN, FAIL   # shared result types

# ---------------------------------------------------------------------------
# The three headers the brief asks for. Each entry is plain data, so adding a
# fourth required header later means adding one dict -- no new code.
# ---------------------------------------------------------------------------
REQUIRED_HEADERS = [
    {
        "id": "csp",
        "header": "Content-Security-Policy",
        "title": "Content-Security-Policy (CSP)",
        "why": "Limits which scripts/styles/frames the browser may load, blocking most XSS attacks.",
    },
    {
        "id": "xfo",
        "header": "X-Frame-Options",
        "title": "X-Frame-Options",
        "why": "Stops other sites from embedding yours in an <iframe> (clickjacking).",
    },
    {
        "id": "hsts",
        "header": "Strict-Transport-Security",
        "title": "Strict-Transport-Security (HSTS)",
        "why": "Forces the browser to use HTTPS for this domain, preventing downgrade attacks.",
    },
]

# Bonus headers: good practice, smaller weight, not required by the brief.
BONUS_HEADERS = [
    {
        "id": "xcto",
        "header": "X-Content-Type-Options",
        "title": "X-Content-Type-Options",
        "why": "Stops the browser from 'sniffing' a file into a different, executable type.",
    },
    {
        "id": "referrer",
        "header": "Referrer-Policy",
        "title": "Referrer-Policy",
        "why": "Controls how much URL information leaks to other sites via the Referer header.",
    },
    {
        "id": "permissions",
        "header": "Permissions-Policy",
        "title": "Permissions-Policy",
        "why": "Switches off browser features (camera, microphone, geolocation) you do not use.",
    },
]


def _short(value: str, limit: int = 160) -> str:
    """Header values can be huge; keep the report readable."""
    value = " ".join(value.split())          # collapse newlines/multiple spaces into single spaces
    if len(value) <= limit:                  # short enough already
        return value
    return value[: limit - 1] + "…"          # cut and add an ellipsis character


def _quality_warning(check_id: str, value: str) -> str:
    """Return a warning message when a header exists but is configured weakly."""

    lowered = value.lower()                                  # case-insensitive searching

    if check_id == "hsts":
        # HSTS must last at least 6 months (15552000 seconds) to be meaningful.
        import re                                            # local import keeps the module's top clean
        match = re.search(r"max-age\s*=\s*(\d+)", lowered)   # find max-age=123456
        if match:
            seconds = int(match.group(1))                    # convert the captured digits
            if seconds < 15552000:                           # less than ~180 days
                return f"HSTS max-age is only {seconds}s; 15552000s (6 months) or more is recommended."
        else:
            return "HSTS is present but has no max-age directive."

    if check_id == "csp":
        if "unsafe-inline" in lowered:                       # inline scripts weaken CSP a lot
            return "CSP contains 'unsafe-inline', which allows injected inline scripts."

    if check_id == "xfo":
        allowed = ("deny", "sameorigin")                     # the only two values modern browsers honour
        if not any(token in lowered for token in allowed):
            return "X-Frame-Options should be DENY or SAMEORIGIN."

    return ""                                                # no warning


def run(fetch_result) -> ModuleResult:
    """Analyse the response headers and build the headers module result."""

    headers = fetch_result.headers          # lower-case dict from fetch.py
    checks = []                             # we collect CheckResult objects here
    score = 50                              # the baseline from the grading rule

    # ---- required headers -------------------------------------------------
    for spec in REQUIRED_HEADERS:                       # loop over the three required specs
        value = headers.get(spec["header"].lower())     # header names are case-insensitive, keys are lower-case
        if value:                                       # header exists
            warning = _quality_warning(spec["id"], value)   # is it configured well?
            score += 10                                 # +10 for present
            checks.append(CheckResult(
                id=spec["id"],
                title=spec["title"],
                status=WARN if warning else PASS,       # present but weak -> yellow
                points=10,                              # earned the 10 points
                max_points=10,                          # out of 10
                detail=warning or spec["why"],          # explain the problem, or why it matters
                evidence=_short(value),                 # show the actual value
            ))
        else:                                           # header missing
            score -= 10                                 # -10 for missing, exactly like the brief
            checks.append(CheckResult(
                id=spec["id"],
                title=spec["title"],
                status=FAIL,
                points=0,
                max_points=10,
                detail=f"Header is missing. {spec['why']}",
                evidence="",
            ))

    # ---- bonus headers ----------------------------------------------------
    for spec in BONUS_HEADERS:                          # same pattern, smaller weight
        value = headers.get(spec["header"].lower())
        if value:
            score += 5                                  # +5 bonus
            checks.append(CheckResult(
                id=spec["id"], title=spec["title"], status=PASS,
                points=5, max_points=5,
                detail=spec["why"], evidence=_short(value),
            ))
        else:
            checks.append(CheckResult(
                id=spec["id"], title=spec["title"], status=WARN,
                points=0, max_points=5,
                detail=f"Optional hardening header missing. {spec['why']}",
                evidence="",
            ))

    # ---- HTTPS ------------------------------------------------------------
    if fetch_result.final_url.lower().startswith("https://"):
        score += 5                                      # HTTPS is the foundation of everything else
        checks.append(CheckResult(
            id="https", title="HTTPS enabled", status=PASS,
            points=5, max_points=5,
            detail="The final URL uses HTTPS.",
            evidence=fetch_result.final_url,
        ))
    else:
        checks.append(CheckResult(
            id="https", title="HTTPS enabled", status=FAIL,
            points=0, max_points=5,
            detail="The site is served over plain HTTP; all traffic can be read and modified.",
            evidence=fetch_result.final_url,
        ))

    score = max(0, min(100, score))                     # clamp into the valid 0-100 range

    return ModuleResult(
        id="headers",
        title="Security Headers",
        score=score,
        weight=0.40,                                    # headers are 40% of the final score
        checks=checks,
    )
