"""
engine.py -- the conductor of the scanner (Week 1 deliverable).

WHY THIS FILE EXISTS
--------------------
Each check module knows how to test ONE thing. Something has to put them in
the right order, share the single HTTP response between them, survive a
module crashing, attach remediation text, and compute the final score.
That "something" is this engine.

The engine is also where the progress callback lives. The API uses it to
write "35% -- checking headers" into Redis, which is what the React UI polls.
"""

import time                                    # stopwatch for duration_ms
import uuid                                    # random unique scan id
from datetime import datetime, timezone        # ISO timestamp

from .fetch import safe_get                    # one safe HTTP request
from .url_guard import assert_url_is_public    # SSRF validation before anything else
from . import headers_check                    # Module 1
from . import ssl_check                        # Module 2
from . import cms_check                        # Module 3
from .models import (                          # shared result types
    CheckResult,
    ModuleResult,
    ScanError,
    ScanResult,
    FAIL,
)
from .remediation import for_check             # "how to fix it" database
from .scoring import overall_score, grade_for, grade_color   # final score + letter


def _noop_progress(percent: int, message: str) -> None:
    """Default progress callback: do nothing (used by the CLI)."""

    return None                                 # explicit, so readers know it is intentional


def _failed_module(module_id: str, title: str, weight: float, message: str) -> ModuleResult:
    """Build a zero-score module when one check crashes unexpectedly.

    A crash in the CMS parser must not throw away a valid SSL result, so the
    engine converts exceptions into a readable failed module instead.
    """

    check = CheckResult(
        id=module_id,
        title=title,
        status=FAIL,
        points=0,
        max_points=100,
        detail=f"This module could not run: {message}",
        evidence="",
    )
    return ModuleResult(id=module_id, title=title, score=0, weight=weight, checks=[check])


def run_scan(url: str, timeout: float = 8.0, progress=None) -> ScanResult:
    """Scan one URL and return the complete result object."""

    progress = progress or _noop_progress       # make the callback always callable
    scan_id = str(uuid.uuid4())                 # e.g. "0f1e2d3c-..." -- the job id in the queue
    started_at = datetime.now(timezone.utc).isoformat()   # timezone-aware UTC ISO string
    started = time.perf_counter()               # high resolution start time

    progress(5, "Validating the URL")
    cleaned_url = assert_url_is_public(url)     # syntax + scheme + DNS + private-IP checks

    progress(15, "Fetching the page")
    fetch_result = safe_get(cleaned_url, timeout=timeout)   # the only network request of the scan

    modules = []                                # collected ModuleResult objects

    progress(40, "Checking security headers")
    try:
        modules.append(headers_check.run(fetch_result))     # Module 1
    except Exception as exc:                                # defensive: never lose the whole scan
        modules.append(_failed_module("headers", "Security Headers", 0.40, str(exc)))

    progress(65, "Inspecting the TLS certificate")
    try:
        modules.append(ssl_check.run(fetch_result.final_url, timeout=timeout))   # Module 2
    except Exception as exc:
        modules.append(_failed_module("ssl", "SSL / TLS", 0.40, str(exc)))

    progress(85, "Detecting the CMS")
    try:
        modules.append(cms_check.run(fetch_result))          # Module 3
    except Exception as exc:
        modules.append(_failed_module("cms", "CMS Detection", 0.20, str(exc)))

    # Attach the remediation entry to every check. Doing it centrally means
    # the check modules stay focused on detection.
    for module in modules:                      # every module...
        for check in module.checks:             # ...every check inside it...
            check.remediation = for_check(check.id)   # ...gets its fix text

    progress(95, "Calculating the score")
    score = overall_score(modules)              # weighted 0-100
    grade = grade_for(score)                    # "B+"
    duration_ms = int((time.perf_counter() - started) * 1000)   # stop the stopwatch

    progress(100, "Done")

    return ScanResult(
        id=scan_id,
        url=url,                                # exactly what the user typed
        final_url=fetch_result.final_url,       # after redirects
        status_code=fetch_result.status_code,
        server=fetch_result.headers.get("server", ""),
        started_at=started_at,
        duration_ms=duration_ms,
        score=score,
        grade=grade,
        modules=modules,
        meta={
            "redirects": fetch_result.redirects,          # chain of URLs we visited
            "tls_error": fetch_result.tls_error,          # certificate problem, if any
            "grade_color": grade_color(score),            # "green" / "amber" / "red"
            "request_ms": fetch_result.elapsed_ms,        # time spent on the HTTP request only
            "passive": True,                              # reminder: no attacks were performed
        },
    )
