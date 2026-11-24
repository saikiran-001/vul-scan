"""
models.py -- the shared "data shapes" of VulnScan Lite.

WHY THIS FILE EXISTS
--------------------
Three different checks (headers, SSL, CMS) all produce results, and two
different consumers (the React UI and the PDF generator) all read results.
If every module invented its own dictionary keys, the UI would need special
cases everywhere. So we define the shapes ONCE, here, with dataclasses.

A dataclass is just a class that stores data. Python writes __init__,
__repr__ and __eq__ for us, so we only declare the fields.
"""

from dataclasses import dataclass, field, asdict      # asdict() turns a dataclass into a plain dict (JSON friendly)
from typing import Any                                # Any = "this value can be of any type"

# ---------------------------------------------------------------------------
# The four possible states of a single check.
# Using constants instead of typing the strings everywhere prevents typos
# like "Pased" that would silently break the UI colours.
# ---------------------------------------------------------------------------
PASS = "pass"        # the site is doing the right thing
WARN = "warn"        # it is present but weak / cannot be confirmed
FAIL = "fail"        # the protection is missing or broken
INFO = "info"        # informational, not a security failure

# Human readable labels used by the UI and the PDF report.
STATUS_LABEL = {
    PASS: "Passed",
    WARN: "Warning",
    FAIL: "Failed",
    INFO: "Info",
}


@dataclass
class CheckResult:
    """One single test, e.g. 'is Content-Security-Policy present?'."""

    id: str                 # stable machine name, e.g. "csp" (used to look up remediation text)
    title: str              # short human title shown in the table
    status: str             # one of PASS / WARN / FAIL / INFO above
    points: int             # points earned by this check
    max_points: int         # points this check could have earned
    detail: str             # one sentence explaining what we saw
    evidence: str = ""      # raw value we observed (header value, cipher name, ...)
    remediation: dict = field(default_factory=dict)   # filled in by the engine from remediation.py

    @property
    def passed(self) -> bool:
        """True when the check should be shown as a green tick."""
        return self.status in (PASS, INFO)               # INFO is not a failure, so it counts as "ok"

    def to_dict(self) -> dict:
        """Convert to a dict that json.dumps() can serialise."""
        data = asdict(self)                              # recursively convert nested dataclasses
        data["passed"] = self.passed                     # property is not included by asdict(), add it manually
        data["status_label"] = STATUS_LABEL.get(self.status, self.status)   # ready-to-show text
        return data


@dataclass
class ModuleResult:
    """A group of checks that share a topic: headers, ssl or cms."""

    id: str                                    # "headers" / "ssl" / "cms"
    title: str                                 # "Security Headers" / "SSL / TLS" / "CMS Detection"
    score: int                                 # 0-100 score for this module only
    weight: float                              # how much this module matters in the final score (0.0-1.0)
    checks: list = field(default_factory=list)  # list[CheckResult]

    def to_dict(self) -> dict:
        """Same idea as CheckResult.to_dict()."""
        return {
            "id": self.id,
            "title": self.title,
            "score": self.score,
            "weight": self.weight,
            "checks": [c.to_dict() for c in self.checks],   # convert every child check too
        }


@dataclass
class ScanResult:
    """Everything we know about one completed scan of one URL."""

    id: str                    # unique scan id (uuid4 string) -- the API uses it in /api/scan/<id>/status
    url: str                   # the URL exactly as the user typed it
    final_url: str             # the URL we actually ended on (after redirects)
    status_code: int           # HTTP status of the final response (200, 403, ...)
    server: str                # value of the Server header, if any
    started_at: str            # ISO-8601 UTC timestamp, easy for JS to parse
    duration_ms: int           # how long the scan took, in milliseconds
    score: int                 # final 0-100 score
    grade: str                 # letter grade derived from score (A+, B, C-, ...)
    modules: list = field(default_factory=list)   # list[ModuleResult]
    meta: dict = field(default_factory=dict)      # free-form extras (redirect chain, cms info, ...)
    error: str = ""                               # empty when the scan succeeded

    def all_checks(self) -> list:
        """Flatten every module's checks into one list, tagging each with its module."""
        flat = []                                            # start empty
        for module in self.modules:                          # walk every module
            for check in module.checks:                      # walk every check inside it
                item = check.to_dict()                       # convert the check to a dict
                item["module_id"] = module.id                # remember where it came from
                item["module_title"] = module.title          # ...and its pretty name
                flat.append(item)                            # collect it
        return flat                                          # return the combined list

    def to_dict(self) -> dict:
        """The exact JSON payload the API returns and the UI consumes."""
        return {
            "id": self.id,
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "server": self.server,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "score": self.score,
            "grade": self.grade,
            "modules": [m.to_dict() for m in self.modules],  # nested modules + checks
            "checks": self.all_checks(),                     # convenience: flat list for the table
            "meta": self.meta,
            "error": self.error,
        }


class ScanError(Exception):
    """Raised when a scan cannot even start or cannot be completed safely.

    Examples: the URL is not http(s), the host resolves to a private IP,
    the site refuses every connection, the DNS name does not exist.
    The API turns this into a friendly 400/502 response.
    """

    def __init__(self, message: str, code: str = "scan_failed") -> None:
        super().__init__(message)   # let Exception store the message normally
        self.code = code            # machine readable reason the API can send to the UI
