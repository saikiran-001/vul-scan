"""
Week 1 checkpoint -- proves the scanner core works end to end.

RUN:
    python week1_scanner_core/checkpoint.py
    python week1_scanner_core/checkpoint.py https://your-site.com

It imports the package directly (no server, no queue, no database) and checks
the contract that Weeks 2-4 rely on.
"""

import json                    # to print the result
import sys                     # argv + exit code
from pathlib import Path       # to find the project root

# When you run "python week1_scanner_core/checkpoint.py", Python puts
# week1_scanner_core/ on sys.path, not the project root. Add the root so
# "import scanner" works from anywhere.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner import run_scan, ScanError     # noqa: E402  (import after path setup)


def check(label: str, condition: bool, detail: str = "") -> bool:
    """Print one PASS/FAIL line and return the condition."""

    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {label}" + (f" -- {detail}" if detail else ""))
    return condition


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"Scanning {url} ...\n")

    try:
        result = run_scan(url)                      # the whole Week 1 engine
    except ScanError as exc:
        print(f"[FAIL] scan raised ScanError: {exc}")
        return 1

    data = result.to_dict()                         # the JSON contract
    ok = True

    # 1. Every key the API and the UI expect must exist.
    required_keys = {"id", "url", "final_url", "status_code", "score", "grade",
                     "modules", "checks", "meta", "duration_ms"}
    ok &= check("result has all required keys", required_keys.issubset(data.keys()),
                ", ".join(sorted(required_keys - data.keys())) or "all present")

    # 2. Exactly the three modules from the brief.
    module_ids = {module["id"] for module in data["modules"]}
    ok &= check("three modules (headers, ssl, cms)",
                module_ids == {"headers", "ssl", "cms"}, str(sorted(module_ids)))

    # 3. Score and grade are sane.
    ok &= check("score is 0-100", 0 <= data["score"] <= 100, str(data["score"]))
    ok &= check("grade is a letter", isinstance(data["grade"], str) and len(data["grade"]) <= 2,
                data["grade"])

    # 4. The flat check list is populated and every check has remediation text
    #    attached by the engine (an empty dict is fine for unknown ids).
    ok &= check("checks list is populated", len(data["checks"]) > 0,
                f"{len(data['checks'])} checks")
    ok &= check("every check carries a remediation field",
                all("remediation" in check for check in data["checks"]))

    # 5. JSON serialisation must work: this is what the queue stores.
    try:
        json.dumps(data)
        ok &= check("result is JSON serialisable", True)
    except TypeError as exc:
        ok &= check("result is JSON serialisable", False, str(exc))

    print("")
    print(f"Score {data['score']}/100 (grade {data['grade']}) in {data['duration_ms']} ms")
    print(json.dumps(data["modules"], indent=2)[:600] + " ...")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
