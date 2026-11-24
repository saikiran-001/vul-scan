"""
Week 3 checkpoint -- proves the report data and the frontend are complete.

RUN (server must be running):
    python run.py --no-open
    python week3_report_interface/checkpoint.py
"""

import sys                     # argv + exit code
import time                    # polling delay

import requests                # HTTP client for the test

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def check(label: str, condition: bool, detail: str = "") -> bool:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    return condition


def run_scan(url: str = "https://example.com") -> dict:
    """Queue a scan and block until it finishes. Returns the result dict."""

    job = requests.post(f"{BASE}/api/scan", json={"url": url}, timeout=10).json()
    deadline = time.time() + 90
    while time.time() < deadline:
        status = requests.get(BASE + job["status_url"], timeout=10).json()
        if status.get("status") in ("done", "error"):
            return status
        time.sleep(2)
    return {"status": "timeout"}


def main() -> int:
    ok = True

    status = run_scan()
    if status.get("status") != "done":
        print(f"[FAIL] scan did not finish: {status}")
        return 1

    result = status["result"]

    # ---- scoring --------------------------------------------------------
    modules = result["modules"]
    weight_sum = round(sum(module["weight"] for module in modules), 4)
    ok &= check("three modules present", len(modules) == 3, str([m["id"] for m in modules]))
    ok &= check("weights add up to 1.0", weight_sum == 1.0, str(weight_sum))

    expected = round(sum(m["score"] * m["weight"] for m in modules))
    ok &= check("final score equals weighted sum", abs(expected - result["score"]) <= 1,
                f"{expected} vs {result['score']}")
    ok &= check("grade matches the score", isinstance(result["grade"], str) and result["grade"] != "",
                result["grade"])

    # ---- remediation ----------------------------------------------------
    failures = [c for c in result["checks"] if c["status"] == "fail"]
    ok &= check("scan produced at least one failure to explain", len(failures) > 0,
                f"{len(failures)} failures")

    missing_fix = [c["id"] for c in failures if not c.get("remediation", {}).get("fix")]
    ok &= check("every failure has a 'how to fix'", not missing_fix, str(missing_fix))

    missing_snippet = [c["id"] for c in failures
                       if c.get("remediation") and not c["remediation"].get("snippet")]
    ok &= check("every remediation has a code snippet", not missing_snippet, str(missing_snippet))

    # ---- UI contract -----------------------------------------------------
    ok &= check("every check has status_label and passed flag",
                all("status_label" in c and "passed" in c for c in result["checks"]))

    # ---- frontend files --------------------------------------------------
    index = requests.get(f"{BASE}/", timeout=10).text
    app_js = requests.get(f"{BASE}/app.jsx", timeout=10).text
    css = requests.get(f"{BASE}/styles.css", timeout=10).text

    ok &= check("index.html serves the React root div", 'id="root"' in index)
    ok &= check("index.html loads the local React vendor files", "/vendor/react.production.min.js" in index)
    ok &= check("app.jsx contains the gauge component", "function Gauge" in app_js)
    ok &= check("app.jsx polls every 2 seconds", "}, 2000)" in app_js)
    ok &= check("styles.css is served", "--accent" in css)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
