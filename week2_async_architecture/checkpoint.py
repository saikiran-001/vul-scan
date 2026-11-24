"""
Week 2 checkpoint -- proves the async API works.

RUN (server must be running):
    python run.py --no-open            # terminal 1
    python week2_async_architecture/checkpoint.py     # terminal 2

Optional custom base URL:
    python week2_async_architecture/checkpoint.py http://127.0.0.1:9000
"""

import sys                     # argv + exit code
import time                    # polling delay

import requests                # simple HTTP client for the test

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def check(label: str, condition: bool, detail: str = "") -> bool:
    """Print one PASS/FAIL line."""

    print(f"[{'PASS' if condition else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    return condition


def main() -> int:
    ok = True

    # ---- 1. health ------------------------------------------------------
    try:
        health = requests.get(f"{BASE}/api/health", timeout=10).json()
    except Exception as exc:
        print(f"[FAIL] could not reach {BASE}/api/health -- is the server running? ({exc})")
        return 1

    ok &= check("health endpoint responds", health.get("status") == "ok")
    print(f"       queue mode: {health.get('queue')}  redis: {health.get('redis')}")

    # ---- 2. queue a scan -------------------------------------------------
    response = requests.post(f"{BASE}/api/scan", json={"url": "https://example.com"}, timeout=10)
    ok &= check("POST /api/scan returns 202", response.status_code == 202, str(response.status_code))

    job = response.json()
    ok &= check("response contains a job id", bool(job.get("id")))
    ok &= check("response contains status_url", job.get("status_url", "").endswith("/status"))

    # ---- 3. poll until done ---------------------------------------------
    status = None
    seen = []                                   # remember progress values
    deadline = time.time() + 90                 # never loop forever
    while time.time() < deadline:
        status = requests.get(BASE + job["status_url"], timeout=10).json()
        if not seen or seen[-1] != status.get("progress"):
            seen.append(status.get("progress"))
            print(f"       {status.get('status'):8s} {status.get('progress'):3d}%  {status.get('message', '')}")
        if status.get("status") in ("done", "error"):
            break
        time.sleep(2)                           # the brief's 2 second interval

    ok &= check("scan finished with status=done", status is not None and status.get("status") == "done",
                (status or {}).get("error", ""))

    result = (status or {}).get("result") or {}
    ok &= check("progress moved through several values", len(seen) >= 2, str(seen))
    ok &= check("result contains a score", isinstance(result.get("score"), int), str(result.get("score")))
    ok &= check("result contains three modules", len(result.get("modules", [])) == 3)
    ok &= check("result contains checks", len(result.get("checks", [])) > 0)

    # ---- 4. SSRF guard ---------------------------------------------------
    blocked = requests.post(f"{BASE}/api/scan", json={"url": "http://127.0.0.1:8000"}, timeout=10)
    ok &= check("private URL rejected with 400", blocked.status_code == 400, str(blocked.status_code))

    # ---- 5. unknown job --------------------------------------------------
    missing = requests.get(f"{BASE}/api/scan/does-not-exist/status", timeout=10)
    ok &= check("unknown job returns 404", missing.status_code == 404, str(missing.status_code))

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
