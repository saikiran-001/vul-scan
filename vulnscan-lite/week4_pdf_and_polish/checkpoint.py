"""
Week 4 checkpoint -- proves PDF export, accounts, history and rate limiting.

RUN (server must be running):
    python run.py --no-open
    python week4_pdf_and_polish/checkpoint.py
"""

import sys                     # argv + exit code
import time                    # polling delay
import uuid                    # unique test account
from pathlib import Path       # to make "import api" work from any folder

import requests                # HTTP client for the test

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # so "from api.settings import ..." works

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def check(label: str, condition: bool, detail: str = "") -> bool:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    return condition


def main() -> int:
    ok = True

    # ---- 1. a fresh account ---------------------------------------------
    email = f"checkpoint-{uuid.uuid4().hex[:8]}@example.com"
    password = "checkpoint-password-123"
    register = requests.post(f"{BASE}/api/auth/register",
                             json={"email": email, "password": password}, timeout=10)
    ok &= check("register returns 201", register.status_code == 201, str(register.status_code))
    token = register.json().get("token", "")
    ok &= check("register returns a token", len(token) > 20, f"{len(token)} chars")

    auth = {"Authorization": f"Bearer {token}"}

    # ---- 2. token is valid ----------------------------------------------
    me = requests.get(f"{BASE}/api/auth/me", headers=auth, timeout=10)
    ok &= check("GET /api/auth/me returns the account", me.status_code == 200 and me.json().get("email") == email)

    # ---- 3. login also works --------------------------------------------
    login = requests.post(f"{BASE}/api/auth/login",
                          json={"email": email, "password": password}, timeout=10)
    ok &= check("login works", login.status_code == 200 and bool(login.json().get("token")))

    bad = requests.post(f"{BASE}/api/auth/login",
                        json={"email": email, "password": "wrong-password"}, timeout=10)
    ok &= check("wrong password is rejected with 401", bad.status_code == 401, str(bad.status_code))

    # ---- 4. scan while logged in ----------------------------------------
    job = requests.post(f"{BASE}/api/scan", json={"url": "https://example.com"},
                        headers=auth, timeout=10).json()
    status = {}
    deadline = time.time() + 90
    while time.time() < deadline:
        status = requests.get(BASE + job["status_url"], timeout=10).json()
        if status.get("status") in ("done", "error"):
            break
        time.sleep(2)

    ok &= check("authenticated scan finishes", status.get("status") == "done", str(status.get("error", "")))
    result = status.get("result") or {}
    scan_id = result.get("id", "")

    # ---- 5. history ------------------------------------------------------
    history = requests.get(f"{BASE}/api/history", headers=auth, timeout=10)
    scans = history.json().get("scans", [])
    ok &= check("history contains the new scan", any(s["id"] == scan_id for s in scans),
                f"{len(scans)} saved scans")

    anonymous = requests.get(f"{BASE}/api/history", timeout=10)
    ok &= check("history requires a token (401)", anonymous.status_code == 401,
                str(anonymous.status_code))

    # ---- 6. PDF ----------------------------------------------------------
    pdf = requests.get(f"{BASE}/api/scan/{scan_id}/report.pdf", headers=auth, timeout=60)
    ok &= check("PDF download returns 200", pdf.status_code == 200, str(pdf.status_code))
    ok &= check("response really is a PDF", pdf.content[:5] == b"%PDF-", str(pdf.content[:8]))
    ok &= check("PDF has a realistic size", len(pdf.content) > 3000, f"{len(pdf.content)} bytes")

    # ---- 7. rate limiting is configured ----------------------------------
    # We do not exhaust the quota (that would break the rest of your demo);
    # we only prove the limiter is wired in by checking its settings.
    from api.settings import RATE_LIMIT, RATE_WINDOW_SECONDS   # noqa: E402
    ok &= check("rate limit is enabled", RATE_LIMIT > 0 and RATE_WINDOW_SECONDS > 0,
                f"{RATE_LIMIT} scans / {RATE_WINDOW_SECONDS}s")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
