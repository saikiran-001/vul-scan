"""
jobs.py -- the bridge between the API and the worker (Week 2).

WHY THIS FILE EXISTS
--------------------
`main.py` should not care whether a scan runs inside Celery or inside a
thread. It calls enqueue_scan() and gets back the mode that was used.

    enqueue_scan() -> "celery"  (Redis + a separate worker process)
                   -> "thread"  (no Redis: a daemon thread in the API process)

Both paths run exactly the same function, execute_scan(), so the behaviour
of a scan cannot drift between them.
"""

import threading                                  # the fallback worker
from datetime import datetime, timezone           # timestamps

from scanner import run_scan, ScanError           # Week 1 engine
from .settings import QUEUE_MODE, SCAN_TIMEOUT    # configuration
from .store import get_store, redis_available     # job status storage
from . import history                             # SQLite history (Week 4)


def queue_mode() -> str:
    """Decide which worker to use, honouring the VULNSCAN_QUEUE variable."""

    if QUEUE_MODE in ("celery", "thread"):        # explicitly forced
        return QUEUE_MODE
    # "auto": Celery is only possible when Redis answers.
    return "celery" if redis_available() else "thread"


def execute_scan(scan_id: str, url: str, user_id: int | None = None) -> dict | None:
    """Run one scan and publish its progress. Used by BOTH worker modes."""

    store = get_store()                           # Redis or memory, same API

    def progress(percent: int, message: str) -> None:
        """Called by the engine several times during the scan."""
        store.update(scan_id, {                    # merge into the existing job record
            "status": "running",
            "progress": percent,
            "message": message,
        })

    store.update(scan_id, {
        "status": "running",
        "progress": 2,
        "message": "Worker picked up the job",
    })

    try:
        result = run_scan(url, timeout=SCAN_TIMEOUT, progress=progress)   # Week 1 engine
        payload = result.to_dict()                                       # JSON-ready dict

        store.update(scan_id, {
            "status": "done",
            "progress": 100,
            "message": "Scan complete",
            "result": payload,
            "error": "",
        })

        if user_id:                                   # only logged-in scans go to history
            try:
                history.save_scan(user_id, payload)   # SQLite insert
            except Exception:
                pass                                  # history failure must not lose the report

        return payload

    except ScanError as exc:
        # Expected failure: bad URL, DNS error, timeout, blocked private IP.
        store.update(scan_id, {
            "status": "error",
            "progress": 100,
            "message": str(exc),
            "error": str(exc),
        })
        return None

    except Exception as exc:                          # unexpected bug
        store.update(scan_id, {
            "status": "error",
            "progress": 100,
            "message": "The scan crashed unexpectedly.",
            "error": repr(exc),                       # repr keeps the exception type
        })
        return None


def enqueue_scan(scan_id: str, url: str, user_id: int | None = None) -> str:
    """Start a scan in the background. Returns the mode that was used."""

    mode = queue_mode()

    if mode == "celery":
        try:
            from .tasks import run_scan_task          # imported lazily: celery is optional
            run_scan_task.delay(scan_id, url, user_id)   # .delay() = send the message to Redis
            return "celery"
        except Exception:
            # Redis died between the ping and now, or the worker package is broken.
            # Falling back to a thread keeps the product usable instead of 500-ing.
            pass

    thread = threading.Thread(
        target=execute_scan,
        args=(scan_id, url, user_id),
        daemon=True,                                  # do not block process exit
        name=f"scan-{scan_id[:8]}",                   # shows up in tracebacks
    )
    thread.start()                                    # returns immediately
    return "thread"


def new_job_record(scan_id: str, url: str, user_id: int | None) -> dict:
    """The initial record written before the worker starts."""

    return {
        "id": scan_id,
        "url": url,
        "status": "queued",                           # queued -> running -> done | error
        "progress": 0,
        "message": "Queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "result": None,
        "error": "",
    }
