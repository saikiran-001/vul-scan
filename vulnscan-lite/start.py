"""
start.py -- platform entry point used by Render (and any PaaS).

WHY THIS FILE EXISTS
--------------------
A hosting platform runs ONE command to start your app. That command must work
even if a dependency is missing, otherwise you get:

    bash: line 1: gunicorn: command not found

So this file tries the production server first and falls back to Flask's
built-in server:

    gunicorn installed  -> gunicorn -w 1 --threads 8 ... api.main:app
    gunicorn missing    -> app.run(...)   (still works, just slower)

The `-w 1` is deliberate: scans run in background threads and job status is
kept in memory, so multiple worker processes would not see each other's jobs.

Usage:
    python start.py                 # reads PORT and HOST from the environment
    PORT=10000 python start.py
"""

import os                      # PORT / HOST are injected by the platform
import sys                     # gunicorn reads its options from sys.argv


def main() -> None:
    """Start the web app with the best server available."""

    port = int(os.getenv("PORT", "8000"))       # Render sets PORT automatically
    host = os.getenv("HOST", "0.0.0.0")         # must be 0.0.0.0 inside a container

    try:
        # Importing gunicorn on Windows fails (it needs fcntl), which is fine:
        # the fallback below is exactly what a Windows developer wants.
        from gunicorn.app.wsgiapp import run as gunicorn_run
    except ImportError:
        print("gunicorn not available -- falling back to the Flask server.")
        from api.main import app                # importing creates the SQLite tables
        app.run(host=host, port=port, threaded=True)
        return

    # Gunicorn reads its command line from sys.argv, so we build it here.
    # One worker + 8 threads: the API stays responsive while a scan runs.
    sys.argv = [
        "gunicorn",
        "-w", "1",
        "--threads", "8",
        "--timeout", "120",
        "--access-logfile", "-",                # log requests to stdout (Render captures it)
        "-b", f"{host}:{port}",
        "api.main:app",
    ]
    gunicorn_run()                              # never returns


if __name__ == "__main__":
    main()
