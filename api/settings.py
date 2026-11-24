"""
settings.py -- every configurable value in one place.

The rule: no magic strings hidden inside modules. If you want to change the
port, the Redis URL or the rate limit, you edit an environment variable or
this file -- never ten different files.
"""

import os                     # read environment variables
from pathlib import Path      # clean, cross-platform file paths

# Path(__file__) is .../vulnscan-lite/api/settings.py
# .parent is the api/ folder, .parent.parent is the project root.
ROOT_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = ROOT_DIR / "data"          # generated files live here (database, PDFs)
WEB_DIR = ROOT_DIR / "web"            # the React frontend
REPORTS_DIR = DATA_DIR / "reports"    # cached PDF reports
DB_PATH = DATA_DIR / "vulnscan.db"    # SQLite database for users + history

# Make sure the folders exist before anything tries to write into them.
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Redis is where Celery stores queued jobs and where we store scan status.
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")

# Queue mode:
#   "auto"   -> use Celery when Redis answers, otherwise run jobs in a thread
#   "celery" -> force Celery (requires Redis)
#   "thread" -> force the simple in-process worker (no Redis needed)
QUEUE_MODE = os.getenv("VULNSCAN_QUEUE", "auto").strip().lower()

SCAN_TIMEOUT = float(os.getenv("VULNSCAN_TIMEOUT", "8"))       # seconds per HTTP request
JOB_TTL_SECONDS = int(os.getenv("VULNSCAN_JOB_TTL", "3600"))   # how long a finished job stays in Redis

# Rate limiting: how many scans one visitor may start per window.
RATE_LIMIT = int(os.getenv("VULNSCAN_RATE_LIMIT", "30"))
RATE_WINDOW_SECONDS = int(os.getenv("VULNSCAN_RATE_WINDOW", "3600"))

# Version string shown in /api/health.
APP_VERSION = "1.0.0"
