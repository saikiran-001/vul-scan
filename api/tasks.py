"""
tasks.py -- the Celery task (Week 2).

A Celery task is just a function with a decorator. The decorator registers it
in the task registry so a worker can find it by name when a message arrives.

Start the worker with:
    celery -A api.celery_app.celery_app worker --loglevel=info --pool=solo
"""

from .celery_app import celery_app     # the app created in celery_app.py
from .jobs import execute_scan         # the shared implementation


@celery_app.task(name="vulnscan.run_scan", bind=False)
def run_scan_task(scan_id: str, url: str, user_id: int | None = None):
    """Worker entry point. Arguments must be JSON-serialisable."""

    return execute_scan(scan_id, url, user_id)   # same code as the thread fallback
