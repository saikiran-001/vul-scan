"""
celery_app.py -- the Celery application object (Week 2).

Celery is a task queue. The API says "run this function later" by putting a
message on a broker (Redis). A separate worker process reads the message and
runs it. That is how a 20-second scan stops blocking an HTTP request.

On Windows, run the worker with --pool=solo (see HOW_TO_RUN.md), because
Celery's default prefork pool relies on fork(), which Windows does not have.
"""

from celery import Celery              # the task queue framework

from .settings import REDIS_URL        # broker and result backend

# First argument is the name used in logs and task paths.
celery_app = Celery("vulnscan", broker=REDIS_URL, backend=REDIS_URL)

celery_app.conf.update(
    task_serializer="json",                    # messages are JSON, never pickle (safer)
    accept_content=["json"],                   # refuse anything else
    result_serializer="json",
    timezone="UTC",                            # consistent timestamps
    enable_utc=True,
    task_track_started=True,                   # lets us see "STARTED" in celery inspect
    broker_connection_retry_on_startup=True,   # worker waits if Redis starts a bit later
    task_time_limit=120,                       # hard kill after 2 minutes
    task_soft_time_limit=90,                   # raise an exception after 90 seconds
)

# Importing the module registers the @celery_app.task function with this app.
# The import must stay at the bottom to avoid a circular import at startup.
from . import tasks  # noqa: E402,F401
