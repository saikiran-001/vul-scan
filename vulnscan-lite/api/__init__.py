"""
The `api` package -- Week 2 (queue + API), Week 3 (report data), Week 4 (PDF, history).

The FastAPI application object lives in api.main:app, which is what uvicorn
and Celery point at. This file is intentionally empty of imports: importing
the package must not start the web app as a side effect (Celery imports
api.celery_app, and that should stay lightweight).
"""
