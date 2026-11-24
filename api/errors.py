"""
errors.py -- one exception type for every "expected" API failure.

WHY NOT JUST return jsonify(...), 400 EVERYWHERE?
-------------------------------------------------
Raising lets the failing function stop immediately (like an exception should)
while the route stays linear and readable. A single error handler at the app
level turns ApiError into the JSON shape the frontend expects:

    {"detail": "message"}

That is the same shape FastAPI uses, so if you later migrate to FastAPI the
frontend does not change.
"""


class ApiError(Exception):
    """An error that should be shown to the client with a specific HTTP status."""

    def __init__(self, status: int, message: str, headers: dict | None = None) -> None:
        super().__init__(message)          # Exception stores the message
        self.status = status               # e.g. 400, 401, 429
        self.message = message             # human readable text for the UI
        self.headers = headers or {}       # extra headers, e.g. Retry-After on 429
