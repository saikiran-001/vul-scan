"""
main.py -- the Flask web server (Week 2 + 3 + 4 wiring).

WHY FLASK AND NOT FASTAPI?
--------------------------
Both are allowed by the brief. This machine's security policy blocks
pydantic_core (a compiled DLL that FastAPI requires), while Flask is pure
Python and runs everywhere. The architecture is identical.

ENDPOINTS
---------
    GET  /api/health                        is the server alive? which queue mode?
    POST /api/scan                          queue a scan          -> {id, status_url}
    GET  /api/scan/{id}/status              poll it every 2 seconds
    GET  /api/scan/{id}/report.pdf          download the PDF
    POST /api/auth/register                 create an account
    POST /api/auth/login                    get a bearer token
    GET  /api/auth/me                       who am I?
    GET  /api/history                       my past scans (needs the token)
    GET  /                                  the React app

WHY POST + POLL INSTEAD OF ONE LONG REQUEST?
--------------------------------------------
A scan takes 10-30 seconds. If POST /api/scan waited for it, every browser
tab would hold a connection open, proxies would time out, and one slow site
would block the server. Instead POST returns in milliseconds with an id, and
the browser asks "done yet?" every 2 seconds. This is the async pattern the
brief asks for.
"""

import os                                              # RENDER / VULNSCAN_TRUST_PROXY
import uuid                                            # scan ids

from flask import Flask, jsonify, request, send_file, send_from_directory   # the framework
from werkzeug.middleware.proxy_fix import ProxyFix     # real client IP behind a PaaS

from scanner import ScanError                          # friendly scan errors
from scanner.url_guard import assert_url_is_public     # SSRF check BEFORE queuing

from . import auth, history                            # accounts + SQLite
from .errors import ApiError                           # our expected-error type
from .jobs import enqueue_scan, new_job_record, queue_mode   # queue abstraction
from .pdf_report import build_pdf                      # Week 4 PDF
from .ratelimit import check_or_raise                  # Week 4 abuse protection
from .settings import APP_VERSION, REPORTS_DIR, WEB_DIR      # configuration
from .store import get_store, redis_available          # job status storage

# static_folder=None because we serve web/ ourselves with send_from_directory.
app = Flask(__name__, static_folder=None)
app.json.sort_keys = False                             # keep JSON key order (nicer to read)


def _behind_proxy() -> bool:
    """True when a reverse proxy in front of us supplies X-Forwarded-*."""

    if os.getenv("VULNSCAN_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes"):
        return True
    # Render (and several other PaaS providers) set RENDER_* variables.
    return any(key.startswith("RENDER") for key in os.environ)


if _behind_proxy():
    # Without this, request.remote_addr is the proxy's IP, so every visitor
    # would share one rate-limit bucket. x_for=1 means "trust exactly one hop".
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

history.init_db()                                      # create tables on first import


# ---------------------------------------------------------------------------
# Error handling: every ApiError becomes {"detail": "..."} + its status code.
# ---------------------------------------------------------------------------
@app.errorhandler(ApiError)
def _handle_api_error(exc: ApiError):
    response = jsonify({"detail": exc.message})
    response.status_code = exc.status
    for key, value in exc.headers.items():             # e.g. Retry-After
        response.headers[key] = value
    return response


@app.errorhandler(404)
def _handle_not_found(exc):
    if request.path.startswith("/api/"):
        return jsonify({"detail": "Endpoint not found."}), 404
    return jsonify({"detail": "File not found."}), 404


@app.errorhandler(405)
def _handle_method_not_allowed(exc):
    """Keep the API JSON-only: Flask's default 405 page is HTML."""
    if request.path.startswith("/api/"):
        return jsonify({"detail": "Method not allowed for this endpoint."}), 405
    return exc                                         # static files keep the HTML page


@app.errorhandler(500)
def _handle_server_error(exc):
    # Never leak a stack trace to the browser in production.
    return jsonify({"detail": "Internal server error."}), 500


# ---------------------------------------------------------------------------
# CORS: only relevant if you open the UI from another origin (e.g. a dev
# server). Same-origin requests ignore these headers.
# ---------------------------------------------------------------------------
@app.after_request
def _add_cors_headers(response):
    if request.path.startswith("/api/"):
        response.headers.setdefault("Access-Control-Allow-Origin", "*")
        response.headers.setdefault("Access-Control-Allow-Headers", "Authorization, Content-Type")
        response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _public_job(job: dict) -> dict:
    """Remove internal fields before sending a job to the browser."""

    return {k: v for k, v in job.items() if k != "user_id"}


def _rate_key(user) -> str:
    """Rate limit per account when logged in, per IP otherwise."""

    if user:
        return f"user:{user['id']}"
    return f"ip:{request.remote_addr or 'unknown'}"


def _json_body() -> dict:
    """Return the request body as a dict, or raise a clean 400."""

    body = request.get_json(silent=True)               # None for invalid JSON
    if not isinstance(body, dict):
        raise ApiError(400, "Send a JSON object in the request body.")
    return body


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    """Quick check used by the UI footer and by deployment platforms."""

    return jsonify({
        "status": "ok",
        "version": APP_VERSION,
        "queue": queue_mode(),              # "celery" or "thread"
        "redis": redis_available(),         # whether a Redis server answered
    })


@app.get("/health")
def health_alias():
    """Alias for hosting platforms whose health check expects /health."""

    return health()


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
@app.post("/api/scan")
def start_scan():
    """Validate the URL, create a job record, and hand it to a worker."""

    body = _json_body()
    raw_url = str(body.get("url", "")).strip()

    if len(raw_url) < 3 or len(raw_url) > 2048:        # same limits the old schema had
        raise ApiError(400, "Please enter a URL between 3 and 2048 characters.")

    user = auth.optional_user()                        # logged in? attach history later
    check_or_raise(_rate_key(user))                    # Week 4: 429 when over the limit

    try:
        cleaned_url = assert_url_is_public(raw_url)    # reject private IPs / bad schemes now
    except ScanError as exc:
        raise ApiError(400, str(exc))

    scan_id = str(uuid.uuid4())                        # the public job id
    user_id = user["id"] if user else None             # only logged-in scans go to history

    store = get_store()
    store.set(scan_id, new_job_record(scan_id, cleaned_url, user_id))   # status = queued

    mode = enqueue_scan(scan_id, cleaned_url, user_id)                  # celery or thread

    return jsonify({
        "id": scan_id,
        "status": "queued",
        "queue": mode,                                 # useful in the UI footer
        "status_url": f"/api/scan/{scan_id}/status",   # the browser polls this
    }), 202


@app.get("/api/scan/<scan_id>/status")
def scan_status(scan_id: str):
    """The polling endpoint. Returns progress, and the full result when done."""

    job = get_store().get(scan_id)
    if job is None:
        raise ApiError(404, "Scan not found or the job expired.")
    return jsonify(_public_job(job))


@app.get("/api/scan/<scan_id>/report.pdf")
def scan_report(scan_id: str):
    """Generate (once) and download the PDF report."""

    payload = None

    job = get_store().get(scan_id)                     # fast path: job still in Redis/memory
    if job and job.get("result"):
        payload = job["result"]

    user = auth.optional_user()
    if payload is None and user:                       # older scans come from SQLite
        payload = history.get_scan(scan_id, user["id"])

    if payload is None:
        raise ApiError(404, "Report not found. The scan may still be running.")

    out_path = REPORTS_DIR / f"{scan_id}.pdf"          # cache the generated file
    if not out_path.exists():                          # build only once
        build_pdf(payload, out_path)

    return send_file(
        out_path,
        mimetype="application/pdf",
        as_attachment=True,                            # triggers "Save as..." in the browser
        download_name=f"vulnscan-report-{scan_id[:8]}.pdf",
    )


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------
@app.post("/api/auth/register")
def register():
    """Create an account; returns a token so the user is logged in immediately."""

    body = _json_body()
    result = auth.register(str(body.get("email", "")), str(body.get("password", "")))
    return jsonify(result), 201


@app.post("/api/auth/login")
def login():
    """Exchange email + password for a bearer token."""

    body = _json_body()
    return jsonify(auth.login(str(body.get("email", "")), str(body.get("password", ""))))


@app.get("/api/auth/me")
def me():
    """Return the logged-in user. The UI uses this to validate a stored token."""

    return jsonify(auth.require_user())


# ---------------------------------------------------------------------------
# History (Week 4)
# ---------------------------------------------------------------------------
@app.get("/api/history")
def get_history():
    """All scans belonging to the logged-in user, newest first."""

    user = auth.require_user()
    return jsonify({"scans": history.list_scans(user["id"])})


# ---------------------------------------------------------------------------
# Static frontend. These two routes must be declared LAST so that a URL such
# as /api/scan/... always hits the API route above instead of the file route.
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    """Serve the single-page React app."""

    return send_from_directory(WEB_DIR, "index.html")


@app.get("/<path:filename>")
def static_files(filename: str):
    """Serve app.jsx, styles.css and web/vendor/*. send_from_directory blocks
    path traversal (../../etc/passwd), so this is safe."""

    # Werkzeug does not know the .jsx extension, so it would answer with
    # application/octet-stream. Browsers are happier with a JavaScript type.
    mimetype = "text/javascript" if filename.endswith(".jsx") else None
    return send_from_directory(WEB_DIR, filename, mimetype=mimetype)
