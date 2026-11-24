# Week 2 -- Async Architecture

> **Goal:** non-blocking. Set up Redis and Celery, create the endpoint to
> trigger a scan (push to the queue) and the endpoint to check its status
> (read from Redis). Connect the frontend.

---

## What was built

| File | Responsibility |
|------|----------------|
| `api/settings.py` | Ports, Redis URL, queue mode, rate limit -- all configuration in one place. |
| `api/store.py` | Job status in Redis **or** in memory, behind the same three methods. |
| `api/celery_app.py` | The Celery application (broker = Redis, JSON only). |
| `api/tasks.py` | `@celery_app.task run_scan_task` -- the worker entry point. |
| `api/jobs.py` | `enqueue_scan()` (Celery or thread) and `execute_scan()` (shared body). |
| `api/main.py` | `POST /api/scan`, `GET /api/scan/<id>/status`, `GET /api/health`. |
| `web/index.html`, `web/app.jsx` | The React page that submits and polls. |

---

## The problem this week solves

A scan takes 10-30 seconds. If `POST /api/scan` waited for it:

* the browser holds a connection open for 30s,
* a reverse proxy may time out at 30-60s,
* one slow website blocks a Flask worker thread,
* the user cannot tell whether anything is happening.

The fix is the standard async pattern:

```
POST /api/scan          -> 202 + job id            (milliseconds)
GET  /api/scan/id/status -> {status, progress}     (every 2 seconds)
```

The work happens in a **different process** (Celery worker) or at least a
**different thread** (fallback), and the status lives somewhere both sides can
read (Redis, or a dict when there is no Redis).

---

## Two workers, one interface

`api/jobs.py` chooses at runtime:

```
VULNSCAN_QUEUE=auto    -> Celery if Redis answers, otherwise a thread
VULNSCAN_QUEUE=celery  -> force Celery (requires Redis)
VULNSCAN_QUEUE=thread  -> force the in-process worker
```

Both paths call `execute_scan()`, which:

1. writes `status: running` to the store,
2. passes a `progress(percent, message)` callback to `scanner.run_scan()`,
3. writes `status: done` + the full result, or `status: error` + the reason.

That is why the UI behaves identically with and without Redis. It also means
you can develop without installing anything, then flip one environment variable
to demo the "real" architecture.

---

## Try the API without the browser

Start the server first (`python run.py --no-open`), then in another terminal:

```powershell
# 1. queue a scan
$body = @{ url = "https://example.com" } | ConvertTo-Json
$job = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/scan `
       -ContentType "application/json" -Body $body
$job | ConvertTo-Json

# 2. poll it
Invoke-RestMethod "http://127.0.0.1:8000/api/scan/$($job.id)/status" |
    Select-Object status, progress, message

# 3. after it finishes, look at the score
(Invoke-RestMethod "http://127.0.0.1:8000/api/scan/$($job.id)/status").result.score
```

The same thing with `curl`:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
     -H "Content-Type: application/json" -d '{"url":"https://example.com"}'
curl http://127.0.0.1:8000/api/scan/<id>/status
```

`GET /api/health` tells you which mode is active:

```json
{"status":"ok","version":"1.0.0","queue":"thread","redis":false}
```

---

## Running the real Celery worker

Requires Redis (Memurai on Windows, or Redis in WSL/Docker).

```powershell
# terminal 1 -- the worker
celery -A api.celery_app.celery_app worker --loglevel=info --pool=solo

# terminal 2 -- the web app, forced to use the queue
$env:VULNSCAN_QUEUE = "celery"
python run.py
```

Why `--pool=solo`? Celery's default prefork pool uses `fork()`. Windows has no
`fork()`, so the worker must run its tasks one at a time in the main process.

---

## Concepts you should be able to explain afterwards

1. **Broker vs backend.** Redis is used as the broker (the queue of messages)
   and also as our status store. Celery's "result backend" is a different,
   optional concept.
2. **`task.delay()` is fire-and-forget.** It serialises the arguments to JSON
   and returns immediately; the worker does the work later.
3. **At-least-once delivery.** A task may run twice if a worker dies after
   starting it. That is why `execute_scan()` writes a complete record instead
   of incrementing counters.
4. **Polling is a feature, not a hack.** It survives proxies, reconnects and
   page refreshes. WebSockets are nicer for live dashboards but add a lot of
   infrastructure for a 20-second job.
5. **Program to an interface.** `MemoryStore` and `RedisStore` expose
   `set/get/update`; the rest of the app cannot tell them apart.

---

## Checkpoint

```powershell
python week2_async_architecture\checkpoint.py
python week2_async_architecture\checkpoint.py http://127.0.0.1:9000
```

It verifies: health endpoint, `202` response, the job reaches `done`, the
result contains the three modules, and a private URL is rejected with `400`.

---

## Exercises

1. Add a `POST /api/scan/<id>/cancel` endpoint that sets a Redis flag; make
   `execute_scan()` check it between modules.
2. Replace polling with Server-Sent Events and compare the code size.
3. Run two Celery workers at once and explain, using `celery inspect active`,
   why the same scan never runs in both.
