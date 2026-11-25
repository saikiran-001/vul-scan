/*
  app.jsx -- the entire React frontend (Week 3 + Week 4).

  React in one paragraph:
    A component is a function that returns markup (JSX). State is data the
    component remembers between renders (useState). When state changes React
    re-runs the component and updates only the parts of the DOM that changed.
    Effects (useEffect) run code after a render, such as starting/stopping a
    polling timer.

  This file is compiled in the browser by Babel (see index.html), so there is
  no npm install and no build step.
*/

// Pull the hooks out of the global React object that index.html loaded.
const { useState, useEffect } = React;

// ---------------------------------------------------------------------------
// API helper -- one place that adds JSON headers and the login token.
// ---------------------------------------------------------------------------
async function api(path, options = {}) {
  // Start with JSON content type; callers may override it.
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };

  // If the user is logged in, attach the bearer token to every request.
  const token = localStorage.getItem("vulnscan_token");
  if (token) headers.Authorization = `Bearer ${token}`;

  // fetch() is the browser's built-in HTTP client.
  const response = await fetch(path, { ...options, headers });

  // Try to parse JSON; an empty body is not an error.
  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = null;
  }

  // Non-2xx status -> throw so the calling component can show a message.
  if (!response.ok) {
    const message = (data && (data.detail || data.message)) || `Request failed (${response.status})`;
    throw new Error(message);
  }
  return data;
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

// Pick a colour for a 0-100 score.
function scoreColor(score) {
  if (score >= 80) return "#34d399";   // green
  if (score >= 60) return "#fbbf24";   // amber
  return "#f87171";                    // red
}

// Format an ISO timestamp for humans. Falls back to the raw string.
function formatDate(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  return isNaN(date.getTime()) ? iso : date.toLocaleString();
}

// Describe the worker mode honestly. If Celery is configured but Redis is
// down, the API silently uses the thread worker -- say so instead of claiming
// "queue: celery" next to "no Redis".
function queueLabel(health) {
  if (!health) return "connecting...";
  if (health.redis) return `queue: ${health.queue} (Redis connected)`;
  if (health.queue === "celery") return "queue: thread (Celery configured, Redis unavailable)";
  return "queue: thread (in-process worker)";
}

// Download the PDF with the auth header, then save it as a blob.
// A plain <a href> cannot send an Authorization header, which is why we fetch.
async function downloadPdf(scanId) {
  const token = localStorage.getItem("vulnscan_token");
  const response = await fetch(`/api/scan/${scanId}/report.pdf`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) throw new Error("Could not generate the PDF.");

  const blob = await response.blob();               // binary PDF data
  const objectUrl = URL.createObjectURL(blob);      // temporary in-memory URL
  const link = document.createElement("a");         // invisible download link
  link.href = objectUrl;
  link.download = `vulnscan-${scanId.slice(0, 8)}.pdf`;
  document.body.appendChild(link);
  link.click();                                     // trigger the save dialog
  link.remove();
  URL.revokeObjectURL(objectUrl);                   // free the memory
}

// ---------------------------------------------------------------------------
// Gauge -- an SVG semicircle that fills up to the score.
// ---------------------------------------------------------------------------
function Gauge({ score, grade }) {
  const color = scoreColor(score);
  return (
    <div>
      <svg viewBox="0 0 200 120" width="100%" role="img" aria-label={`Score ${score} out of 100`}>
        {/* Grey track: a half circle from the left to the right. */}
        <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="#0a1424" strokeWidth="16" strokeLinecap="round" />
        {/* Coloured progress: pathLength=100 lets us use the score directly as a percentage. */}
        <path
          d="M20 100 A80 80 0 0 1 180 100"
          fill="none"
          stroke={color}
          strokeWidth="16"
          strokeLinecap="round"
          pathLength="100"
          strokeDasharray={`${score} 100`}
        />
        {/* The number in the middle. */}
        <text x="100" y="88" textAnchor="middle" fontSize="36" fontWeight="700" fill="#e6edf7">{score}</text>
        <text x="100" y="108" textAnchor="middle" fontSize="11" fill="#93a4bf">out of 100</text>
      </svg>
      <div style={{ fontSize: 26, fontWeight: 800, color, marginTop: 4 }}>Grade {grade}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sparkline -- a tiny line chart of score history.
// ---------------------------------------------------------------------------
function Sparkline({ scans }) {
  // scans arrive newest-first; reverse so the line reads left to right in time.
  const values = [...scans].reverse().map((scan) => scan.score);
  if (values.length < 2) return null;                // a line needs two points

  const width = 100;
  const height = 28;
  const step = width / (values.length - 1);
  // SVG y grows downwards, so a high score must have a small y.
  const points = values
    .map((value, index) => `${(index * step).toFixed(2)},${(height - (value / 100) * height).toFixed(2)}`)
    .join(" ");

  return (
    <svg className="spark" viewBox={`0 0 ${width} ${height}`} width="100%" height="28" preserveAspectRatio="none">
      <polyline points={points} fill="none" stroke="#38bdf8" strokeWidth="2" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// One check row -- <details> gives us expand/collapse for free.
// ---------------------------------------------------------------------------
function CheckRow({ check, moduleTitle }) {
  const remediation = check.remediation || {};
  return (
    <details className="check">
      <summary>
        <span className={`pill ${check.status}`}>{check.status_label}</span>
        <span className="check-title">{check.title}</span>
        <span className="check-module">{moduleTitle}</span>
      </summary>
      <div className="check-body">
        <p>{check.detail}</p>

        {/* The raw value we observed, when there is one. */}
        {check.evidence ? <div className="evidence">{check.evidence}</div> : null}

        {/* Remediation only exists for things worth fixing. */}
        {remediation.why ? <p className="fix mt-8"><b>Why it matters:</b> {remediation.why}</p> : null}
        {remediation.fix ? <p className="fix"><b>How to fix:</b> {remediation.fix}</p> : null}
        {remediation.snippet ? <pre>{remediation.snippet}</pre> : null}
        {remediation.docs ? (
          <p className="mt-8">
            <a href={remediation.docs} target="_blank" rel="noreferrer">Read the documentation</a>
          </p>
        ) : null}
      </div>
    </details>
  );
}

// ---------------------------------------------------------------------------
// Module card -- title, score and a progress bar.
// ---------------------------------------------------------------------------
function ModuleCard({ module }) {
  const color = scoreColor(module.score);
  return (
    <div className="card module">
      <div className="module-head">
        <h3>{module.title}</h3>
        <span className="module-score" style={{ color }}>{module.score}</span>
      </div>
      <div className="module-sub">{Math.round(module.weight * 100)}% of the final score</div>
      <div className="bar"><i style={{ width: `${module.score}%`, background: color }} /></div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Progress card -- shown while the browser polls /status.
// ---------------------------------------------------------------------------
function ProgressCard({ job }) {
  return (
    <div className="card progress-card">
      <div className="progress-row">
        <span>{job.message || "Working..."}</span>
        <span>{job.progress || 0}%</span>
      </div>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${job.progress || 0}%` }} />
      </div>
      <p className="muted mt-8" style={{ fontSize: 12.5 }}>
        Polling <code>/api/scan/{String(job.id).slice(0, 8)}.../status</code> every 2 seconds.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// The full report for a finished scan.
// ---------------------------------------------------------------------------
function Results({ result }) {
  const [pdfState, setPdfState] = useState("");      // "" | "loading" | error text

  async function handleDownload() {
    setPdfState("loading");
    try {
      await downloadPdf(result.id);
      setPdfState("");
    } catch (err) {
      setPdfState(err.message);
    }
  }

  const passed = result.checks.filter((check) => check.passed).length;
  const total = result.checks.length;

  return (
    <div className="mt-16">
      <div className="result-grid">
        {/* Left column: the big score. */}
        <div className="card score-card">
          <h3>Security score</h3>
          <Gauge score={result.score} grade={result.grade} />
          <div className="score-meta">
            {passed} of {total} checks passed
            <br />
            {result.final_url}
            <br />
            HTTP {result.status_code} in {result.duration_ms} ms
          </div>
          <button className="btn btn-ghost btn-small mt-16" onClick={handleDownload} disabled={pdfState === "loading"}>
            {pdfState === "loading" ? "Preparing..." : "Download PDF"}
          </button>
          {pdfState && pdfState !== "loading" ? <div className="error">{pdfState}</div> : null}
        </div>

        {/* Right column: the three modules. */}
        <div className="modules">
          {result.modules.map((module) => <ModuleCard key={module.id} module={module} />)}
        </div>
      </div>

      {/* Every check, grouped by module. */}
      {result.modules.map((module) => {
        const modulePassed = module.checks.filter((check) => check.passed).length;
        return (
          <div className="card checks" key={module.id}>
            <div className="module-head" style={{ padding: "14px 18px 0" }}>
              <h3>{module.title}</h3>
              <span className="muted" style={{ fontSize: 12.5 }}>
                {modulePassed}/{module.checks.length} passed
              </span>
            </div>
            {module.checks.map((check) => (
              <CheckRow key={check.id} check={check} moduleTitle={module.title} />
            ))}
          </div>
        );
      })}

      {/* Transparency: show the redirect chain when there was one. */}
      {result.meta && result.meta.redirects && result.meta.redirects.length > 1 ? (
        <div className="card" style={{ padding: "14px 18px", marginTop: 14 }}>
          <p className="muted" style={{ fontSize: 12.5 }}>
            Redirect chain: {result.meta.redirects.join("  ->  ")}
          </p>
        </div>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// The URL form.
// ---------------------------------------------------------------------------
function ScanForm({ url, setUrl, onScan, scanning }) {
  return (
    <form className="scan-form" onSubmit={onScan}>
      <input
        className="input"
        type="text"
        value={url}
        onChange={(event) => setUrl(event.target.value)}
        placeholder="example.com or https://example.com"
        aria-label="Website URL"
        spellCheck="false"
      />
      <button className="btn btn-primary" type="submit" disabled={scanning}>
        {scanning ? "Scanning..." : "Run scan"}
      </button>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Login / register panel.
// ---------------------------------------------------------------------------
function AuthPanel({ user, onAuth, onLogout }) {
  const [mode, setMode] = useState("login");         // "login" | "register"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (user) {
    // Logged in: show who it is and a logout button.
    return (
      <div className="row">
        <span className="muted" style={{ fontSize: 13 }}>{user.email}</span>
        <button className="btn btn-ghost btn-small" onClick={onLogout}>Log out</button>
      </div>
    );
  }

  async function submit(event) {
    event.preventDefault();                          // stop the browser from reloading the page
    setBusy(true);
    setError("");
    try {
      await onAuth(mode, email, password);           // App handles the API call + token
      setPassword("");                               // never keep the password in state longer than needed
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="auth-form" onSubmit={submit}>
      <input className="input" type="email" placeholder="you@example.com" value={email}
             onChange={(event) => setEmail(event.target.value)} required />
      <input className="input" type="password" placeholder="password (8+ chars)" value={password}
             onChange={(event) => setPassword(event.target.value)} required minLength={8} />
      <button className="btn btn-primary btn-small" type="submit" disabled={busy}>
        {busy ? "..." : mode === "login" ? "Log in" : "Sign up"}
      </button>
      <button
        type="button"
        className="btn btn-ghost btn-small"
        onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(""); }}
      >
        {mode === "login" ? "Create account" : "I have an account"}
      </button>
      {error ? <div className="error" style={{ flexBasis: "100%" }}>{error}</div> : null}
    </form>
  );
}

// ---------------------------------------------------------------------------
// Scan history for the logged-in user.
// ---------------------------------------------------------------------------
function HistoryPanel({ scans, onError }) {
  async function handleDownload(scanId) {
    try {
      await downloadPdf(scanId);
    } catch (err) {
      onError(err.message);
    }
  }

  return (
    <section className="card" style={{ padding: "18px 20px", marginTop: 20 }}>
      <div className="row spread">
        <h3 style={{ fontSize: 15 }}>Your scan history</h3>
        <span className="muted" style={{ fontSize: 12.5 }}>{scans.length} saved scans</span>
      </div>

      <Sparkline scans={scans} />

      {scans.length === 0 ? (
        <p className="muted mt-8" style={{ fontSize: 13 }}>
          Run a scan while logged in and it will appear here.
        </p>
      ) : (
        <div className="history-list">
          {scans.map((scan) => (
            <div className="history-item" key={scan.id}>
              <span className="history-score" style={{ color: scoreColor(scan.score) }}>{scan.score}</span>
              <span className="history-url" title={scan.final_url || scan.url}>{scan.final_url || scan.url}</span>
              <span className="history-date">{formatDate(scan.created_at)}</span>
              <button className="btn btn-ghost btn-small" onClick={() => handleDownload(scan.id)}>PDF</button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// App -- owns all shared state.
// ---------------------------------------------------------------------------
function App() {
  const [url, setUrl] = useState("https://example.com");
  const [job, setJob] = useState(null);              // the current scan job
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [user, setUser] = useState(null);
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState(null);

  // On first render: ask the server which queue mode it is using.
  useEffect(() => {
    api("/api/health").then(setHealth).catch(() => setHealth(null));
  }, []);

  // On first render: if a token is stored, verify it and restore the session.
  useEffect(() => {
    if (!localStorage.getItem("vulnscan_token")) return;
    api("/api/auth/me")
      .then((me) => setUser(me))
      .catch(() => localStorage.removeItem("vulnscan_token"));   // stale token
  }, []);

  // Load history whenever the logged-in user changes.
  useEffect(() => {
    if (!user) {
      setHistory([]);
      return;
    }
    api("/api/history")
      .then((data) => setHistory(data.scans || []))
      .catch(() => setHistory([]));
  }, [user]);

  // Polling loop. Re-runs only when the job id or status changes, NOT on
  // every progress update, otherwise the 2s timer would restart constantly.
  const jobId = job && job.id;
  const jobStatus = job && job.status;

  useEffect(() => {
    if (!jobId || jobStatus === "done" || jobStatus === "error") return undefined;

    const timer = setInterval(async () => {
      try {
        const next = await api(`/api/scan/${jobId}/status`);
        setJob(next);

        if (next.status === "done") {
          setScanning(false);
          if (user) {
            api("/api/history").then((data) => setHistory(data.scans || [])).catch(() => {});
          }
        }
        if (next.status === "error") {
          setScanning(false);
          setError(next.error || next.message || "The scan failed.");
        }
      } catch (err) {
        setError(err.message);
        setScanning(false);
      }
    }, 2000);                                        // the 2 second poll from the brief

    return () => clearInterval(timer);               // cleanup when the effect re-runs
  }, [jobId, jobStatus, user]);

  // Submit the URL: POST once, then let the polling effect take over.
  async function startScan(event) {
    event.preventDefault();
    setError("");
    setJob(null);
    setScanning(true);
    try {
      const created = await api("/api/scan", {
        method: "POST",
        body: JSON.stringify({ url }),
      });
      setJob({ id: created.id, status: "queued", progress: 0, message: "Queued", result: null });
    } catch (err) {
      setError(err.message);
      setScanning(false);
    }
  }

  // Login or register, then store the token.
  async function handleAuth(mode, email, password) {
    const data = await api(`/api/auth/${mode}`, {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    localStorage.setItem("vulnscan_token", data.token);
    setUser(data.user);
  }

  function handleLogout() {
    localStorage.removeItem("vulnscan_token");
    setUser(null);
  }

  return (
    <div className="shell">
      {/* ---------- top bar ---------- */}
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            {/* A shield, drawn with plain SVG so there is no icon library. */}
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
              <path d="M12 3l7 3v5c0 4.4-3 8.3-7 10-4-1.7-7-5.6-7-10V6l7-3z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div>
            <h1>VulnScan Lite</h1>
            <span>Passive web security scanner</span>
          </div>
        </div>
        <AuthPanel user={user} onAuth={handleAuth} onLogout={handleLogout} />
      </header>

      {/* ---------- mandatory disclaimer ---------- */}
      <div className="disclaimer">
        <span aria-hidden="true">!</span>
        <span>
          <b>Only scan websites you own.</b> This tool performs passive analysis only:
          one normal HTTP request and one TLS handshake. No attacks, no exploitation.
        </span>
      </div>

      {/* ---------- hero + form ---------- */}
      <section className="card hero">
        <h2>How healthy is your website's security?</h2>
        <p className="lead">
          Enter a URL to check its security headers, TLS configuration and CMS version.
          You get a score, a letter grade and copy-paste fixes for every failed check.
        </p>
        <ScanForm url={url} setUrl={setUrl} onScan={startScan} scanning={scanning} />
        {error ? <div className="error">{error}</div> : null}
      </section>

      {/* ---------- progress or results ---------- */}
      {job && job.status !== "done" ? <ProgressCard job={job} /> : null}
      {job && job.status === "done" && job.result ? <Results result={job.result} /> : null}

      {/* ---------- history ---------- */}
      {user ? <HistoryPanel scans={history} onError={setError} /> : null}

      {/* ---------- footer ---------- */}
      <footer className="footer">
        <span>VulnScan Lite v1.0 -- passive DAST</span>
        <span>
          {queueLabel(health)}
        </span>
      </footer>
    </div>
  );
}

// Render the app into the #root div from index.html.
ReactDOM.createRoot(document.getElementById("root")).render(<App />);
