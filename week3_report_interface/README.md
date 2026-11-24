# Week 3 -- The Report Interface

> **Goal:** user experience. Build the results page, implement the 0-100 scoring
> logic and write the "remediation tips" database.

---

## What was built

| File | Responsibility |
|------|----------------|
| `scanner/scoring.py` | Module weights, the final formula and the letter-grade bands. |
| `scanner/remediation.py` | One entry per check id: `why`, `fix`, `snippet`, `docs`. |
| `scanner/engine.py` | Attaches the matching remediation to every check. |
| `web/app.jsx` | The whole UI: form, gauge, module cards, check list, history, auth. |
| `web/styles.css` | Design tokens and layout. |
| `web/index.html` | Loads React + Babel from `web/vendor/`; no build step. |

---

## The report, piece by piece

### 1. The gauge

An SVG semicircle. The trick that makes it simple:

```jsx
<path d="M20 100 A80 80 0 0 1 180 100"
      pathLength="100"
      strokeDasharray={`${score} 100`} />
```

`pathLength="100"` rescales the path so its total length is 100 units. Then
`strokeDasharray="70 100"` means "draw 70 units, leave 100 empty" -- the score
is literally the dash length. No trigonometry, no chart library.

### 2. Module cards

Each module shows its own 0-100 score and its weight (`40%`, `40%`, `20%`), so
the user can see *why* the final number is what it is. A thin bar repeats the
score visually.

### 3. The check list

Every check becomes a `<details>` element:

* the summary row holds the status pill, the title and the module name,
* expanding it reveals the finding, the evidence, and the remediation.

`<details>`/`<summary>` gives keyboard accessibility and expand/collapse with
zero JavaScript state.

### 4. Remediation

For every failure the user gets three things:

* **Why it matters** -- the attack it enables, in one sentence.
* **How to fix** -- the action, in plain English.
* **Snippet** -- a copy-pasteable nginx / Apache / WP-CLI block.

The text lives in `scanner/remediation.py`, keyed by check id. The engine
attaches it, so the web page and the PDF (Week 4) show identical advice.

---

## Scoring, in one place

```
final = headers x 0.40 + ssl x 0.40 + cms x 0.20
```

Grade bands: `93 A`, `90 A-`, `87 B+`, `83 B`, `80 B-`, `77 C+`, `73 C`,
`70 C-`, `67 D+`, `63 D`, `60 D-`, below 60 `F`.

The header module implements the brief's rule literally: 50 baseline,
`+10` per required header present, `-10` per missing one. See
`docs/scanning-logic.md` for the full table.

---

## React in five ideas

1. **Component** = a function returning JSX. `Gauge`, `CheckRow`, `Results`...
2. **State** = data that survives re-renders (`useState`). `job`, `error`, `user`.
3. **Effect** = code that runs after a render (`useEffect`). Used for the
   initial health check and for the polling timer.
4. **Lifting state up.** `App` owns `job`; `Results` and `ProgressCard` only
   receive props. One source of truth.
5. **Cleanup.** The polling effect returns `() => clearInterval(timer)`;
   without it, every re-render would add another timer and the browser would
   send more and more requests.

The polling dependency array is `[jobId, jobStatus]`, **not** `[job]`.
Depending on the whole job object would restart the 2-second timer on every
progress update.

---

## Open it

```powershell
python run.py
```

The browser opens at `http://127.0.0.1:8000`. Scan a site, then:

* click any failed check to read the fix,
* resize the window to see the responsive layout,
* open DevTools -> Network and watch one request every 2 seconds while a scan
  is running.

---

## Checkpoint

```powershell
python week3_report_interface\checkpoint.py
```

It verifies that a real scan contains the three modules with weights summing to
1.0, that every failed check has remediation text and a snippet, and that the
frontend files are actually served.

---

## Exercises

1. Add a **filter** above the check list: "All / Failed only / Passed only".
   (Hint: `useState` in `Results` + `.filter()`.)
2. Add a **copy button** next to each snippet using `navigator.clipboard`.
3. Show the module score as a letter as well as a number, reusing
   `grade_for()` on the server (add it to the module JSON).
4. Make the gauge animate from 0 to the score with a CSS transition on
   `stroke-dasharray`.
