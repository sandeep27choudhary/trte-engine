# TRTE UI — Streamlit Dashboard: Design Spec
**Date:** 2026-04-19  
**Status:** Approved

---

## Overview

A single-file Streamlit app (`ui/app.py`) that lets users see and test every TRTE feature through a browser UI. It talks to the existing FastAPI backend via HTTP. No changes to the API are required.

---

## Architecture

```
[Browser] → Streamlit (streamlit run ui/app.py)
                │
                │ HTTP requests (requests library)
                ▼
           FastAPI API (localhost:8000)
           ├── GET  /health
           ├── POST /findings
           ├── GET  /triage
           └── POST /triage/analyze
```

`API_URL` is read from `TRTE_API_URL` env var, defaulting to `http://localhost:8000`. No new Docker service — the UI runs as a local process alongside the stack.

---

## File Structure

```
trte-engine/
└── ui/
    ├── app.py                  # single Streamlit app — all UI logic
    ├── requirements.txt        # streamlit, requests
    └── sample_findings.json    # pre-built 3-finding sample for "Load Sample" button
```

**Run command:**
```bash
pip install -r ui/requirements.txt && streamlit run ui/app.py
```

---

## Page Layout (single scrollable page)

### 1. Header
- App title: "🛡 TRTE — Top Risk Triage Engine"
- Live health badge: polls `GET /health` on load → green `● API Online` or red `● API Offline`
- API URL shown next to badge (from `TRTE_API_URL`)

### 2. Stats Row (3 metric cards)
Fetches from `GET /triage?days=7` on load:
- **Top Score** — highest `base_score` in the current window
- **Findings** — total count of results returned
- **Critical** — count of findings with `severity == "critical"`

If triage returns empty, all cards show `—`.

### 3. Ingest Findings
- **Scanner name** — text input, default `"trivy"`
- **📋 Load Sample** button — prefills the textarea with `sample_findings.json` content (the 3-finding smoke test payload)
- **Findings JSON** — multiline textarea, expects a JSON array
- Client-side JSON validation before submit — shows inline red error if invalid
- **🚀 Submit Findings** button → `POST /findings` → shows success banner with `scan_run_id` and count, or error message on failure

### 4. Top 5 Triage
- **Window selector** — radio: `Days` / `Scans`, number input (default: `days=7`)
- **↻ Refresh** button → re-fetches `GET /triage`
- **Results table** columns: `#` · `Service · Type` · `Severity` (colored badge) · `Score` · `Flags` (🌐 for internet_exposed, 🔒 for sensitive_data)
- Empty state: "No scored findings yet. Ingest some findings and wait a moment for the worker to score them."

### 5. LLM Analysis
- **▶ Run Analysis** button → `POST /triage/analyze` with the same window params set in the Triage section above (days/scans values are shared state)
- Result: one expandable card per finding (collapsed by default, first expanded):
  - Header: `#rank · service · type` + urgency chip (NOW=red, TODAY=orange, THIS-WEEK=yellow)
  - Body: two columns — **Exploitability** + **Fix**
- If `enrichment` is `null`: card shows "Enrichment unavailable — configure `LLM_PROVIDER` and API key in `.env`"
- Informational note: "Results are cached in Redis — repeated calls for the same findings are instant"

---

## Error Handling

| Scenario | Behaviour |
|---|---|
| API offline | Red `● API Offline` badge; warning banner in each section instead of content |
| No scored findings | Empty state message in Triage section |
| `enrichment: null` from API | Per-card "unavailable" message in Analyze section |
| Invalid JSON in textarea | Inline red error before submit, no API call made |
| Network timeout | `requests` timeout = 10s; friendly per-section error message |

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `TRTE_API_URL` | `http://localhost:8000` | FastAPI backend URL |

---

## Sample Findings (`ui/sample_findings.json`)

```json
{
  "scanner": "trivy",
  "findings": [
    {
      "id": "vuln-001",
      "service": "payment-api",
      "severity": "critical",
      "type": "SQL Injection",
      "environment": "production",
      "internet_exposed": true,
      "sensitive_data": true,
      "cve": "CVE-2024-1234",
      "description": "Unsanitized input in login endpoint"
    },
    {
      "id": "vuln-002",
      "service": "auth-service",
      "severity": "high",
      "type": "XSS",
      "environment": "production",
      "internet_exposed": false,
      "sensitive_data": true,
      "description": "Reflected XSS in search param"
    },
    {
      "id": "vuln-003",
      "service": "reporting-api",
      "severity": "medium",
      "type": "SSRF",
      "environment": "staging",
      "internet_exposed": true,
      "sensitive_data": false,
      "description": "Unvalidated URL in webhook handler"
    }
  ]
}
```
