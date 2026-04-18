# TRTE UI — Streamlit Dashboard: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-file Streamlit app that lets users test every TRTE API feature through a browser UI.

**Architecture:** `ui/app.py` talks to the FastAPI backend via `requests`. API URL is read from `TRTE_API_URL` env var (default `http://localhost:8000`). No changes to the existing API. Run with `streamlit run ui/app.py`.

**Tech Stack:** Python 3.12, Streamlit, requests.

---

## File Map

| File | Responsibility |
|---|---|
| `ui/requirements.txt` | `streamlit` + `requests` |
| `ui/sample_findings.json` | 3-finding smoke test payload for "Load Sample" button |
| `ui/app.py` | Full Streamlit app — header, stats, ingest, triage, analyze |

---

## Task 1: Scaffold

**Files:**
- Create: `ui/requirements.txt`
- Create: `ui/sample_findings.json`

- [ ] **Step 1: Create `ui/requirements.txt`**

```
streamlit==1.45.0
requests==2.32.3
```

- [ ] **Step 2: Create `ui/sample_findings.json`**

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

- [ ] **Step 3: Install dependencies**

```bash
pip install -r ui/requirements.txt
```

Expected: installs `streamlit` and `requests` without errors.

- [ ] **Step 4: Commit**

```bash
git add ui/requirements.txt ui/sample_findings.json
git commit -m "feat: ui scaffold — requirements and sample findings"
```

---

## Task 2: Full Streamlit App

**Files:**
- Create: `ui/app.py`

- [ ] **Step 1: Create `ui/app.py`**

```python
import json
import os

import requests
import streamlit as st

API_URL = os.environ.get("TRTE_API_URL", "http://localhost:8000")
TIMEOUT = 10

st.set_page_config(
    page_title="TRTE — Top Risk Triage Engine",
    page_icon="🛡",
    layout="wide",
)

# ── Header ────────────────────────────────────────────────────────────────────

st.title("🛡 TRTE — Top Risk Triage Engine")

try:
    health_resp = requests.get(f"{API_URL}/health", timeout=TIMEOUT)
    api_ok = health_resp.status_code == 200
except Exception:
    api_ok = False

if api_ok:
    st.success(f"● API Online · {API_URL}")
else:
    st.error(f"● API Offline · {API_URL}")
    st.warning("Cannot reach the API. Start the stack with `make up` and try again.")
    st.stop()

# ── Stats Row ─────────────────────────────────────────────────────────────────

try:
    triage_resp = requests.get(f"{API_URL}/triage", params={"days": 7}, timeout=TIMEOUT)
    triage_data = triage_resp.json().get("findings", []) if triage_resp.status_code == 200 else []
except Exception:
    triage_data = []

col1, col2, col3 = st.columns(3)
with col1:
    top_score = max((f["base_score"] for f in triage_data), default=None)
    st.metric("Top Score", top_score if top_score is not None else "—", help="Highest base score this week")
with col2:
    st.metric("Findings", len(triage_data), help="Findings in current triage window")
with col3:
    critical_count = sum(1 for f in triage_data if f.get("severity") == "critical")
    st.metric("Critical", critical_count if triage_data else "—", help="Critical severity findings in triage window")

st.divider()

# ── Ingest Findings ───────────────────────────────────────────────────────────

st.subheader("📥 Ingest Findings")

scanner = st.text_input("Scanner name", value="trivy")

_sample_path = os.path.join(os.path.dirname(__file__), "sample_findings.json")
with open(_sample_path) as _f:
    _sample = json.load(_f)
_sample_json = json.dumps(_sample["findings"], indent=2)

if st.button("📋 Load Sample"):
    st.session_state["findings_json"] = _sample_json

findings_input = st.text_area(
    "Findings JSON (array)",
    value=st.session_state.get("findings_json", ""),
    height=150,
    placeholder='[{"id": "vuln-001", "service": "payment-api", ...}]',
)

if st.button("🚀 Submit Findings"):
    findings = None
    try:
        findings = json.loads(findings_input)
        if not isinstance(findings, list):
            st.error("JSON must be an array of findings, not a single object.")
    except json.JSONDecodeError as e:
        st.error(f"Invalid JSON: {e}")

    if findings is not None:
        try:
            resp = requests.post(
                f"{API_URL}/findings",
                json={"scanner": scanner, "findings": findings},
                timeout=TIMEOUT,
            )
            if resp.status_code == 202:
                data = resp.json()
                st.success(
                    f"✓ Ingested {data['count']} findings · scan_run_id: `{data['scan_run_id']}`"
                )
            else:
                st.error(f"API error {resp.status_code}: {resp.text}")
        except Exception as e:
            st.error(f"Request failed: {e}")

st.divider()

# ── Top 5 Triage ──────────────────────────────────────────────────────────────

st.subheader("📊 Top 5 Triage")

col_wtype, col_wval, col_refresh = st.columns([2, 2, 1])
with col_wtype:
    window_type = st.radio("Window type", ["Days", "Scans"], horizontal=True)
with col_wval:
    window_val = st.number_input("Window value", min_value=1, value=7, label_visibility="collapsed")
with col_refresh:
    st.write("")
    st.button("↻ Refresh")

window_params = (
    {"days": int(window_val)} if window_type == "Days" else {"scans": int(window_val)}
)

SEV_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

try:
    t_resp = requests.get(f"{API_URL}/triage", params=window_params, timeout=TIMEOUT)
    findings_list = t_resp.json().get("findings", []) if t_resp.status_code == 200 else []
except Exception as e:
    st.error(f"Triage request failed: {e}")
    findings_list = []

if not findings_list:
    st.info("No scored findings yet. Ingest some findings and wait a moment for the worker to score them.")
else:
    rows = []
    for f in findings_list:
        sev = f.get("severity", "unknown")
        flags = ("🌐 " if f.get("internet_exposed") else "") + ("🔒" if f.get("sensitive_data") else "")
        rows.append({
            "#": f["rank"],
            "Service · Type": f"{f['service']} · {f['title'].split(' in ')[0]}",
            "Severity": f"{SEV_ICONS.get(sev, '⚪')} {sev.upper()}",
            "Score": f["base_score"],
            "Flags": flags.strip() or "—",
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)

st.divider()

# ── LLM Analysis ──────────────────────────────────────────────────────────────

st.subheader("🤖 LLM Analysis")
st.caption(
    "Enriches top findings with exploitability reasoning and fix suggestions. "
    "Results are cached in Redis — repeated calls for the same findings are instant."
)

URGENCY_ICONS = {"now": "🔴", "today": "🟠", "this-week": "🟡"}

if st.button("▶ Run Analysis"):
    with st.spinner("Calling LLM..."):
        try:
            a_resp = requests.post(
                f"{API_URL}/triage/analyze",
                json=window_params,
                timeout=30,
            )
            if a_resp.status_code == 200:
                enriched = a_resp.json().get("findings", [])
                if not enriched:
                    st.info("No findings to analyze in the current window.")
                for i, f in enumerate(enriched):
                    enr = f.get("enrichment")
                    urgency = enr.get("urgency", "") if enr else ""
                    icon = URGENCY_ICONS.get(urgency, "⚪")
                    label = f"#{f['rank']} · {f['service']} · {f['title'].split(' in ')[0]}"
                    header = f"{icon} {label}" + (f" — {urgency.upper()}" if urgency else "")
                    with st.expander(header, expanded=(i == 0)):
                        if enr:
                            col_exp, col_fix = st.columns(2)
                            with col_exp:
                                st.markdown("**Exploitability**")
                                st.write(enr["exploitability"])
                            with col_fix:
                                st.markdown("**Fix**")
                                st.write(enr["fix"])
                        else:
                            st.warning(
                                "Enrichment unavailable — configure `LLM_PROVIDER` "
                                "and the matching API key in `.env`, then restart the stack."
                            )
            else:
                st.error(f"API error {a_resp.status_code}: {a_resp.text}")
        except Exception as e:
            st.error(f"Request failed: {e}")
```

- [ ] **Step 2: Verify the app starts without import errors**

```bash
cd /Users/sandeepchoudhary/Documents/code-repo/trte-engine
python3 -c "import ast; ast.parse(open('ui/app.py').read()); print('Syntax OK')"
```

Expected:
```
Syntax OK
```

- [ ] **Step 3: Start the stack and run the app end-to-end**

In one terminal:
```bash
make up
```

In another terminal:
```bash
TRTE_API_URL=http://localhost:8000 streamlit run ui/app.py
```

Open `http://localhost:8501` in the browser and verify:
- Header shows `● API Online`
- Stats row loads (may show `—` if no findings yet)
- Click "📋 Load Sample" → textarea fills with JSON
- Click "🚀 Submit Findings" → success banner with scan_run_id appears
- Wait 3 seconds, click "↻ Refresh" → 3 findings appear in Triage table with correct scores (vuln-001: 120, vuln-002: 80, vuln-003: 40)
- If LLM key is set: click "▶ Run Analysis" → enrichment cards appear
- If no LLM key: click "▶ Run Analysis" → cards show "Enrichment unavailable" message

- [ ] **Step 4: Verify offline behavior**

Stop the stack:
```bash
make down
```

Reload the browser. Expected: red `● API Offline` badge, warning message, no other sections rendered.

- [ ] **Step 5: Commit**

```bash
git add ui/app.py
git commit -m "feat: streamlit UI — ingest, triage, LLM analyze, health status"
```
