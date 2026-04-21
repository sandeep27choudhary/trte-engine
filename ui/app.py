import json
import os
from datetime import datetime, timezone

import requests
import streamlit as st

API_URL = os.environ.get("TRTE_API_URL", "http://localhost:8000")
TIMEOUT = 10
MAX_SCORE = 140

# ── Design tokens (dark / engineer-focused) ───────────────────────────────────
SEV_COLOR  = {"critical": "#EF4444", "high": "#F97316", "medium": "#EAB308", "low": "#22C55E"}
SEV_BG     = {"critical": "#450a0a", "high": "#431407", "medium": "#422006", "low": "#052e16"}
URG_COLOR  = {"now": "#EF4444", "today": "#F97316", "this-week": "#EAB308"}
URG_BG     = {"now": "#450a0a", "today": "#431407", "this-week": "#422006"}
URG_LABEL  = {"now": "NOW", "today": "TODAY", "this-week": "THIS WEEK"}
CRIT_COLOR = {"high": "#EF4444", "medium": "#EAB308", "low": "#22C55E"}
ENV_LABEL  = {"production": "PROD", "staging": "STAGE", "dev": "DEV"}
ENV_COLOR  = {"production": "#EF4444", "staging": "#EAB308", "dev": "#64748B"}
PRI_COLOR  = {"high": "#EF4444", "medium": "#EAB308", "low": "#22C55E"}

def _age(iso_str):
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(str(iso_str).replace("Z", "+00:00"))
        secs = int((datetime.now(tz=timezone.utc) - dt).total_seconds())
        if secs < 60:    return "just now"
        if secs < 3600:  return f"{secs // 60}m ago"
        if secs < 86400: return f"{secs // 3600}h ago"
        return f"{secs // 86400}d ago"
    except Exception:
        return ""

def _badge(text, color, bg):
    return (
        f'<span style="background:{bg};color:{color};border:1px solid {color}44;'
        f'font-family:\'Fira Code\',monospace;font-size:11px;font-weight:600;'
        f'letter-spacing:0.08em;padding:2px 8px;border-radius:4px;">{text}</span>'
    )

def _pill(text, color="#64748B"):
    return (
        f'<span style="color:{color};font-size:11px;font-weight:500;'
        f'font-family:\'Fira Sans\',sans-serif;">{text}</span>'
    )

@st.cache_data(ttl=30)
def _fetch_triage(days=None, scans=None):
    params = {k: v for k, v in {"days": days, "scans": scans}.items() if v is not None}
    try:
        r = requests.get(f"{API_URL}/triage", params=params, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json().get("findings", [])
    except requests.exceptions.RequestException:
        pass
    return []

# ── Page config & CSS ─────────────────────────────────────────────────────────
st.set_page_config(page_title="TRTE", page_icon="🛡", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&display=swap');

:root {
    --bg:        #020617;
    --surface:   #0F172A;
    --surface-2: #1E293B;
    --border:    #334155;
    --fg:        #F8FAFC;
    --fg-muted:  #94A3B8;
    --accent:    #22C55E;
}

/* Base */
.stApp { background-color: var(--bg) !important; }
.stApp, .stApp * { font-family: 'Fira Sans', sans-serif !important; color: var(--fg); }
code, pre, [data-testid="stMetricValue"] { font-family: 'Fira Code', monospace !important; }

/* Hide Streamlit chrome */
#MainMenu, footer, header { visibility: hidden !important; }
.block-container { max-width: 1200px; padding-top: 1.5rem !important; padding-bottom: 3rem !important; }

/* Metrics */
[data-testid="stMetric"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    padding: 1rem 1.25rem !important;
}
[data-testid="stMetricValue"] {
    font-size: 1.9rem !important;
    font-weight: 700 !important;
    color: var(--fg) !important;
    line-height: 1.2 !important;
}
[data-testid="stMetricLabel"] p {
    color: var(--fg-muted) !important;
    font-size: 0.65rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.12em !important;
    font-weight: 600 !important;
}

/* Expanders */
[data-testid="stExpander"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    margin-bottom: 6px !important;
}
[data-testid="stExpander"] summary {
    padding: 0.75rem 1rem !important;
    font-family: 'Fira Code', monospace !important;
    font-size: 13px !important;
}
[data-testid="stExpander"] summary:hover { background: var(--surface-2) !important; border-radius: 8px; }
[data-testid="stExpander"] > div > div { padding: 0.75rem 1rem 1rem !important; }

/* Buttons */
.stButton > button {
    background: var(--surface-2) !important;
    border: 1px solid var(--border) !important;
    color: var(--fg) !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
    font-size: 13px !important;
    transition: border-color 180ms ease, color 180ms ease !important;
    cursor: pointer !important;
}
.stButton > button:hover { border-color: var(--accent) !important; color: var(--accent) !important; }
.stButton > button:focus-visible { outline: 2px solid var(--accent) !important; outline-offset: 2px !important; }

/* Run analysis button — primary */
[data-testid="stButton"]:first-child > button[kind="secondary"]:has(svg) { color: var(--accent) !important; }

/* Inputs / selects */
.stTextInput input, .stTextArea textarea, .stSelectbox select,
[data-baseweb="select"] { background: var(--surface-2) !important; border-color: var(--border) !important; color: var(--fg) !important; }
[data-baseweb="select"] * { background: var(--surface-2) !important; color: var(--fg) !important; }

/* Divider */
hr { border-color: var(--border) !important; }

/* Progress bar */
.stProgress > div > div { background: var(--surface-2) !important; border-radius: 4px !important; }
.stProgress > div > div > div { border-radius: 4px !important; }

/* Captions */
[data-testid="stCaptionContainer"] p { color: var(--fg-muted) !important; font-size: 12px !important; }

/* Info / warning / success / error boxes */
[data-testid="stAlert"] { border-radius: 6px !important; border-width: 1px !important; }

/* Spinner */
.stSpinner > div { border-top-color: var(--accent) !important; }

/* Radio */
[data-testid="stRadio"] label { font-size: 13px !important; }

/* Toggle */
[data-testid="stToggle"] label { font-size: 13px !important; }

/* Section headings */
h1 { font-family: 'Fira Code', monospace !important; font-size: 1.4rem !important; font-weight: 700 !important; letter-spacing: -0.02em !important; }
h2, h3 { font-family: 'Fira Code', monospace !important; font-size: 0.85rem !important; font-weight: 600 !important; letter-spacing: 0.1em !important; text-transform: uppercase !important; color: var(--fg-muted) !important; }
</style>
""", unsafe_allow_html=True)

# ── Health check ──────────────────────────────────────────────────────────────
try:
    health_resp = requests.get(f"{API_URL}/health", timeout=TIMEOUT)
    api_ok = health_resp.status_code == 200
except requests.exceptions.RequestException:
    api_ok = False

# ── Header ────────────────────────────────────────────────────────────────────
hcol, scol = st.columns([5, 1])
with hcol:
    st.title("🛡 TRTE — Top Risk Triage Engine")
with scol:
    st.write("")
    if api_ok:
        st.success("● API Online", icon=None)
    else:
        st.error("● API Offline", icon=None)

if not api_ok:
    st.markdown("""
    <div style="background:#450a0a;border:1px solid #ef4444;border-radius:8px;padding:1rem 1.25rem;margin-top:1rem;">
      <p style="margin:0;font-weight:600;color:#ef4444;">Cannot reach the API</p>
      <p style="margin:0.25rem 0 0;color:#fca5a5;font-size:13px;">Run <code>make up</code> in the project directory, then reload this page.</p>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ── Controls ──────────────────────────────────────────────────────────────────
st.divider()
c1, c2, c3, c4, c5, c6 = st.columns([1, 1, 2, 2, 1, 1])
with c1:
    window_type = st.radio("Window", ["Days", "Scans"], horizontal=True, label_visibility="collapsed")
with c2:
    window_val = st.number_input("Val", min_value=1, value=7, label_visibility="collapsed")
with c3:
    env_filter = st.selectbox("Env", ["All environments", "production", "staging", "dev"],
                               label_visibility="collapsed")
with c4:
    sev_filter = st.selectbox("Sev", ["All severities", "critical", "high", "medium", "low"],
                               label_visibility="collapsed")
with c5:
    critical_only = st.toggle("Critical only", value=False)
with c6:
    if st.button("↻  Refresh", use_container_width=True):
        _fetch_triage.clear()
        st.session_state.pop("analysis_map", None)
        st.rerun()

window_params = {"days": int(window_val)} if window_type == "Days" else {"scans": int(window_val)}
all_findings = _fetch_triage(days=window_params.get("days"), scans=window_params.get("scans"))

filtered = all_findings
if env_filter != "All environments":
    filtered = [f for f in filtered if f.get("environment") == env_filter]
if sev_filter != "All severities":
    filtered = [f for f in filtered if f.get("severity") == sev_filter]
if critical_only:
    filtered = [f for f in filtered if f.get("severity") == "critical"]

# ── Stats row ─────────────────────────────────────────────────────────────────
st.divider()
s1, s2, s3, s4 = st.columns(4)
with s1:
    top = max((f["base_score"] for f in filtered), default=None)
    st.metric("Top Risk Score", f"{top}/{MAX_SCORE}" if top is not None else "—")
with s2:
    st.metric("Findings", len(filtered) if filtered else "—")
with s3:
    crit_n = sum(1 for f in filtered if f.get("severity") == "critical")
    st.metric("Critical", crit_n if filtered else "—")
with s4:
    corr_n = sum(1 for f in filtered if f.get("has_correlation"))
    st.metric("Correlated", corr_n if filtered else "—")

# ── Risk Dashboard ────────────────────────────────────────────────────────────
st.divider()
st.subheader("What to fix today")

analysis_map = st.session_state.get("analysis_map", {})

if not filtered:
    if all_findings:
        st.markdown("""
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.5rem;text-align:center;">
          <p style="color:var(--fg-muted);margin:0;font-size:14px;">No findings match the active filters.</p>
          <p style="color:var(--fg-muted);margin:0.25rem 0 0;font-size:12px;">Adjust the environment or severity selectors above.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:2rem;text-align:center;">
          <p style="color:var(--fg-muted);margin:0;font-size:14px;font-weight:500;">No scored findings in this window.</p>
          <p style="color:var(--fg-muted);margin:0.5rem 0 0;font-size:12px;">Ingest findings below → wait ~3s for scoring → click Refresh.</p>
        </div>
        """, unsafe_allow_html=True)
else:
    for i, f in enumerate(filtered):
        sev      = f.get("severity", "unknown")
        env      = f.get("environment", "unknown")
        enr      = analysis_map.get(f["id"]) or f.get("enrichment") or {}
        urgency  = enr.get("urgency", "")
        priority = enr.get("adjusted_priority", "")
        age_str  = _age(f.get("detected_at"))
        score    = f["base_score"]

        # ── Card header ──────────────────────────────────────────────────────
        sev_c   = SEV_COLOR.get(sev, "#64748B")
        sev_bg  = SEV_BG.get(sev, "#1e293b")
        urg_c   = URG_COLOR.get(urgency, "")
        urg_bg  = URG_BG.get(urgency, "")
        urg_lbl = URG_LABEL.get(urgency, "")

        score_pct = min(score / MAX_SCORE, 1.0)
        # color transitions: green→yellow→orange→red
        bar_color = (
            "#22C55E" if score_pct < 0.4 else
            "#EAB308" if score_pct < 0.6 else
            "#F97316" if score_pct < 0.8 else
            "#EF4444"
        )

        vuln_type = f["title"].split(" in ")[0]

        header_html = (
            f'{_badge(sev.upper(), sev_c, sev_bg)}&nbsp;&nbsp;'
            f'<b style="font-size:14px;">#{f["rank"]}&nbsp;&nbsp;{f["service"]}</b>'
            f'&nbsp;<span style="color:var(--fg-muted);font-size:13px;">— {vuln_type}</span>'
            f'&nbsp;&nbsp;{_badge(urg_lbl, urg_c, urg_bg) if urg_lbl else ""}'
            f'&nbsp;&nbsp;<span style="font-family:\'Fira Code\',monospace;font-size:12px;color:var(--fg-muted);">'
            f'{score}/{MAX_SCORE}</span>'
            f'{"&nbsp;&nbsp;⚡" if f.get("has_correlation") else ""}'
            f'&nbsp;&nbsp;<span style="font-size:11px;color:#475569;">{age_str}</span>'
        )

        with st.expander(f"#{f['rank']}  {f['service']}  —  {vuln_type}  {'⚡' if f.get('has_correlation') else ''}  {score}/{MAX_SCORE}", expanded=(i == 0)):

            # Context tags row
            env_c   = ENV_COLOR.get(env, "#64748B")
            env_lbl = ENV_LABEL.get(env, env.upper())
            tags = [
                _badge(env_lbl, env_c, "#0f172a"),
                _badge(sev.upper(), sev_c, sev_bg),
            ]
            if f.get("criticality"):
                cc = CRIT_COLOR.get(f["criticality"], "#64748B")
                tags.append(_pill(f"Criticality: {f['criticality'].upper()}", cc))
            if f.get("internet_exposed"):
                tags.append(_pill("🌐 Internet-exposed", "#60A5FA"))
            if f.get("sensitive_data"):
                tags.append(_pill("🔒 Sensitive data", "#A78BFA"))
            if f.get("owner"):
                tags.append(_pill(f"👤 {f['owner']}", "#94A3B8"))
            if age_str:
                tags.append(_pill(f"🕐 {age_str}", "#64748B"))

            st.markdown(
                '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px;">'
                + "".join(tags)
                + "</div>",
                unsafe_allow_html=True,
            )

            # Score bar
            st.markdown(
                f'<div style="background:#1e293b;border-radius:4px;height:6px;margin-bottom:14px;">'
                f'<div style="background:{bar_color};width:{score_pct*100:.0f}%;height:6px;border-radius:4px;'
                f'transition:width 300ms ease;"></div></div>'
                f'<p style="font-family:\'Fira Code\',monospace;font-size:11px;color:#64748b;margin-top:-10px;margin-bottom:12px;">'
                f'Risk score {score} / {MAX_SCORE}</p>',
                unsafe_allow_html=True,
            )

            # Correlation notes
            if f.get("has_correlation") and f.get("correlation_notes"):
                notes_html = "".join(
                    f'<li style="color:#FCD34D;font-size:12px;margin-bottom:3px;">{n}</li>'
                    for n in f["correlation_notes"]
                )
                st.markdown(
                    f'<div style="background:#1c1708;border:1px solid #92400e;border-radius:6px;'
                    f'padding:10px 14px;margin-bottom:12px;">'
                    f'<p style="color:#FCD34D;font-size:11px;font-weight:600;margin:0 0 6px;'
                    f'letter-spacing:0.08em;text-transform:uppercase;">⚡ Attack Path Correlations</p>'
                    f'<ul style="margin:0;padding-left:16px;">{notes_html}</ul></div>',
                    unsafe_allow_html=True,
                )

            # Enrichment
            if enr:
                exp_col, fix_col = st.columns(2)

                with exp_col:
                    exp_level = enr.get("exploitability", "")
                    pri_c = PRI_COLOR.get(priority, "#64748B")
                    meta_parts = []
                    if priority:
                        meta_parts.append(f'Priority&nbsp;{_badge(priority.upper(), pri_c, "#0f172a")}')
                    if exp_level:
                        meta_parts.append(f'Exploitability&nbsp;{_badge(exp_level, "#60A5FA", "#0c1a2e")}')
                    if meta_parts:
                        st.markdown(
                            '<p style="font-size:12px;margin-bottom:10px;">'
                            + "&nbsp;&nbsp;|&nbsp;&nbsp;".join(meta_parts)
                            + "</p>",
                            unsafe_allow_html=True,
                        )

                    reason = enr.get("reason", "")
                    if reason:
                        st.markdown(
                            f'<div style="background:#0f172a;border-left:3px solid #3B82F6;'
                            f'padding:8px 12px;border-radius:0 4px 4px 0;margin-bottom:8px;">'
                            f'<p style="color:#94A3B8;font-size:10px;font-weight:600;'
                            f'text-transform:uppercase;letter-spacing:0.1em;margin:0 0 4px;">Why it matters</p>'
                            f'<p style="color:#CBD5E1;font-size:13px;margin:0;">{reason}</p></div>',
                            unsafe_allow_html=True,
                        )

                    combined = enr.get("combined_risk")
                    if combined:
                        st.markdown(
                            f'<div style="background:#1c1708;border-left:3px solid #F59E0B;'
                            f'padding:8px 12px;border-radius:0 4px 4px 0;">'
                            f'<p style="color:#F59E0B;font-size:10px;font-weight:600;'
                            f'text-transform:uppercase;letter-spacing:0.1em;margin:0 0 4px;">Combined Risk</p>'
                            f'<p style="color:#FCD34D;font-size:13px;margin:0;">{combined}</p></div>',
                            unsafe_allow_html=True,
                        )

                with fix_col:
                    fix = enr.get("fix", "")
                    if fix:
                        st.markdown(
                            f'<div style="background:#052e16;border-left:3px solid #22C55E;'
                            f'padding:8px 12px;border-radius:0 4px 4px 0;">'
                            f'<p style="color:#22C55E;font-size:10px;font-weight:600;'
                            f'text-transform:uppercase;letter-spacing:0.1em;margin:0 0 4px;">Recommended Fix</p>'
                            f'<p style="color:#86EFAC;font-size:13px;margin:0;">{fix}</p></div>',
                            unsafe_allow_html=True,
                        )
            else:
                st.markdown(
                    '<p style="color:#475569;font-size:12px;font-style:italic;margin:0;">'
                    'No LLM analysis yet — click Run Analysis below to enrich this finding.</p>',
                    unsafe_allow_html=True,
                )

# ── Correlated findings summary ───────────────────────────────────────────────
corr_findings = [f for f in filtered if f.get("has_correlation")]
if corr_findings:
    st.divider()
    with st.expander(f"⚡ Combined Risk Summary — {len(corr_findings)} correlated finding(s)"):
        for f in corr_findings:
            sev = f.get("severity", "unknown")
            sev_c = SEV_COLOR.get(sev, "#64748B")
            sev_bg = SEV_BG.get(sev, "#1e293b")
            st.markdown(
                f'{_badge(sev.upper(), sev_c, sev_bg)}&nbsp;&nbsp;'
                f'<b>#{f["rank"]} {f["service"]}</b>&nbsp;'
                f'<span style="color:#64748B;font-size:13px;">— {f["title"].split(" in ")[0]}</span>',
                unsafe_allow_html=True,
            )
            for note in f.get("correlation_notes", []):
                st.markdown(
                    f'<p style="color:#94A3B8;font-size:12px;margin:2px 0 4px 16px;">↳ {note}</p>',
                    unsafe_allow_html=True,
                )

# ── LLM Analysis ──────────────────────────────────────────────────────────────
st.divider()
st.subheader("LLM Analysis")
st.caption("Enriches top findings with exploitability + fix. Cached in Redis (24h). Slack alert fires when SLACK_WEBHOOK_URL is set.")

run_col, clear_col = st.columns([3, 1])
with run_col:
    run_analysis = st.button("▶  Run Analysis", use_container_width=True)
with clear_col:
    if st.button("✕  Clear", use_container_width=True):
        st.session_state.pop("analysis_map", None)
        st.rerun()

if run_analysis:
    with st.spinner("Calling LLM — cached after first run…"):
        try:
            a_resp = requests.post(f"{API_URL}/triage/analyze", json=window_params, timeout=30)
            if a_resp.status_code == 200:
                enriched = a_resp.json().get("findings", [])
                new_map = {f["id"]: f["enrichment"] for f in enriched if f.get("enrichment")}
                st.session_state["analysis_map"] = new_map
                st.success(f"✓ {len(new_map)} findings enriched — scroll up to see results in the risk cards.")
                st.rerun()
            else:
                st.error(f"API error {a_resp.status_code}: {a_resp.text}")
        except requests.exceptions.Timeout:
            st.error("Request timed out. LLM provider may be slow — try again.")
        except Exception as e:
            st.error(f"Request failed: {e}")

# ── Ingest (collapsed, secondary) ─────────────────────────────────────────────
st.divider()
with st.expander("📥  Ingest Findings"):
    scanner = st.text_input("Scanner name", value="trivy")

    _sample_path = os.path.join(os.path.dirname(__file__), "sample_findings.json")
    try:
        with open(_sample_path) as _f:
            _sample = json.load(_f)
        _sample_json = json.dumps(_sample["findings"], indent=2)
        _sample_ok = True
    except (FileNotFoundError, json.JSONDecodeError):
        _sample_json = ""
        _sample_ok = False

    if _sample_ok and st.button("📋  Load Sample"):
        st.session_state["findings_json"] = _sample_json
    elif not _sample_ok:
        st.warning("sample_findings.json not found — Load Sample unavailable.")

    findings_input = st.text_area(
        "Findings JSON (array)",
        value=st.session_state.get("findings_json", ""),
        height=140,
        placeholder='[{"id": "vuln-001", "service": "payment-api", "severity": "critical", ...}]',
    )

    sub_col, wh_col = st.columns(2)
    with sub_col:
        if st.button("🚀  Submit Findings", use_container_width=True):
            findings = None
            try:
                findings = json.loads(findings_input)
                if not isinstance(findings, list):
                    st.error("JSON must be an array of findings.")
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
                            f"✓ Ingested {data['count']} findings "
                            f"(normalized: {data.get('normalized', data['count'])}) "
                            f"· scan_run_id: {data['scan_run_id']}"
                        )
                        _fetch_triage.clear()
                    else:
                        st.error(f"API error {resp.status_code}: {resp.text}")
                except Exception as e:
                    st.error(f"Request failed: {e}")
    with wh_col:
        st.caption("Webhook endpoint: `POST /webhook/findings` — accepts any scanner format.")
