import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from correlator import correlate_as_map
from db import (
    create_scan_run,
    get_latest_scan_run,
    get_scan_run,
    get_top_findings,
    init_db,
    insert_findings,
    update_scan_run_status,
)
from job_queue import enqueue_scoring_job
from llm_wrapper import get_llm_provider
from models import (
    AnalyzeRequest,
    Enrichment,
    IngestRequest,
    IngestResponse,
    ScanStatusResponse,
    ScanSummaryResponse,
    ScoredFinding,
    TriageResponse,
    WebhookFinding,
    WebhookIngestRequest,
)
from normalizer import normalize_finding
from slack_notifier import notify_top_risks
from webhook_parser import parse_webhook_body

_CONTEXT_MAP_PATH = Path(__file__).parent / "context_map.json"

_SEV_PTS  = {"critical": 30, "high": 20, "medium": 10, "low": 2}
_CRIT_PTS = {"high": 20, "medium": 10}


def _load_context_map() -> dict:
    try:
        return json.loads(_CONTEXT_MAP_PATH.read_text())
    except Exception:
        return {}


def _enrich_context(finding: dict, context_map: dict) -> dict:
    if finding.get("context"):
        return finding
    ctx = context_map.get(finding.get("service", "")) or context_map.get("_default")
    if ctx:
        finding = dict(finding)
        finding["context"] = ctx
    return finding


def _build_why_ranked(row: dict) -> list[str]:
    reasons = []
    sev = row.get("severity", "")
    if sev in _SEV_PTS:
        reasons.append(f"{sev.capitalize()} severity (+{_SEV_PTS[sev]} pts)")
    if row.get("environment") == "production":
        reasons.append("Production environment (+40 pts)")
    if row.get("internet_exposed"):
        reasons.append("Internet exposed (+30 pts)")
    if row.get("sensitive_data"):
        reasons.append("Handles sensitive data (+20 pts)")
    raw_ctx = (row.get("raw") or {}).get("context") or {}
    crit = raw_ctx.get("criticality")
    if crit in _CRIT_PTS:
        reasons.append(f"Business criticality: {crit} (+{_CRIT_PTS[crit]} pts)")
    return reasons[:3]


def _build_combined_risk(corr) -> str | None:
    if not corr or not corr.has_correlation or not corr.notes:
        return None
    return corr.notes[0]


def _serialize_dt(val) -> str | None:
    if val is None:
        return None
    return val.isoformat() if hasattr(val, "isoformat") else str(val)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    app.state.context_map = _load_context_map()
    yield


app = FastAPI(title="TRTE — Top Risk Triage Engine", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Ingest (structured) ───────────────────────────────────────────────────────

@app.post("/findings", status_code=202)
def ingest(request: IngestRequest) -> IngestResponse:
    context_map = app.state.context_map
    raw_dicts = [f.model_dump() for f in request.findings]

    normalized = []
    for f in raw_dicts:
        f = normalize_finding(f)
        f = _enrich_context(f, context_map)
        normalized.append(f)

    scan_run_id = create_scan_run(request.scanner, findings_count=len(normalized))
    inserted = insert_findings(scan_run_id, normalized)
    enqueue_scoring_job(scan_run_id, normalized)
    return IngestResponse(
        scan_run_id=scan_run_id,
        count=len(raw_dicts),
        normalized=len(normalized),
        deduplicated=len(raw_dicts) - inserted,
    )


# ── Webhook (flexible scanner format) ────────────────────────────────────────

@app.post("/webhook/findings", status_code=202)
async def webhook_ingest(request: Request) -> IngestResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Request body must be valid JSON"})

    try:
        scanner, raw_findings = parse_webhook_body(body)
    except ValueError as exc:
        return JSONResponse(status_code=422, content={"error": str(exc)})

    context_map = app.state.context_map
    normalized = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        try:
            wf = WebhookFinding(**{k: v for k, v in raw.items() if k in WebhookFinding.model_fields})
        except Exception:
            wf = WebhookFinding()
        cleaned = wf.model_dump(exclude_none=False)
        cleaned = {k: v for k, v in cleaned.items() if v is not None or k in ("internet_exposed", "sensitive_data")}
        f = normalize_finding(cleaned)
        f = _enrich_context(f, context_map)
        normalized.append(f)

    if not normalized:
        return JSONResponse(status_code=422, content={"error": "No valid findings could be parsed from the payload"})

    scan_run_id = create_scan_run(scanner, findings_count=len(normalized))
    inserted = insert_findings(scan_run_id, normalized)
    enqueue_scoring_job(scan_run_id, normalized)
    return IngestResponse(
        scan_run_id=scan_run_id,
        count=len(raw_findings),
        normalized=len(normalized),
        deduplicated=len(raw_findings) - inserted,
    )


# ── Triage ────────────────────────────────────────────────────────────────────

def _scored_finding(rank: int, row: dict, corr=None, enrichment=None) -> ScoredFinding:
    raw_ctx = (row.get("raw") or {}).get("context") or {}
    return ScoredFinding(
        rank=rank,
        id=row["id"],
        service=row["service"],
        title=f"{row['type']} in {row['service']}",
        severity=row["severity"],
        base_score=row["base_score"],
        environment=row.get("environment") or "unknown",
        internet_exposed=bool(row.get("internet_exposed", False)),
        sensitive_data=bool(row.get("sensitive_data", False)),
        criticality=raw_ctx.get("criticality"),
        owner=raw_ctx.get("owner"),
        detected_at=_serialize_dt(row.get("detected_at")),
        why_ranked=_build_why_ranked(row),
        combined_risk=_build_combined_risk(corr),
        correlation_notes=corr.notes if corr else [],
        has_correlation=corr.has_correlation if corr else False,
        enrichment=enrichment,
    )


@app.get("/triage")
def triage(
    days: int = Query(default=None),
    scans: int = Query(default=None),
) -> TriageResponse:
    rows = get_top_findings(days=days, scans=scans, limit=5)
    correlation_map = correlate_as_map(rows)
    findings = [
        _scored_finding(i + 1, row, corr=correlation_map.get(row["id"]))
        for i, row in enumerate(rows)
    ]
    return TriageResponse(findings=findings)


# ── LLM Analyze ───────────────────────────────────────────────────────────────

@app.post("/triage/analyze")
def analyze(
    request: AnalyzeRequest = Body(default=AnalyzeRequest()),
) -> TriageResponse:
    score_top_n = int(os.getenv("SCORE_TOP_N", "10"))
    rows = get_top_findings(days=request.days, scans=request.scans, limit=score_top_n)
    if not rows:
        return TriageResponse(findings=[])

    correlation_map = correlate_as_map(rows)

    enrichment_map: dict = {}
    provider = get_llm_provider()
    if provider is not None:
        try:
            enrichment_map = provider.analyze(rows)
        except Exception as e:
            print(f"[analyze] LLM enrichment failed, continuing without it: {e}")

    findings = []
    for i, row in enumerate(rows[:5]):
        raw_enrichment = enrichment_map.get(row["id"])
        try:
            enrichment = Enrichment(**raw_enrichment) if raw_enrichment else None
        except Exception:
            enrichment = None
        findings.append(
            _scored_finding(i + 1, row, corr=correlation_map.get(row["id"]), enrichment=enrichment)
        )

    # Mark the most recent scan_run as analyzed
    if request.scans is not None or request.days is not None:
        pass  # scoped window — don't mark a specific scan_run
    else:
        latest = get_latest_scan_run()
        if latest and latest["status"] == "scored":
            update_scan_run_status(latest["id"], "analyzed", llm_analyzed=True)

    findings_dicts = [f.model_dump() for f in findings]
    try:
        notify_top_risks(findings_dicts)
    except Exception as e:
        print(f"[analyze] Slack notification failed (non-fatal): {e}")

    return TriageResponse(findings=findings)


# ── Scan Status ───────────────────────────────────────────────────────────────

@app.get("/scan/latest/status")
def latest_scan_status() -> ScanStatusResponse:
    run = get_latest_scan_run()
    if not run:
        raise HTTPException(status_code=404, detail="No scan runs found")
    return ScanStatusResponse(
        scan_run_id=str(run["id"]),
        status=run["status"] or "ingested",
        findings_count=run["findings_count"] or 0,
        scored_count=run["scored_count"] or 0,
        llm_analyzed=bool(run["llm_analyzed"]),
        created_at=_serialize_dt(run.get("created_at")),
        updated_at=_serialize_dt(run.get("updated_at")),
    )


@app.get("/scan/{scan_run_id}/status")
def scan_status(scan_run_id: str) -> ScanStatusResponse:
    run = get_scan_run(scan_run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"scan_run {scan_run_id!r} not found")
    return ScanStatusResponse(
        scan_run_id=str(run["id"]),
        status=run["status"] or "ingested",
        findings_count=run["findings_count"] or 0,
        scored_count=run["scored_count"] or 0,
        llm_analyzed=bool(run["llm_analyzed"]),
        created_at=_serialize_dt(run.get("created_at")),
        updated_at=_serialize_dt(run.get("updated_at")),
    )


@app.get("/scan/{scan_run_id}/summary")
def scan_summary(scan_run_id: str) -> ScanSummaryResponse:
    run = get_scan_run(scan_run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"scan_run {scan_run_id!r} not found")

    status = run["status"] or "ingested"
    scoring_done = status in ("scored", "analyzed")
    llm_done = bool(run["llm_analyzed"])

    top_risks = []
    if scoring_done:
        rows = get_top_findings(scan_run_id=scan_run_id, limit=5)
        correlation_map = correlate_as_map(rows)
        top_risks = [
            _scored_finding(i + 1, row, corr=correlation_map.get(row["id"]))
            for i, row in enumerate(rows)
        ]

    return ScanSummaryResponse(
        scan_run_id=str(run["id"]),
        status=status,
        findings_count=run["findings_count"] or 0,
        scored_count=run["scored_count"] or 0,
        scoring_done=scoring_done,
        llm_done=llm_done,
        top_risks=top_risks,
    )
