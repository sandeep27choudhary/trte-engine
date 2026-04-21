import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, Query

from correlator import correlate_as_map
from db import create_scan_run, get_top_findings, init_db, insert_findings
from job_queue import enqueue_scoring_job
from llm_wrapper import get_llm_provider
from models import (
    AnalyzeRequest,
    Enrichment,
    IngestRequest,
    IngestResponse,
    ScoredFinding,
    TriageResponse,
    WebhookFinding,
    WebhookIngestRequest,
)
from normalizer import normalize_finding
from slack_notifier import notify_top_risks

_CONTEXT_MAP_PATH = Path(__file__).parent / "context_map.json"


def _load_context_map() -> dict:
    try:
        return json.loads(_CONTEXT_MAP_PATH.read_text())
    except Exception:
        return {}


def _enrich_context(finding: dict, context_map: dict) -> dict:
    """Merge service context from context_map if the finding has none."""
    if finding.get("context"):
        return finding
    ctx = context_map.get(finding.get("service", ""))
    if ctx:
        finding = dict(finding)
        finding["context"] = ctx
    return finding


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

    scan_run_id = create_scan_run(request.scanner)
    insert_findings(scan_run_id, normalized)
    enqueue_scoring_job(scan_run_id, normalized)
    return IngestResponse(
        scan_run_id=scan_run_id,
        count=len(normalized),
        normalized=len(normalized),
    )


# ── Webhook (flexible scanner format) ────────────────────────────────────────

@app.post("/webhook/findings", status_code=202)
def webhook_ingest(request: WebhookIngestRequest) -> IngestResponse:
    context_map = app.state.context_map
    normalized = []
    for wf in request.findings:
        raw = wf.model_dump(exclude_none=False)
        raw = {k: v for k, v in raw.items() if v is not None or k in ("internet_exposed", "sensitive_data")}
        f = normalize_finding(raw)
        f = _enrich_context(f, context_map)
        normalized.append(f)

    scan_run_id = create_scan_run(request.scanner)
    insert_findings(scan_run_id, normalized)
    enqueue_scoring_job(scan_run_id, normalized)
    return IngestResponse(
        scan_run_id=scan_run_id,
        count=len(normalized),
        normalized=len(normalized),
    )


# ── Triage ────────────────────────────────────────────────────────────────────

def _scored_finding(rank: int, row: dict, corr=None, enrichment=None) -> ScoredFinding:
    raw_ctx = (row.get("raw") or {}).get("context") or {}
    detected_at = row.get("detected_at")
    if detected_at is not None:
        detected_at = detected_at.isoformat() if hasattr(detected_at, "isoformat") else str(detected_at)
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
        detected_at=detected_at,
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
    provider = get_llm_provider()
    enrichment_map = provider.analyze(rows)

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

    findings_dicts = [f.model_dump() for f in findings]
    notify_top_risks(findings_dicts)

    return TriageResponse(findings=findings)
