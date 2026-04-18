import os
from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, Query

from db import create_scan_run, get_top_findings, init_db, insert_findings
from llm_wrapper import get_llm_provider
from models import (
    AnalyzeRequest,
    Enrichment,
    IngestRequest,
    IngestResponse,
    ScoredFinding,
    TriageResponse,
)
from job_queue import enqueue_scoring_job


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="TRTE — Top Risk Triage Engine", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/findings", status_code=202)
def ingest(request: IngestRequest) -> IngestResponse:
    scan_run_id = create_scan_run(request.scanner)
    findings_dicts = [f.model_dump() for f in request.findings]
    insert_findings(scan_run_id, findings_dicts)
    enqueue_scoring_job(scan_run_id, findings_dicts)
    return IngestResponse(scan_run_id=scan_run_id, count=len(findings_dicts))


@app.get("/triage")
def triage(
    days: int = Query(default=None),
    scans: int = Query(default=None),
) -> TriageResponse:
    rows = get_top_findings(days=days, scans=scans, limit=5)
    findings = [
        ScoredFinding(
            rank=i + 1,
            id=row["id"],
            service=row["service"],
            title=f"{row['type']} in {row['service']}",
            severity=row["severity"],
            base_score=row["base_score"],
        )
        for i, row in enumerate(rows)
    ]
    return TriageResponse(findings=findings)


@app.post("/triage/analyze")
def analyze(
    request: AnalyzeRequest = Body(default=AnalyzeRequest()),
) -> TriageResponse:
    score_top_n = int(os.getenv("SCORE_TOP_N", "10"))
    rows = get_top_findings(days=request.days, scans=request.scans, limit=score_top_n)
    if not rows:
        return TriageResponse(findings=[])

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
            ScoredFinding(
                rank=i + 1,
                id=row["id"],
                service=row["service"],
                title=f"{row['type']} in {row['service']}",
                severity=row["severity"],
                base_score=row["base_score"],
                enrichment=enrichment,
            )
        )
    return TriageResponse(findings=findings)
