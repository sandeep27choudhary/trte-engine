from typing import Literal, Optional
from pydantic import BaseModel


class Finding(BaseModel):
    id: str
    service: str
    severity: str
    type: str
    environment: str
    internet_exposed: bool = False
    sensitive_data: bool = False
    cve: Optional[str] = None
    description: str


class IngestRequest(BaseModel):
    scanner: str
    findings: list[Finding]


class IngestResponse(BaseModel):
    scan_run_id: str
    count: int


class Enrichment(BaseModel):
    exploitability: str
    fix: str
    urgency: Literal["now", "today", "this-week"]


class ScoredFinding(BaseModel):
    rank: int
    id: str
    service: str
    title: str
    severity: str
    base_score: int
    enrichment: Optional[Enrichment] = None


class TriageResponse(BaseModel):
    findings: list[ScoredFinding]


class AnalyzeRequest(BaseModel):
    days: Optional[int] = None
    scans: Optional[int] = None
