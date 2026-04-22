from typing import Literal, Optional
from pydantic import BaseModel


class FindingContext(BaseModel):
    criticality: Optional[Literal["high", "medium", "low"]] = None
    public_facing: Optional[bool] = None
    owner: Optional[str] = None


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
    context: Optional[FindingContext] = None


class IngestRequest(BaseModel):
    scanner: str
    findings: list[Finding]


class IngestResponse(BaseModel):
    scan_run_id: str
    count: int
    normalized: int
    deduplicated: int


class Enrichment(BaseModel):
    exploitability: str
    reason: Optional[str] = None
    fix: str
    urgency: Literal["now", "today", "this-week"]
    adjusted_priority: Optional[Literal["high", "medium", "low"]] = None
    combined_risk: Optional[str] = None


class ScoredFinding(BaseModel):
    rank: int
    id: str
    service: str
    title: str
    severity: str
    base_score: int
    environment: str = "unknown"
    internet_exposed: bool = False
    sensitive_data: bool = False
    criticality: Optional[str] = None
    owner: Optional[str] = None
    detected_at: Optional[str] = None
    why_ranked: list[str] = []
    combined_risk: Optional[str] = None
    correlation_notes: list[str] = []
    has_correlation: bool = False
    enrichment: Optional[Enrichment] = None


class TriageResponse(BaseModel):
    findings: list[ScoredFinding]


class AnalyzeRequest(BaseModel):
    days: Optional[int] = None
    scans: Optional[int] = None


# Webhook ingestion — flexible schema for external scanners
class WebhookFinding(BaseModel):
    id: Optional[str] = None
    service: Optional[str] = None
    severity: Optional[str] = None
    type: Optional[str] = None
    environment: Optional[str] = None
    internet_exposed: Optional[bool] = False
    sensitive_data: Optional[bool] = False
    cve: Optional[str] = None
    description: Optional[str] = None


class WebhookIngestRequest(BaseModel):
    scanner: str
    findings: list[WebhookFinding]
