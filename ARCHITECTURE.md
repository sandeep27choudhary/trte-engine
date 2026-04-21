# TRTE — Top Risk Triage Engine

> An AI-assisted security vulnerability triage system. Ingests scanner findings, scores them by risk, and enriches the top results with LLM-generated exploitability analysis and fix suggestions.

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Components](#components)
4. [API Reference](#api-reference)
5. [Scoring Rule Engine](#scoring-rule-engine)
6. [LLM Integration](#llm-integration)
7. [Data Models](#data-models)
8. [Project Structure](#project-structure)
9. [Configuration](#configuration)
10. [Running the Stack](#running-the-stack)
11. [Testing](#testing)
12. [Streamlit UI](#streamlit-ui)

---

## Overview

TRTE ingests vulnerability findings from any security scanner (Trivy, Snyk, etc.), applies a deterministic scoring formula to rank them by real-world risk, and optionally calls an LLM to enrich the top findings with exploitability reasoning and remediation advice.

**Design goals:**
- Deterministic, auditable scoring — no black boxes in the ranking
- Async worker pattern — ingest is instant, scoring happens in the background
- Provider-switchable LLM — OpenAI, Anthropic, or OpenRouter behind a single interface
- Redis caching — LLM results cached 24h per finding, repeated calls are free

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Layer                            │
│                                                                 │
│   Streamlit UI (localhost:8501)    curl / scanner webhook       │
└──────────────────────┬──────────────────────┬───────────────────┘
                       │ HTTP                 │ HTTP
                       ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI — API Service (port 8000)            │
│                                                                 │
│  GET  /health          POST /findings                           │
│  GET  /triage          POST /triage/analyze                     │
└──────┬──────────────────────────────┬───────────────────────────┘
       │ psycopg2                     │ LPUSH / GET
       ▼                              ▼
┌──────────────┐            ┌─────────────────────────────────────┐
│  PostgreSQL  │            │               Redis                 │
│  (port 5432) │            │  Job queue: trte:score_queue        │
│              │            │  LLM cache:  trte:llm:<sha256>      │
│  scan_runs   │            └──────────────────┬──────────────────┘
│  findings    │                               │ BRPOP
└──────┬───────┘            ┌──────────────────▼──────────────────┐
       │                    │        Worker Service                │
       │ UPDATE             │                                      │
       └────────────────────│  rule_engine.score() → base_score   │
                            │  writes back to PostgreSQL          │
                            └──────────────────────────────────────┘

                                    POST /triage/analyze
                                           │
                            ┌──────────────▼──────────────────────┐
                            │         LLM Provider                │
                            │  OpenAI / Anthropic / OpenRouter    │
                            │  Redis cache check before each call │
                            └─────────────────────────────────────┘
```

### Data Flow

**Ingest:**
1. Scanner POSTs findings to `POST /findings`
2. API creates a `scan_run` record in PostgreSQL, inserts all findings
3. API pushes a scoring job onto the Redis queue (`trte:score_queue`) via LPUSH
4. Returns `202 Accepted` with `scan_run_id` immediately

**Scoring (async):**
5. Worker blocks on BRPOP waiting for jobs
6. For each finding in the job, calls `rule_engine.score()` → `base_score`
7. Writes `base_score` back to PostgreSQL via `UPDATE findings`

**Triage:**
8. `GET /triage?days=7` queries PostgreSQL for top-5 findings by `base_score` within the window
9. Returns ranked list with scores

**LLM Analysis:**
10. `POST /triage/analyze` fetches top-10 findings from PostgreSQL
11. For each finding, checks Redis cache (`trte:llm:<sha256(finding)>`)
12. Uncached findings are batched into a single LLM call
13. Results are cached in Redis (24h TTL) and returned

---

## Components

### API Service (`api/`)

FastAPI application. Single process, synchronous handlers (no async DB calls needed at MVP scale).

| File | Responsibility |
|---|---|
| `main.py` | Route handlers, FastAPI app, lifespan hook for DB init |
| `models.py` | Pydantic v2 request/response schemas |
| `db.py` | PostgreSQL layer — connection management, all SQL |
| `job_queue.py` | Redis LPUSH wrapper — enqueues scoring jobs |
| `llm_wrapper.py` | LLM provider abstraction + Redis cache logic |
| `requirements.txt` | fastapi, uvicorn, psycopg2, redis, openai, anthropic, pydantic |
| `Dockerfile` | python:3.12-slim, installs deps, runs uvicorn on port 8000 |

### Worker Service (`worker/`)

Long-running process. BRPOP blocks on the Redis queue and scores findings one at a time. Shares `api/db.py` via Docker volume mount to avoid code duplication.

| File | Responsibility |
|---|---|
| `main.py` | BRPOP event loop, per-finding try/except, calls `score()` and `update_finding_score()` |
| `rule_engine.py` | Pure `score(finding: dict) -> int` function — no I/O, fully unit-testable |
| `requirements.txt` | redis, psycopg2 |
| `Dockerfile` | python:3.12-slim, installs deps, runs `python main.py` |

### PostgreSQL

Two tables, created by `init_db()` at API startup:

```sql
CREATE TABLE scan_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scanner TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE findings (
    id TEXT NOT NULL,
    scan_run_id UUID REFERENCES scan_runs(id),
    service TEXT,
    severity TEXT,
    type TEXT,
    environment TEXT,
    internet_exposed BOOLEAN DEFAULT FALSE,
    sensitive_data BOOLEAN DEFAULT FALSE,
    cve TEXT,
    description TEXT,
    base_score INTEGER,
    scored_at TIMESTAMPTZ,
    PRIMARY KEY (id, scan_run_id)
);
```

`ON CONFLICT (id, scan_run_id) DO NOTHING` prevents duplicate ingestion within the same scan run.

### Redis

Two key namespaces:

| Namespace | Type | Purpose | TTL |
|---|---|---|---|
| `trte:score_queue` | List | Worker job queue (LPUSH / BRPOP) | — |
| `trte:llm:<sha256>` | String | LLM enrichment cache per finding | 24h |

Cache key is `sha256` of the canonical JSON of the finding (sorted keys). Same finding content → same key → instant cache hit.

### Streamlit UI (`ui/`)

Single-file browser dashboard. Talks to the FastAPI backend via the `requests` library. No server-side state — all data fetched fresh on each Streamlit rerun.

| File | Responsibility |
|---|---|
| `app.py` | Full Streamlit app — all UI logic in one file |
| `requirements.txt` | streamlit, requests |
| `sample_findings.json` | 3-finding smoke test payload for "Load Sample" button |

---

## API Reference

### `GET /health`

Returns service health.

```json
{ "status": "ok" }
```

---

### `POST /findings`

Ingest vulnerability findings from a scanner.

**Request body:**
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
    }
  ]
}
```

**Response `202 Accepted`:**
```json
{
  "scan_run_id": "05fe87a7-f08c-4553-8dd6-dbddf9edbb5c",
  "count": 1
}
```

---

### `GET /triage`

Return top-5 findings ranked by `base_score`.

**Query params:**

| Param | Type | Description |
|---|---|---|
| `days` | int | Look back N days (default: all time) |
| `scans` | int | Look back N most recent scan runs |

**Response:**
```json
{
  "findings": [
    {
      "rank": 1,
      "id": "vuln-001",
      "service": "payment-api",
      "title": "SQL Injection in payment-api",
      "severity": "critical",
      "base_score": 120,
      "enrichment": null
    }
  ]
}
```

---

### `POST /triage/analyze`

Enrich top findings with LLM exploitability analysis. Results are cached in Redis.

**Request body:**
```json
{ "days": 7 }
```
or
```json
{ "scans": 3 }
```

**Response:** Same shape as `/triage` but `enrichment` is populated:
```json
{
  "findings": [
    {
      "rank": 1,
      "id": "vuln-001",
      "service": "payment-api",
      "title": "SQL Injection in payment-api",
      "severity": "critical",
      "base_score": 120,
      "enrichment": {
        "exploitability": "An attacker could inject arbitrary SQL via the login endpoint...",
        "fix": "Use parameterized queries or an ORM. Sanitize all user inputs.",
        "urgency": "now"
      }
    }
  ]
}
```

`urgency` is always one of: `"now"` | `"today"` | `"this-week"`

---

## Scoring Rule Engine

`worker/rule_engine.py` — pure function, no I/O, deterministic.

```python
def score(finding: dict) -> int
```

| Condition | Points |
|---|---|
| `environment == "production"` | +40 |
| `internet_exposed == true` | +30 |
| `sensitive_data == true` | +20 |
| `severity == "critical"` | +30 |
| `severity == "high"` | +20 |
| `severity == "medium"` | +10 |
| `severity == "low"` | +2 |
| anything else | +0 |

**Score examples:**

| Finding | Breakdown | Total |
|---|---|---|
| Critical, production, internet-exposed, sensitive | 40+30+20+30 | **120** |
| High, production, no internet, sensitive | 40+0+20+20 | **80** |
| Medium, staging, internet-exposed, no sensitive | 0+30+0+10 | **40** |
| Low, staging, no flags | 0+0+0+2 | **2** |

---

## LLM Integration

`api/llm_wrapper.py` implements a provider-switchable LLM layer.

### Provider Interface

```python
class LLMProvider:
    def analyze(self, findings: list[dict]) -> dict[str, Optional[dict]]:
        # Returns {finding_id: enrichment_dict} for all findings
        # Checks Redis cache first; only calls LLM for uncached findings
```

### Providers

| Provider | SDK | Model (default) | Config |
|---|---|---|---|
| `openai` | `openai` Python SDK | `gpt-4o-mini` | `OPENAI_API_KEY`, `OPENAI_MODEL` |
| `anthropic` | `anthropic` Python SDK | `claude-haiku-4-5-20251001` | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |
| `openrouter` | `openai` SDK with `base_url` override | `openai/gpt-4o-mini` | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` |

OpenRouter uses the OpenAI SDK pointed at `https://openrouter.ai/api/v1` — no extra dependency needed.

### Cache Strategy

```
For each finding:
  key = "trte:llm:" + sha256(json.dumps(finding, sort_keys=True))
  if Redis.get(key):
    → return cached result (no LLM call)
  else:
    → batch with other uncached findings for a single LLM call
    → store result in Redis with 24h TTL
```

The LLM is called once per batch of uncached findings (not once per finding), minimizing latency and API cost.

---

## Data Models

```python
class Finding(BaseModel):
    id: str
    service: str
    severity: str           # critical | high | medium | low
    type: str               # SQL Injection, XSS, SSRF, etc.
    environment: str        # production | staging | dev
    internet_exposed: bool = False
    sensitive_data: bool = False
    cve: Optional[str] = None
    description: str

class IngestRequest(BaseModel):
    scanner: str
    findings: list[Finding]

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

class AnalyzeRequest(BaseModel):
    days: Optional[int] = None
    scans: Optional[int] = None
```

---

## Project Structure

```
trte-engine/
├── api/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py           # FastAPI routes
│   ├── models.py         # Pydantic schemas
│   ├── db.py             # PostgreSQL layer
│   ├── job_queue.py      # Redis LPUSH
│   └── llm_wrapper.py    # LLM providers + Redis cache
│
├── worker/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py           # BRPOP event loop
│   └── rule_engine.py    # score() pure function
│
├── ui/
│   ├── app.py            # Streamlit single-page app
│   ├── requirements.txt  # streamlit, requests
│   └── sample_findings.json
│
├── tests/
│   ├── conftest.py
│   └── test_rule_engine.py   # 13 unit tests
│
├── docker-compose.yml
├── Makefile
├── requirements-dev.txt  # pytest
├── .env.example
└── ARCHITECTURE.md
```

---

## Configuration

All configuration is via environment variables (`.env` file for Docker Compose).

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql://trte:trte@postgres:5432/trte` | PostgreSQL connection string |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `REDIS_LLM_TTL_SECONDS` | `86400` | LLM cache TTL (24h) |
| `LLM_PROVIDER` | `openai` | Active provider: `openai` / `anthropic` / `openrouter` |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5-20251001` | Anthropic model |
| `OPENROUTER_API_KEY` | — | OpenRouter API key |
| `OPENROUTER_MODEL` | `openai/gpt-4o-mini` | OpenRouter model slug |
| `SCORE_TOP_N` | `10` | How many findings to pass to the LLM |
| `TRTE_API_URL` | `http://localhost:8000` | API URL for the Streamlit UI |

---

## Running the Stack

**Prerequisites:** Docker, Docker Compose, Python 3.12+

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env — set LLM_PROVIDER and the matching API key
```

### 2. Start all services

```bash
make up
# or: docker compose up --build -d
```

This starts: PostgreSQL, Redis, API (port 8000), Worker.

### 3. Start the UI

```bash
pip install -r ui/requirements.txt
TRTE_API_URL=http://localhost:8000 streamlit run ui/app.py
# Open http://localhost:8501
```

### 4. Stop the stack

```bash
make down
# or: docker compose down
```

### Quick smoke test via curl

```bash
# Ingest 3 findings
curl -s -X POST http://localhost:8000/findings \
  -H "Content-Type: application/json" \
  -d '{
    "scanner": "trivy",
    "findings": [
      {"id":"vuln-001","service":"payment-api","severity":"critical","type":"SQL Injection","environment":"production","internet_exposed":true,"sensitive_data":true,"cve":"CVE-2024-1234","description":"Unsanitized input in login endpoint"},
      {"id":"vuln-002","service":"auth-service","severity":"high","type":"XSS","environment":"production","internet_exposed":false,"sensitive_data":true,"description":"Reflected XSS in search param"},
      {"id":"vuln-003","service":"reporting-api","severity":"medium","type":"SSRF","environment":"staging","internet_exposed":true,"sensitive_data":false,"description":"Unvalidated URL in webhook handler"}
    ]
  }'

# Wait 3s for worker to score, then fetch triage
sleep 3 && curl -s "http://localhost:8000/triage?days=7"

# Run LLM analysis (requires API key)
curl -s -X POST http://localhost:8000/triage/analyze \
  -H "Content-Type: application/json" \
  -d '{"days": 7}'
```

Expected scores: vuln-001 → 120, vuln-002 → 80, vuln-003 → 40.

---

## Testing

Unit tests cover the rule engine — 13 tests across 4 groups.

```bash
# Run tests
PYTHONPATH=worker pytest tests/ -v
```

| Test group | Coverage |
|---|---|
| `TestEnvironment` | production +40, non-production +0 |
| `TestFlags` | internet_exposed +30, sensitive_data +20 |
| `TestSeverity` | critical/high/medium/low/unknown, case-insensitive |
| `TestEdgeCases` | max score = 120, empty dict = 0, None values = 0 |

---

## Streamlit UI

Single-page dashboard at `http://localhost:8501`.

### Sections

**Header** — Live API health badge (polls `GET /health` on every load). Shows green `● API Online` or red `● API Offline`. If offline, the rest of the page is blocked.

**Stats Row** — Three metric cards loaded from `GET /triage?days=7`:
- Top Score — highest `base_score` in the window
- Findings — total count of scored findings
- Critical — count of `severity == "critical"` findings

**Ingest Findings** — Text input for scanner name, textarea for findings JSON, "Load Sample" button to prefill with the 3-finding test payload. Client-side JSON validation before submit. Shows success banner with `scan_run_id` on 202.

**Top 5 Triage** — Radio to select Days/Scans window, number input, Refresh button. Fetches `GET /triage` with selected params. Table columns: `#` · `Service · Type` · `Severity` (colored emoji) · `Score` · `Flags` (🌐 internet-exposed, 🔒 sensitive-data).

**LLM Analysis** — "Run Analysis" button calls `POST /triage/analyze`. Results shown as expandable cards, one per finding. First card is expanded by default. Each card has two columns: Exploitability and Fix. Urgency shown in header: `NOW 🔴` / `TODAY 🟠` / `THIS-WEEK 🟡`. If enrichment is unavailable (no LLM key configured), shows a per-card warning.
