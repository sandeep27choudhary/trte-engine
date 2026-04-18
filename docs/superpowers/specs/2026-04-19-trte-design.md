# TRTE — Top Risk Triage Engine: Design Spec
**Date:** 2026-04-19  
**Status:** Approved

---

## Overview

TRTE is a lightweight AI-assisted security triage system. It ingests vulnerability JSON findings from automated CI scanners, scores them via a deterministic rule engine, and optionally enriches the top candidates with LLM reasoning. The output is the top 5 most exploitable risks with fix suggestions and urgency labels.

---

## Architecture

```
[Scanner CI] → POST /findings → FastAPI API
                                     │
                              Postgres (findings table)
                                     │
                              Redis job queue (trte:score_queue)
                                     │
                              Worker process
                              ├─ Rule Engine → base_score per finding
                              └─ stores scored results in Postgres

[Client] → GET /triage?days=N   → reads top 5 from Postgres (pre-scored, no LLM)
[Client] → POST /triage/analyze → Rule Engine + LLM wrapper
                                    └─ checks Redis cache (sha256 of finding)
                                    └─ on miss: calls LLM provider
                                    └─ stores in Redis (TTL 24h), returns enriched top 5
```

**Key properties:**
- Ingest is fire-and-forget — scanner receives HTTP 202 immediately; scoring is async
- `GET /triage` is always fast — reads pre-scored DB rows, no LLM involved
- `POST /triage/analyze` is the only LLM-touching path; Redis cache makes repeated calls free
- LLM failure degrades gracefully — returns top 5 with `enrichment: null`, HTTP 200

---

## Data Model

### Postgres Tables

**`scan_runs`**
```
id          uuid PRIMARY KEY DEFAULT gen_random_uuid()
scanner     varchar(255)
created_at  timestamptz DEFAULT now()
```

**`findings`**
```
id              varchar(255)           -- from payload, e.g. "vuln-001"
scan_run_id     uuid REFERENCES scan_runs(id)
service         varchar(255)
severity        varchar(50)            -- critical / high / medium / low
type            varchar(255)
environment     varchar(100)
internet_exposed boolean DEFAULT false
sensitive_data   boolean DEFAULT false
cve             varchar(50) NULLABLE
description     text
base_score      int NULLABLE           -- null until worker processes
scored_at       timestamptz NULLABLE
raw             jsonb                  -- full original payload
created_at      timestamptz DEFAULT now()
PRIMARY KEY (id, scan_run_id)
```

**Deduplication:** findings are keyed by `(id, scan_run_id)`. The same vuln-id across multiple scan runs is intentional — it tracks recurrence over time. No cross-run deduplication in MVP.

### Redis Keys

| Key pattern | Type | TTL | Purpose |
|---|---|---|---|
| `trte:score_queue` | List | — | Worker job queue (LPUSH/BRPOP) |
| `trte:llm:{sha256}` | String | 24h (configurable) | LLM response cache |

Cache key is `sha256` of the canonical JSON of the finding dict (sorted keys), making it deterministic regardless of field insertion order.

---

## Rule Engine

**File:** `worker/rule_engine.py`  
**Interface:** `score(finding: dict) -> int` — pure function, no I/O.

### Scoring Rules

```
environment == "production"  → +40
internet_exposed == True     → +30
sensitive_data == True       → +20

severity:
  "critical" → +30
  "high"     → +20
  "medium"   → +10
  "low"      → +2
  (unknown)  → +0
```

Missing or null fields default to 0 contribution (no KeyError).

### Triage Window (GET /triage)

| Query param | Behavior |
|---|---|
| `?days=N` | findings where `scan_runs.created_at >= now() - N days` |
| `?scans=N` | findings from the N most recent `scan_run_id`s |
| _(none)_ | defaults to `?days=7` |

**Top-5 selection:** `ORDER BY base_score DESC, created_at DESC LIMIT 5` within window. Tie-broken by recency.

---

## LLM Wrapper

**File:** `worker/llm_wrapper.py`  
**Interface:** `analyze(findings: list[dict]) -> list[EnrichedFinding]` — same signature for all providers.

### Provider Selection

Configured via `LLM_PROVIDER` env var at startup. Unknown value → fail fast with a clear error.

| `LLM_PROVIDER` | Required env var | Default model |
|---|---|---|
| `openai` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-haiku-4-5-20251001` |
| `openrouter` | `OPENROUTER_API_KEY` | `OPENROUTER_MODEL` env var |

Adding a new provider = one new class implementing the `LLMProvider` interface. Nothing else changes.

### Prompt Design

Each finding compressed to one line:
```
{id} | {service} | {severity} | {type} | {environment} | exposed={internet_exposed} | sensitive={sensitive_data} | {cve} | "{description}"
```

System prompt requests a JSON array of 5 objects with fields: `exploitability`, `fix`, `urgency` (`now`/`today`/`this-week`).

### Caching

- On request: compute `sha256` of canonical finding JSON, check `trte:llm:{hash}` in Redis
- Cache hit → return immediately, no LLM call
- Cache miss → call provider, parse response, write to Redis with TTL, return
- TTL default: 86400s (24h), configurable via `REDIS_LLM_TTL_SECONDS`

---

## API Contracts

### POST /findings
**Body:** `{ "scanner": "trivy", "findings": [ ...array of finding objects... ] }`  
**Response:** `202 Accepted` — `{ "scan_run_id": "uuid", "count": N }`  
Writes to Postgres, enqueues scoring job in Redis. Returns immediately.

### GET /triage
**Query params:** `days=N` or `scans=N` (default: `days=7`)  
**Response:** `200` — array of up to 5 scored findings, ordered by `base_score DESC`.  
No LLM involved. Fast path.

### POST /triage/analyze
**Body:** `{ "days": 7 }` or `{ "scans": 3 }` — omit for default (`days=7`)  
**Response:** `200` — array of up to 5 enriched findings including `exploitability`, `fix`, `urgency`.  
On LLM failure: returns findings with `enrichment: null`, still HTTP 200.

### GET /health
**Response:** `200` — `{ "status": "ok", "db": "ok", "redis": "ok" }`

---

## Input / Output Schemas

### Finding (input)
```json
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
```

### Enriched Finding (output)
```json
{
  "rank": 1,
  "id": "vuln-001",
  "service": "payment-api",
  "title": "SQL Injection in payment-api",
  "severity": "critical",
  "base_score": 120,
  "exploitability": "...",
  "fix": "...",
  "urgency": "now",
  "enrichment": null
}
```

---

## Project Structure

```
trte-engine/
├── docker-compose.yml
├── .env.example
├── api/
│   ├── Dockerfile
│   ├── main.py          # FastAPI app, route definitions only
│   ├── models.py        # Pydantic input/output schemas
│   ├── db.py            # Postgres connection + query helpers
│   └── queue.py         # Redis LPUSH helper for job queue
├── worker/
│   ├── Dockerfile
│   ├── main.py          # BRPOP loop — consumes queue, orchestrates scoring
│   ├── rule_engine.py   # Pure scoring function score(finding) -> int
│   └── llm_wrapper.py   # Provider-switchable LLM client + Redis cache
├── tests/
│   └── test_rule_engine.py   # Unit tests for scoring logic
└── docs/
    └── superpowers/specs/
        └── 2026-04-19-trte-design.md
```

---

## Error Handling

| Scenario | Behavior |
|---|---|
| Malformed finding in batch | Skip that finding, log warning, continue processing rest |
| Unknown `LLM_PROVIDER` | Fail fast at startup with clear error message |
| LLM API call fails | Return findings with `enrichment: null`, HTTP 200 (degraded mode) |
| Redis unavailable | Log error; LLM cache disabled, calls pass through to provider |
| Postgres unavailable | HTTP 503 on all endpoints |

---

## Testing

**Unit tests** (`tests/test_rule_engine.py`):
- All severity levels (critical/high/medium/low/unknown)
- All boolean flag combinations (internet_exposed, sensitive_data)
- Environment == production vs. other
- Missing/null fields default to 0
- Max score combination (120)

No DB or network required — `score()` is a pure function.

---

## Configuration (.env.example)

```env
# Database
DATABASE_URL=postgresql://trte:trte@postgres:5432/trte

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_LLM_TTL_SECONDS=86400

# LLM Provider (openai | anthropic | openrouter)
LLM_PROVIDER=openai
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openai/gpt-4o-mini

# Worker
SCORE_TOP_N=10    # how many top findings to send to LLM (pre-filter before prompt)
```
