# TRTE — Top Risk Triage Engine

> **Turn scanner noise into an ordered, LLM-enriched action list in seconds.**

TRTE is an open-source security triage platform that ingests findings from any scanner, scores them with a deterministic rule engine, correlates related vulnerabilities, enriches the top risks with LLM reasoning, and delivers a ranked "fix this first" list to your team — with optional Slack delivery.

---

## Table of Contents

- [Why TRTE](#why-trte)
- [What It Does](#what-it-does)
- [Architecture](#architecture)
- [Scoring Model](#scoring-model)
- [LLM Enrichment](#llm-enrichment)
- [Enterprise Integration Guide](#enterprise-integration-guide)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [API Reference](#api-reference)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)

---

## Why TRTE

Security teams at scale face a common problem: **too many findings, not enough signal.**

A typical mid-size engineering org runs 5–15 scanners (SAST, DAST, SCA, container scanning, cloud posture, secrets detection). Each produces hundreds of findings per scan. The result is a backlog of thousands of items where a critical RCE in a public-facing payment service sits next to a low-severity typo in an internal tool — both labeled "High."

TRTE solves this with three layers:

1. **Deterministic scoring** — environment, exposure, data sensitivity, CVE presence, and business context (criticality, ownership) combine into a single integer score. No black boxes.
2. **Correlation detection** — findings that share a service, CVE, or risk pattern are flagged as a cluster, surfacing systemic issues rather than isolated incidents.
3. **LLM enrichment** — the top findings are analyzed by an LLM that adds exploitability context, a specific fix recommendation, urgency classification (`now / today / this-week`), and adjusted priority based on business context.

The output is a ranked list of five findings your team should act on immediately, delivered via dashboard and Slack.

---

## What It Does

```
Scanner Output  →  TRTE API  →  Rule Engine  →  LLM  →  Ranked Action List
     (any)          (ingest)     (scoring)    (enrich)   (dashboard + Slack)
```

**Ingest** — Accepts findings from any scanner via two endpoints:
- `POST /findings` — structured JSON matching the TRTE schema
- `POST /webhook/findings` — flexible schema for tools that emit non-standard formats (Trivy, Snyk, Grype, Checkov, etc.)

**Normalize** — Severity aliases (`CRIT`, `P0`, `p1`), environment aliases (`prod`, `prd`, `production`), and string booleans are all normalized to canonical forms. Missing IDs are auto-generated.

**Score** — A deterministic rule engine assigns a base score (0–140) to every finding. Scores are stored in PostgreSQL and serve as the ranking key.

**Correlate** — Five built-in correlation rules detect clusters: same-service multi-finding, CVE reuse, internet-exposed + sensitive-data combination, production environment clusters, and high-severity bundles.

**Enrich** — The top N findings (configurable, default 10) are sent to an LLM. The LLM returns exploitability context, a specific fix, urgency, adjusted priority, and a combined risk note if correlation was detected.

**Deliver** — The ranked top 5 are shown in the Streamlit dashboard. Optionally posted to Slack as formatted risk cards.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        TRTE Platform                            │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  FastAPI      │    │    Worker    │    │   Streamlit UI   │  │
│  │  :8000        │    │  (BRPOP)     │    │   :8501          │  │
│  │               │    │              │    │                  │  │
│  │  POST         │───▶│  rule_engine │    │  Dashboard       │  │
│  │  /findings    │    │  score()     │    │  Ingest form     │  │
│  │  /webhook/    │    │  update DB   │    │  LLM analyze     │  │
│  │  findings     │    └──────┬───────┘    └────────┬─────────┘  │
│  │               │           │                     │            │
│  │  GET /triage  │    ┌──────▼───────┐    ┌────────▼─────────┐  │
│  │  POST         │    │  PostgreSQL  │    │   HTTP API calls  │  │
│  │  /triage/     │◀───│  findings    │    │   to :8000        │  │
│  │  analyze      │    │  scan_runs   │    └──────────────────┘  │
│  └──────┬────────┘    └──────────────┘                          │
│         │                                                        │
│  ┌──────▼────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Redis        │    │  LLM Provider│    │  Slack Webhook   │  │
│  │  job queue    │    │  OpenAI /    │    │  (optional)      │  │
│  │  cache        │    │  Anthropic / │    └──────────────────┘  │
│  └───────────────┘    │  OpenRouter  │                          │
│                        └──────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

**Services**

| Service | Image | Role |
|---------|-------|------|
| `api` | Python 3.12 + FastAPI | REST API, ingestion, triage, LLM orchestration |
| `worker` | Python 3.12 | Async scorer — BRPOP from Redis, updates DB |
| `ui` | Python 3.12 + Streamlit | Web dashboard |
| `postgres` | PostgreSQL 16 | Persistent finding + scan run storage |
| `redis` | Redis 7 | Scoring job queue + LLM response cache |

---

## Scoring Model

Every finding receives a deterministic integer score. The score is additive — no weights, no machine learning, fully auditable.

| Factor | Condition | Points |
|--------|-----------|--------|
| Severity | `critical` | +30 |
| Severity | `high` | +20 |
| Severity | `medium` | +10 |
| Severity | `low` | +2 |
| Environment | `production` | +40 |
| Exposure | `internet_exposed = true` | +30 |
| Data sensitivity | `sensitive_data = true` | +20 |
| Business criticality | `high` (from context map) | +20 |
| Business criticality | `medium` (from context map) | +10 |
| Public facing | `public_facing = true` (when not internet_exposed) | +15 |

**Maximum score: 140** (critical + production + internet_exposed + sensitive_data + high criticality)

Scores are computed asynchronously by the worker after ingest. The `GET /triage` endpoint returns findings ordered by `base_score DESC`.

### Context Map

A JSON file at `api/context_map.json` enriches findings at ingest time with business context:

```json
{
  "payment-api": {
    "criticality": "high",
    "public_facing": true,
    "owner": "payments-team"
  },
  "auth-service": {
    "criticality": "high",
    "public_facing": true,
    "owner": "identity-team"
  }
}
```

If a finding's `service` field matches a key in this map and the finding has no `context`, the context is automatically merged. This means scanners don't need to know about business context — TRTE enriches it at ingest time.

---

## LLM Enrichment

`POST /triage/analyze` triggers LLM analysis on the top N findings (default: 10). The LLM returns:

| Field | Description |
|-------|-------------|
| `exploitability` | Why this is dangerous in plain language |
| `fix` | Specific, actionable remediation step |
| `urgency` | `now` / `today` / `this-week` |
| `adjusted_priority` | `high` / `medium` / `low` — may differ from raw severity |
| `reason` | Why priority was adjusted (e.g., "no public exposure reduces risk") |
| `combined_risk` | Cross-finding risk note if correlation detected |

Results are cached in Redis (24h TTL) keyed by a SHA-256 hash of the finding content. Repeat calls for the same findings return instantly.

**Supported LLM providers** — set `LLM_PROVIDER` in `.env`:

| Provider | Env var | Notes |
|----------|---------|-------|
| `openrouter` (default) | `OPENROUTER_API_KEY` | Access 100+ models via one key |
| `openai` | `OPENAI_API_KEY` | GPT-4o, GPT-4-turbo |
| `anthropic` | `ANTHROPIC_API_KEY` | Claude 3.5 Sonnet, Claude 3 Opus |

---

## Enterprise Integration Guide

### 1. Push Scanner Output via Webhook

TRTE accepts findings from any scanner that can POST JSON. Most enterprise scanners support webhook or CI integration.

**Structured ingest** (full schema):
```bash
curl -X POST https://trte.your-org.com/findings \
  -H "Content-Type: application/json" \
  -d '{
    "scanner": "snyk",
    "findings": [{
      "id": "snyk-vuln-12345",
      "service": "payment-api",
      "severity": "critical",
      "type": "sql-injection",
      "environment": "production",
      "internet_exposed": true,
      "sensitive_data": true,
      "cve": "CVE-2024-1234",
      "description": "SQL injection in /checkout endpoint allows auth bypass"
    }]
  }'
```

**Flexible webhook** (tolerant schema — ideal for CI pipelines piping raw scanner output):
```bash
curl -X POST https://trte.your-org.com/webhook/findings \
  -H "Content-Type: application/json" \
  -d '{
    "scanner": "trivy",
    "findings": [{
      "id": "trivy-CVE-2024-5678",
      "service": "order-service",
      "severity": "HIGH",
      "type": "container-vuln",
      "environment": "prod",
      "cve": "CVE-2024-5678",
      "description": "OpenSSL heap buffer overflow"
    }]
  }'
```

TRTE normalizes `HIGH` → `high`, `prod` → `production` automatically.

### 2. CI/CD Integration

Add TRTE as a post-scan step in your pipeline to feed findings automatically:

**GitHub Actions**
```yaml
- name: Run Trivy scan
  uses: aquasecurity/trivy-action@master
  with:
    format: json
    output: trivy-results.json

- name: Push findings to TRTE
  run: |
    # Transform Trivy output and POST to TRTE
    python scripts/trivy_to_trte.py trivy-results.json | \
      curl -X POST $TRTE_URL/webhook/findings \
           -H "Content-Type: application/json" \
           -d @-
```

**GitLab CI**
```yaml
push-to-trte:
  stage: security-triage
  script:
    - python scripts/transform.py gl-sast-report.json | curl -X POST $TRTE_URL/webhook/findings -H "Content-Type: application/json" -d @-
  needs: [sast]
```

### 3. Context Map Setup

Create `api/context_map.json` with your organization's service inventory. This is the key integration point that gives TRTE business context:

```json
{
  "checkout-api":       { "criticality": "high",   "public_facing": true,  "owner": "payments-eng" },
  "user-auth-service":  { "criticality": "high",   "public_facing": true,  "owner": "identity-eng" },
  "recommendation-api": { "criticality": "medium",  "public_facing": true,  "owner": "ml-platform" },
  "data-pipeline":      { "criticality": "high",   "public_facing": false, "owner": "data-eng" },
  "internal-admin":     { "criticality": "low",    "public_facing": false, "owner": "platform-eng" }
}
```

This file can be generated automatically from your service catalog (PagerDuty, Backstage, ServiceNow) via a scheduled script.

### 4. Slack Integration

Set `SLACK_WEBHOOK_URL` in your environment. After every `POST /triage/analyze` call, TRTE posts a formatted card to your configured channel with the top 3 risks, scores, urgency, and owner information.

To create a Slack webhook:
1. Go to `api.slack.com/apps` → Create New App → Incoming Webhooks
2. Activate and add to your `#security-triage` channel
3. Copy the webhook URL to `SLACK_WEBHOOK_URL` in `.env`

### 5. Scheduling Automated Triage

Run `POST /triage/analyze` on a schedule to get regular Slack updates without manual triggering:

```bash
# Cron: run LLM triage every morning at 8am and push to Slack
0 8 * * * curl -X POST https://trte.your-org.com/triage/analyze
```

Or using a Kubernetes CronJob:
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: trte-daily-triage
spec:
  schedule: "0 8 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: triage
            image: curlimages/curl
            args: ["-X", "POST", "http://trte-api/triage/analyze"]
```

### 6. Production Deployment

TRTE is fully containerized. For production, consider:

**Environment variables** — Store secrets in your secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) and inject at runtime.

**Database** — Replace the Docker PostgreSQL with a managed database (RDS, Cloud SQL, Azure Database for PostgreSQL). Update `DATABASE_URL` in your environment.

**Redis** — Replace with a managed Redis (ElastiCache, Upstash, Redis Cloud). Update `REDIS_URL`.

**Reverse proxy** — Put the API and UI behind nginx or a cloud load balancer with TLS termination.

**Kubernetes example**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: trte-api
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: api
        image: your-registry/trte-api:latest
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: trte-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: trte-secrets
              key: redis-url
```

### 7. Extending the Scoring Model

Edit `worker/rule_engine.py` to add org-specific scoring rules. The scoring function is a simple integer accumulator — add any rule that makes sense for your risk model:

```python
# Example: add +25 for PCI-scope services
PCI_SERVICES = {"payment-api", "card-processor", "billing-service"}
if finding.get("service") in PCI_SERVICES:
    total += 25

# Example: add +15 for findings with active exploit in CISA KEV
if finding.get("cve") in KEV_CVE_LIST:
    total += 15
```

### 8. Multi-Scanner Correlation

TRTE correlates across scanner sources automatically. If Snyk flags a vulnerable library in `payment-api` and Trivy flags the same CVE in the container image, both findings are scored independently but the correlation engine detects the shared CVE and notes the cluster. The LLM enrichment receives both findings together and can produce a `combined_risk` note explaining the systemic exposure.

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- An LLM API key (OpenRouter recommended — one key for 100+ models)

### 1. Clone and configure

```bash
git clone https://github.com/your-org/trte-engine.git
cd trte-engine
cp .env.example .env
```

Edit `.env`:
```env
DATABASE_URL=postgresql://trte:trte@postgres:5432/trte
REDIS_URL=redis://redis:6379/0
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...  # optional
```

### 2. Start the stack

```bash
docker compose up -d
```

This starts: PostgreSQL, Redis, API (port 8000), Worker, and UI (port 8501).

### 3. Open the dashboard

Navigate to `http://localhost:8501`

### 4. Ingest your first findings

Use the **Ingest** section in the UI, or POST directly to the API:

```bash
curl -X POST http://localhost:8000/findings \
  -H "Content-Type: application/json" \
  -d '{
    "scanner": "demo",
    "findings": [{
      "id": "vuln-001",
      "service": "payment-api",
      "severity": "critical",
      "type": "sql-injection",
      "environment": "production",
      "internet_exposed": true,
      "sensitive_data": true,
      "description": "SQL injection in payment processing endpoint"
    }]
  }'
```

### 5. Run triage

Click **Run LLM Analysis** in the dashboard, or:

```bash
curl -X POST http://localhost:8000/triage/analyze
```

---

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `REDIS_URL` | Yes | — | Redis connection string |
| `LLM_PROVIDER` | No | `openrouter` | `openrouter` / `openai` / `anthropic` |
| `OPENROUTER_API_KEY` | If using OpenRouter | — | OpenRouter API key |
| `OPENAI_API_KEY` | If using OpenAI | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | If using Anthropic | — | Anthropic API key |
| `OPENROUTER_MODEL` | No | `anthropic/claude-3.5-sonnet` | Model to use with OpenRouter |
| `SCORE_TOP_N` | No | `10` | How many findings to send to LLM |
| `SLACK_WEBHOOK_URL` | No | — | Slack incoming webhook URL |
| `TRTE_API_URL` | No | `http://localhost:8000` | API base URL (used by UI) |

---

## API Reference

### Health

```
GET /health
→ {"status": "ok"}
```

### Ingest findings (structured)

```
POST /findings
Body: { "scanner": string, "findings": [Finding] }
→ { "scan_run_id": uuid, "count": int, "normalized": int }
```

### Ingest findings (flexible webhook)

Accepts three payload shapes — no strict schema required:

```
POST /webhook/findings

# Format A — wrapped object (recommended)
{ "scanner": "trivy", "findings": [{ ...finding... }] }

# Format B — raw list
[{ ...finding... }, { ...finding... }]

# Format C — single finding dict
{ "service": "api", "severity": "CRITICAL", "description": "..." }

→ { "scan_run_id": uuid, "count": int, "normalized": int, "deduplicated": int }
```

`deduplicated` reports how many findings in the batch had duplicate IDs and were dropped.

### Get triage list (rule-scored only)

```
GET /triage?days=7&scans=3
→ { "findings": [ScoredFinding x5] }
```

Query params: `days` (default 7) or `scans` (N most recent scan runs).

### Run LLM analysis

```
POST /triage/analyze
Body: { "days": int, "scans": int }  (optional, same as GET /triage)
→ { "findings": [ScoredFinding with enrichment x5] }
```

Also triggers Slack notification if `SLACK_WEBHOOK_URL` is set.

### Finding schema

```json
{
  "id": "string",
  "service": "string",
  "severity": "critical | high | medium | low",
  "type": "string",
  "environment": "production | staging | development",
  "internet_exposed": false,
  "sensitive_data": false,
  "cve": "CVE-YYYY-NNNNN",
  "description": "string",
  "context": {
    "criticality": "high | medium | low",
    "public_facing": true,
    "owner": "team-name"
  }
}
```

---

## Running Tests

```bash
# Install test dependencies
pip install pytest

# Run rule engine tests
cd tests
pytest test_rule_engine.py -v
```

The test suite covers 21 cases across severity scoring, environment bonuses, exposure flags, context criticality, and edge cases.

---

## Project Structure

```
trte-engine/
├── api/
│   ├── main.py              # FastAPI routes
│   ├── models.py            # Pydantic schemas
│   ├── db.py                # PostgreSQL operations
│   ├── normalizer.py        # Finding normalization
│   ├── correlator.py        # Cross-finding correlation rules
│   ├── llm_wrapper.py       # LLM provider abstraction + Redis cache
│   ├── slack_notifier.py    # Slack webhook delivery
│   ├── job_queue.py         # Redis queue enqueue
│   ├── context_map.json     # Service business context
│   └── requirements.txt
├── worker/
│   ├── main.py              # BRPOP loop
│   ├── rule_engine.py       # Deterministic scoring
│   └── requirements.txt
├── ui/
│   ├── app.py               # Streamlit dashboard
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_rule_engine.py
├── docs/
│   └── superpowers/
│       ├── specs/           # Design documents
│       └── plans/           # Implementation plans
├── docker-compose.yml
├── .env.example
└── ARCHITECTURE.md
```

---

## Roadmap

- [ ] Scanner-specific adapters (Snyk, Trivy, Grype, Semgrep, Checkov, Wiz)
- [ ] RBAC — team-scoped finding views
- [ ] Finding deduplication across scan runs
- [ ] Trend charts — score history per service over time
- [ ] Webhook delivery to Jira / Linear / PagerDuty
- [ ] CVSS v3/v4 base score as input to rule engine
- [ ] Multi-tenant mode for MSSPs

---

## License

MIT
