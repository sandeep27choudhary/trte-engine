# TRTE — Top Risk Triage Engine: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a FastAPI + Postgres + Redis + Worker system that ingests vulnerability findings from CI scanners, scores them with a rule engine, and enriches the top 5 with LLM reasoning.

**Architecture:** FastAPI handles ingest (202 immediately) and writes to Postgres + Redis queue. A separate worker process consumes the queue and runs the rule engine to score findings. The API's `/triage/analyze` endpoint runs LLM enrichment synchronously with Redis caching per finding.

**Tech Stack:** Python 3.12, FastAPI, psycopg2, redis-py, openai SDK (also used for OpenRouter), anthropic SDK, Docker Compose, pytest.

---

## File Map

| File | Responsibility |
|---|---|
| `docker-compose.yml` | Orchestrates postgres, redis, api, worker |
| `.env.example` | All required env vars documented |
| `api/Dockerfile` | API container |
| `api/requirements.txt` | API dependencies |
| `api/models.py` | Pydantic input/output schemas |
| `api/db.py` | Postgres connection + all query helpers |
| `api/job_queue.py` | Redis LPUSH enqueue helper |
| `api/llm_wrapper.py` | Provider-switchable LLM client + per-finding Redis cache |
| `api/main.py` | FastAPI route definitions only |
| `worker/Dockerfile` | Worker container |
| `worker/requirements.txt` | Worker dependencies |
| `worker/rule_engine.py` | Pure `score(finding) -> int` function |
| `worker/main.py` | BRPOP loop — consumes queue, calls rule engine, updates DB |
| `tests/conftest.py` | Adds worker/ to sys.path for imports |
| `tests/test_rule_engine.py` | Unit tests for scoring logic |
| `Makefile` | `make test` shortcut |

---

## Task 1: Project Scaffold

**Files:**
- Create: `docker-compose.yml`
- Create: `.env.example`
- Create: `api/Dockerfile`
- Create: `api/requirements.txt`
- Create: `worker/Dockerfile`
- Create: `worker/requirements.txt`
- Create: `Makefile`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p api worker tests
```

- [ ] **Step 2: Write docker-compose.yml**

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: trte
      POSTGRES_PASSWORD: trte
      POSTGRES_DB: trte
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U trte"]
      interval: 5s
      timeout: 5s
      retries: 10

  redis:
    image: redis:7
    ports:
      - "6379:6379"

  api:
    build: ./api
    ports:
      - "8000:8000"
    env_file: .env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started

  worker:
    build: ./worker
    env_file: .env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started

volumes:
  postgres_data:
```

- [ ] **Step 3: Write .env.example**

```env
# Database
DATABASE_URL=postgresql://trte:trte@postgres:5432/trte

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_LLM_TTL_SECONDS=86400

# LLM Provider: openai | anthropic | openrouter
LLM_PROVIDER=openai
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-haiku-4-5-20251001
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openai/gpt-4o-mini

# Worker
SCORE_TOP_N=10
```

- [ ] **Step 4: Write api/Dockerfile**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 5: Write api/requirements.txt**

```
fastapi==0.115.0
uvicorn==0.30.6
psycopg2-binary==2.9.9
redis==5.0.8
pydantic==2.8.2
openai==1.40.0
anthropic==0.34.0
python-dotenv==1.0.1
```

- [ ] **Step 6: Write worker/Dockerfile**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
```

- [ ] **Step 7: Write worker/requirements.txt**

```
psycopg2-binary==2.9.9
redis==5.0.8
python-dotenv==1.0.1
```

- [ ] **Step 8: Write Makefile**

```makefile
test:
	PYTHONPATH=worker pytest tests/ -v

up:
	docker compose up --build

down:
	docker compose down -v
```

- [ ] **Step 9: Copy .env.example to .env and fill in your real API key**

```bash
cp .env.example .env
# Edit .env — set LLM_PROVIDER and the matching *_API_KEY
```

- [ ] **Step 10: Commit**

```bash
git add docker-compose.yml .env.example api/Dockerfile api/requirements.txt worker/Dockerfile worker/requirements.txt Makefile
git commit -m "feat: project scaffold — docker compose, dockerfiles, requirements"
```

---

## Task 2: Pydantic Models

**Files:**
- Create: `api/models.py`

- [ ] **Step 1: Write api/models.py**

```python
from typing import Optional
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
    urgency: str  # "now" | "today" | "this-week"


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
```

- [ ] **Step 2: Commit**

```bash
git add api/models.py
git commit -m "feat: pydantic schemas for ingest, triage, and LLM enrichment"
```

---

## Task 3: Rule Engine (TDD)

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_rule_engine.py`
- Create: `worker/rule_engine.py`

- [ ] **Step 1: Install pytest locally**

```bash
pip install pytest==8.3.0
```

- [ ] **Step 2: Write tests/conftest.py**

```python
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "worker"))
```

- [ ] **Step 3: Write the failing tests in tests/test_rule_engine.py**

```python
from rule_engine import score


class TestEnvironment:
    def test_production_adds_40(self):
        f = {"environment": "production", "severity": "low", "internet_exposed": False, "sensitive_data": False}
        assert score(f) == 42

    def test_non_production_adds_0(self):
        f = {"environment": "staging", "severity": "low", "internet_exposed": False, "sensitive_data": False}
        assert score(f) == 2


class TestFlags:
    def test_internet_exposed_adds_30(self):
        f = {"environment": "staging", "severity": "low", "internet_exposed": True, "sensitive_data": False}
        assert score(f) == 32

    def test_sensitive_data_adds_20(self):
        f = {"environment": "staging", "severity": "low", "internet_exposed": False, "sensitive_data": True}
        assert score(f) == 22


class TestSeverity:
    def test_critical_adds_30(self):
        assert score({"severity": "critical"}) == 30

    def test_high_adds_20(self):
        assert score({"severity": "high"}) == 20

    def test_medium_adds_10(self):
        assert score({"severity": "medium"}) == 10

    def test_low_adds_2(self):
        assert score({"severity": "low"}) == 2

    def test_unknown_severity_adds_0(self):
        assert score({"severity": "unknown"}) == 0

    def test_severity_case_insensitive(self):
        assert score({"severity": "CRITICAL"}) == 30


class TestEdgeCases:
    def test_max_score_is_120(self):
        f = {"environment": "production", "severity": "critical", "internet_exposed": True, "sensitive_data": True}
        assert score(f) == 120

    def test_empty_dict_returns_0(self):
        assert score({}) == 0

    def test_none_values_return_0(self):
        f = {"environment": None, "severity": None, "internet_exposed": None, "sensitive_data": None}
        assert score(f) == 0
```

- [ ] **Step 4: Run tests to confirm they fail**

```bash
make test
```

Expected: `ModuleNotFoundError: No module named 'rule_engine'`

- [ ] **Step 5: Write worker/rule_engine.py**

```python
SEVERITY_SCORES = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 2,
}


def score(finding: dict) -> int:
    total = 0
    if finding.get("environment") == "production":
        total += 40
    if finding.get("internet_exposed"):
        total += 30
    if finding.get("sensitive_data"):
        total += 20
    severity = (finding.get("severity") or "").lower()
    total += SEVERITY_SCORES.get(severity, 0)
    return total
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
make test
```

Expected:
```
tests/test_rule_engine.py::TestEnvironment::test_production_adds_40 PASSED
tests/test_rule_engine.py::TestEnvironment::test_non_production_adds_0 PASSED
tests/test_rule_engine.py::TestFlags::test_internet_exposed_adds_30 PASSED
tests/test_rule_engine.py::TestFlags::test_sensitive_data_adds_20 PASSED
tests/test_rule_engine.py::TestSeverity::test_critical_adds_30 PASSED
tests/test_rule_engine.py::TestSeverity::test_high_adds_20 PASSED
tests/test_rule_engine.py::TestSeverity::test_medium_adds_10 PASSED
tests/test_rule_engine.py::TestSeverity::test_low_adds_2 PASSED
tests/test_rule_engine.py::TestSeverity::test_unknown_severity_adds_0 PASSED
tests/test_rule_engine.py::TestSeverity::test_severity_case_insensitive PASSED
tests/test_rule_engine.py::TestEdgeCases::test_max_score_is_120 PASSED
tests/test_rule_engine.py::TestEdgeCases::test_empty_dict_returns_0 PASSED
tests/test_rule_engine.py::TestEdgeCases::test_none_values_return_0 PASSED
13 passed in 0.XXs
```

- [ ] **Step 7: Commit**

```bash
git add tests/conftest.py tests/test_rule_engine.py worker/rule_engine.py
git commit -m "feat: rule engine with full unit test coverage"
```

---

## Task 4: Database Layer

**Files:**
- Create: `api/db.py`

- [ ] **Step 1: Write api/db.py**

```python
import os
import json
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ["DATABASE_URL"]


def _get_conn():
    return psycopg2.connect(DATABASE_URL)


@contextmanager
def _cursor():
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(retries: int = 10, delay: float = 2.0):
    for attempt in range(retries):
        try:
            with _cursor() as (conn, cur):
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scan_runs (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        scanner VARCHAR(255),
                        created_at TIMESTAMPTZ DEFAULT now()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id VARCHAR(255),
                        scan_run_id UUID REFERENCES scan_runs(id),
                        service VARCHAR(255),
                        severity VARCHAR(50),
                        type VARCHAR(255),
                        environment VARCHAR(100),
                        internet_exposed BOOLEAN DEFAULT FALSE,
                        sensitive_data BOOLEAN DEFAULT FALSE,
                        cve VARCHAR(50),
                        description TEXT,
                        base_score INT,
                        scored_at TIMESTAMPTZ,
                        raw JSONB,
                        created_at TIMESTAMPTZ DEFAULT now(),
                        PRIMARY KEY (id, scan_run_id)
                    )
                """)
            return
        except Exception as e:
            if attempt == retries - 1:
                raise
            time.sleep(delay)


def create_scan_run(scanner: str) -> str:
    with _cursor() as (conn, cur):
        cur.execute(
            "INSERT INTO scan_runs (scanner) VALUES (%s) RETURNING id",
            (scanner,),
        )
        return str(cur.fetchone()["id"])


def insert_findings(scan_run_id: str, findings: list[dict]):
    with _cursor() as (conn, cur):
        for f in findings:
            cur.execute(
                """
                INSERT INTO findings
                    (id, scan_run_id, service, severity, type, environment,
                     internet_exposed, sensitive_data, cve, description, raw)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id, scan_run_id) DO NOTHING
                """,
                (
                    f["id"], scan_run_id, f["service"], f["severity"],
                    f["type"], f["environment"],
                    f.get("internet_exposed", False),
                    f.get("sensitive_data", False),
                    f.get("cve"), f["description"],
                    json.dumps(f),
                ),
            )


def get_top_findings(
    days: int | None = None,
    scans: int | None = None,
    limit: int = 5,
) -> list[dict]:
    with _cursor() as (conn, cur):
        if scans is not None:
            cur.execute(
                """
                SELECT f.id, f.service, f.severity, f.type, f.environment,
                       f.internet_exposed, f.sensitive_data, f.cve,
                       f.description, f.base_score, f.raw
                FROM findings f
                JOIN scan_runs sr ON f.scan_run_id = sr.id
                WHERE sr.id IN (
                    SELECT id FROM scan_runs ORDER BY created_at DESC LIMIT %s
                )
                  AND f.base_score IS NOT NULL
                ORDER BY f.base_score DESC, f.created_at DESC
                LIMIT %s
                """,
                (scans, limit),
            )
        else:
            n_days = days if days is not None else 7
            cutoff = datetime.now(tz=timezone.utc) - timedelta(days=n_days)
            cur.execute(
                """
                SELECT f.id, f.service, f.severity, f.type, f.environment,
                       f.internet_exposed, f.sensitive_data, f.cve,
                       f.description, f.base_score, f.raw
                FROM findings f
                JOIN scan_runs sr ON f.scan_run_id = sr.id
                WHERE sr.created_at >= %s
                  AND f.base_score IS NOT NULL
                ORDER BY f.base_score DESC, f.created_at DESC
                LIMIT %s
                """,
                (cutoff, limit),
            )
        return [dict(row) for row in cur.fetchall()]


def update_finding_score(scan_run_id: str, finding_id: str, base_score: int):
    with _cursor() as (conn, cur):
        cur.execute(
            """
            UPDATE findings
            SET base_score = %s, scored_at = now()
            WHERE id = %s AND scan_run_id = %s
            """,
            (base_score, finding_id, scan_run_id),
        )
```

- [ ] **Step 2: Commit**

```bash
git add api/db.py
git commit -m "feat: postgres layer — schema init, insert findings, top-N query"
```

---

## Task 5: Redis Queue Helper

**Files:**
- Create: `api/job_queue.py`

- [ ] **Step 1: Write api/job_queue.py**

```python
import os
import json

import redis

REDIS_URL = os.environ["REDIS_URL"]
QUEUE_KEY = "trte:score_queue"


def enqueue_scoring_job(scan_run_id: str, findings: list[dict]):
    r = redis.from_url(REDIS_URL)
    payload = json.dumps({"scan_run_id": scan_run_id, "findings": findings})
    r.lpush(QUEUE_KEY, payload)
```

- [ ] **Step 2: Commit**

```bash
git add api/job_queue.py
git commit -m "feat: redis queue helper for async scoring jobs"
```

---

## Task 6: LLM Wrapper

**Files:**
- Create: `api/llm_wrapper.py`

- [ ] **Step 1: Write api/llm_wrapper.py**

```python
import hashlib
import json
import os
from typing import Optional

import redis
from anthropic import Anthropic
from openai import OpenAI

REDIS_URL = os.environ["REDIS_URL"]
REDIS_LLM_TTL = int(os.getenv("REDIS_LLM_TTL_SECONDS", "86400"))
CACHE_PREFIX = "trte:llm:"

SYSTEM_PROMPT = (
    "You are a security triage assistant. Analyze the vulnerability findings below.\n"
    "Return a JSON array where each element corresponds to one finding (same order).\n"
    "Each element must have exactly these fields:\n"
    '- "id": the finding id (string)\n'
    '- "exploitability": 1-2 sentences on how this could be exploited (string)\n'
    '- "fix": 1-2 sentences on how to fix it (string)\n'
    '- "urgency": one of "now", "today", or "this-week" (string)\n'
    "Return ONLY valid JSON. No markdown, no explanation."
)


def _cache_key(finding: dict) -> str:
    canonical = json.dumps(finding, sort_keys=True)
    return CACHE_PREFIX + hashlib.sha256(canonical.encode()).hexdigest()


def _compress(f: dict) -> str:
    cve = f.get("cve") or "no-cve"
    desc = (f.get("description") or "")[:100]
    return (
        f"{f['id']} | {f['service']} | {f['severity']} | {f['type']} | "
        f"{f['environment']} | exposed={f.get('internet_exposed', False)} | "
        f"sensitive={f.get('sensitive_data', False)} | {cve} | \"{desc}\""
    )


class LLMProvider:
    def __init__(self):
        self._redis = redis.from_url(REDIS_URL)

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        raise NotImplementedError

    def analyze(self, findings: list[dict]) -> dict[str, Optional[dict]]:
        results: dict[str, Optional[dict]] = {}
        uncached: list[dict] = []

        for f in findings:
            cached = self._redis.get(_cache_key(f))
            if cached:
                results[f["id"]] = json.loads(cached)
            else:
                uncached.append(f)

        if uncached:
            try:
                enrichments = self._call_llm(uncached)
                for f, enrichment in zip(uncached, enrichments):
                    self._redis.setex(_cache_key(f), REDIS_LLM_TTL, json.dumps(enrichment))
                    results[f["id"]] = enrichment
            except Exception as e:
                print(f"LLM call failed: {e}")
                for f in uncached:
                    results[f["id"]] = None

        return results


class OpenAIProvider(LLMProvider):
    def __init__(self):
        super().__init__()
        self._client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        self._model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        lines = "\n".join(_compress(f) for f in findings)
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": lines},
            ],
            temperature=0.2,
        )
        return json.loads(resp.choices[0].message.content)


class AnthropicProvider(LLMProvider):
    def __init__(self):
        super().__init__()
        self._client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._model = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        lines = "\n".join(_compress(f) for f in findings)
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": lines}],
        )
        return json.loads(resp.content[0].text)


class OpenRouterProvider(LLMProvider):
    def __init__(self):
        super().__init__()
        self._client = OpenAI(
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url="https://openrouter.ai/api/v1",
        )
        self._model = os.environ["OPENROUTER_MODEL"]

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        lines = "\n".join(_compress(f) for f in findings)
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": lines},
            ],
            temperature=0.2,
        )
        return json.loads(resp.choices[0].message.content)


_PROVIDERS = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "openrouter": OpenRouterProvider,
}


def get_llm_provider() -> LLMProvider:
    name = os.environ.get("LLM_PROVIDER", "openai")
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown LLM_PROVIDER '{name}'. Must be one of: {list(_PROVIDERS.keys())}"
        )
    return cls()
```

- [ ] **Step 2: Commit**

```bash
git add api/llm_wrapper.py
git commit -m "feat: LLM wrapper supporting openai, anthropic, openrouter with redis caching"
```

---

## Task 7: FastAPI Routes

**Files:**
- Create: `api/main.py`

- [ ] **Step 1: Write api/main.py**

```python
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
        enrichment = Enrichment(**raw_enrichment) if raw_enrichment else None
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
```

- [ ] **Step 2: Commit**

```bash
git add api/main.py
git commit -m "feat: fastapi routes — POST /findings, GET /triage, POST /triage/analyze, GET /health"
```

---

## Task 8: Worker Main Loop

**Files:**
- Create: `worker/main.py`

- [ ] **Step 1: Write worker/main.py**

```python
import json
import os
import time

import psycopg2
import redis

from rule_engine import score

DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ["REDIS_URL"]
QUEUE_KEY = "trte:score_queue"


def _get_conn():
    return psycopg2.connect(DATABASE_URL)


def _update_score(conn, scan_run_id: str, finding_id: str, base_score: int):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE findings SET base_score = %s, scored_at = now() WHERE id = %s AND scan_run_id = %s",
            (base_score, finding_id, scan_run_id),
        )
    conn.commit()


def process_job(job_data: str):
    job = json.loads(job_data)
    scan_run_id = job["scan_run_id"]
    findings = job["findings"]

    conn = _get_conn()
    try:
        for finding in findings:
            try:
                base_score = score(finding)
                _update_score(conn, scan_run_id, finding["id"], base_score)
            except Exception as e:
                print(f"Skipping finding {finding.get('id')}: {e}")
    finally:
        conn.close()


def main():
    r = redis.from_url(REDIS_URL)
    print("Worker started — waiting for jobs on trte:score_queue")
    while True:
        job = r.brpop(QUEUE_KEY, timeout=5)
        if job:
            _, data = job
            try:
                process_job(data)
            except Exception as e:
                print(f"Job failed: {e}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Commit**

```bash
git add worker/main.py
git commit -m "feat: worker BRPOP loop — scores findings via rule engine, updates postgres"
```

---

## Task 9: Smoke Test

Verify the full system end-to-end.

- [ ] **Step 1: Bring up the stack**

```bash
make up
```

Expected: all four services start without errors. Worker logs show `Worker started — waiting for jobs on trte:score_queue`.

- [ ] **Step 2: Check health**

```bash
curl http://localhost:8000/health
```

Expected: `{"status":"ok"}`

- [ ] **Step 3: Ingest a batch of findings**

```bash
curl -s -X POST http://localhost:8000/findings \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

Expected: `{"scan_run_id":"<uuid>","count":3}`

- [ ] **Step 4: Wait 2 seconds for worker to score, then check triage**

```bash
sleep 2 && curl -s http://localhost:8000/triage | python3 -m json.tool
```

Expected: JSON with `findings` array. `vuln-001` rank 1 with `base_score: 120`, `vuln-002` rank 2 with `base_score: 90`, `vuln-003` rank 3 with `base_score: 40`.

- [ ] **Step 5: Run LLM-enriched triage (requires real API key in .env)**

```bash
curl -s -X POST http://localhost:8000/triage/analyze \
  -H "Content-Type: application/json" \
  -d '{"days": 7}' | python3 -m json.tool
```

Expected: same top findings but each has `enrichment: {"exploitability": "...", "fix": "...", "urgency": "now"}`.

- [ ] **Step 6: Run the same analyze call again — verify Redis cache is used (response must be identical and fast)**

```bash
time curl -s -X POST http://localhost:8000/triage/analyze \
  -H "Content-Type: application/json" \
  -d '{"days": 7}' | python3 -m json.tool
```

Expected: same result, `real` time under 100ms (no LLM call on cache hit).

- [ ] **Step 7: Run unit tests one final time**

```bash
make test
```

Expected: 13 passed.

- [ ] **Step 8: Final commit**

```bash
git add .
git commit -m "chore: smoke test verified — all endpoints working, redis cache confirmed"
```
