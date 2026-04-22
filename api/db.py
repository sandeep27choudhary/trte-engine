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
        except Exception:
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


def insert_findings(scan_run_id: str, findings: list[dict]) -> int:
    """Insert findings, deduplicating by id within the batch. Returns inserted count."""
    seen: set[str] = set()
    unique = []
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)

    with _cursor() as (conn, cur):
        for f in unique:
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
    return len(unique)


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
                       f.description, f.base_score, f.raw,
                       f.created_at as detected_at
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
                       f.description, f.base_score, f.raw,
                       f.created_at as detected_at
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
