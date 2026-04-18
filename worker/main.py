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
