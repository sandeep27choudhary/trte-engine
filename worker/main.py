import json
import os

import redis

from db import update_finding_score, update_scan_run_status
from rule_engine import score

REDIS_URL = os.environ["REDIS_URL"]
QUEUE_KEY = "trte:score_queue"


def process_job(job_data: str):
    job = json.loads(job_data)
    scan_run_id = job["scan_run_id"]
    findings = job["findings"]

    update_scan_run_status(scan_run_id, "scoring")

    scored = 0
    for finding in findings:
        try:
            base_score = score(finding)
            update_finding_score(scan_run_id, finding["id"], base_score)
            scored += 1
        except Exception as e:
            print(f"Skipping finding {finding.get('id')}: {e}")

    update_scan_run_status(scan_run_id, "scored", scored_count=scored)
    print(f"[worker] scan_run={scan_run_id} scored={scored}/{len(findings)}")


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
