import os
import json

import redis

REDIS_URL = os.environ["REDIS_URL"]
QUEUE_KEY = "trte:score_queue"


def enqueue_scoring_job(scan_run_id: str, findings: list[dict]):
    r = redis.from_url(REDIS_URL)
    payload = json.dumps({"scan_run_id": scan_run_id, "findings": findings})
    r.lpush(QUEUE_KEY, payload)
