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
