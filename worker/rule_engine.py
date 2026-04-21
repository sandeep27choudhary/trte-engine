SEVERITY_SCORES = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 2,
}

CRITICALITY_SCORES = {
    "high": 20,
    "medium": 10,
    "low": 0,
}


def score(finding: dict) -> int:
    total = 0

    # Environment
    if finding.get("environment") == "production":
        total += 40

    # Internet exposure
    if finding.get("internet_exposed"):
        total += 30

    # Sensitive data
    if finding.get("sensitive_data"):
        total += 20

    # Severity
    severity = (finding.get("severity") or "").lower()
    total += SEVERITY_SCORES.get(severity, 0)

    # Business context — optional, additive only
    ctx = finding.get("context") or {}
    criticality = (ctx.get("criticality") or "").lower()
    total += CRITICALITY_SCORES.get(criticality, 0)

    # Public-facing adds exposure weight when not already flagged internet_exposed
    if ctx.get("public_facing") and not finding.get("internet_exposed"):
        total += 15

    return total
