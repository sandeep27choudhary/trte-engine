from uuid import uuid4

SEVERITY_MAP = {
    # critical
    "critical": "critical", "crit": "critical", "p0": "critical",
    "sev-1": "critical", "sev1": "critical", "s1": "critical", "severity-critical": "critical",
    # high
    "high": "high", "h": "high", "p1": "high",
    "sev-2": "high", "sev2": "high", "s2": "high",
    # medium
    "medium": "medium", "med": "medium", "moderate": "medium", "p2": "medium",
    "sev-3": "medium", "sev3": "medium", "s3": "medium",
    # low
    "low": "low", "l": "low", "info": "low", "informational": "low", "p3": "low",
    "sev-4": "low", "sev4": "low", "s4": "low", "note": "low",
}

ENV_MAP = {
    "production": "production", "prod": "production", "prd": "production",
    "live": "production", "prd-1": "production", "prod-1": "production",
    "staging": "staging", "stage": "staging", "stg": "staging",
    "preprod": "staging", "pre-prod": "staging", "qa": "staging", "uat": "staging",
    "development": "development", "dev": "development", "develop": "development",
    "local": "development", "test": "development", "testing": "development",
}


def normalize_finding(raw: dict) -> dict:
    f = dict(raw)
    f["id"] = (f.get("id") or "").strip() or f"auto-{uuid4().hex[:8]}"
    f["service"] = (f.get("service") or "unknown").strip() or "unknown"
    f["type"] = (f.get("type") or "unknown").strip() or "unknown"
    f["description"] = (f.get("description") or "").strip()
    f["cve"] = (f.get("cve") or "").strip() or None
    f["severity"] = SEVERITY_MAP.get((f.get("severity") or "").lower().strip(), "low")
    f["environment"] = ENV_MAP.get((f.get("environment") or "").lower().strip(), "development")
    f["internet_exposed"] = _to_bool(f.get("internet_exposed", False))
    f["sensitive_data"] = _to_bool(f.get("sensitive_data", False))
    return f


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower().strip() in ("true", "yes", "1", "on")
    return False
