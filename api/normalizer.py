from uuid import uuid4

SEVERITY_MAP = {
    "critical": "critical", "crit": "critical", "p0": "critical",
    "high": "high", "h": "high", "p1": "high",
    "medium": "medium", "med": "medium", "moderate": "medium", "p2": "medium",
    "low": "low", "l": "low", "info": "low", "informational": "low", "p3": "low",
}

ENV_MAP = {
    "production": "production", "prod": "production", "prd": "production",
    "staging": "staging", "stage": "staging", "stg": "staging",
    "dev": "dev", "development": "dev", "local": "dev", "test": "dev",
}


def normalize_finding(raw: dict) -> dict:
    f = dict(raw)
    f["id"] = (f.get("id") or "").strip() or f"auto-{uuid4().hex[:8]}"
    f["service"] = (f.get("service") or "unknown").strip()
    f["type"] = (f.get("type") or "unknown").strip()
    f["description"] = (f.get("description") or "").strip()
    f["severity"] = SEVERITY_MAP.get((f.get("severity") or "").lower().strip(), "low")
    f["environment"] = ENV_MAP.get((f.get("environment") or "").lower().strip(), "dev")
    f["internet_exposed"] = _to_bool(f.get("internet_exposed", False))
    f["sensitive_data"] = _to_bool(f.get("sensitive_data", False))
    return f


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1")
    return bool(value)
