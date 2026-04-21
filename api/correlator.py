"""
Simple deterministic correlation engine.
Detects obvious multi-finding attack paths and per-finding risk amplifiers.
Does NOT change base_score — produces advisory notes only.
"""

from typing import NamedTuple


class CorrelationResult(NamedTuple):
    finding_id: str
    notes: list[str]
    has_correlation: bool


_RULES = [
    (
        lambda f: f.get("internet_exposed") and f.get("severity") in ("critical", "high"),
        "Public attack surface with {severity} severity — direct remote exploitation path",
    ),
    (
        lambda f: f.get("sensitive_data") and f.get("internet_exposed"),
        "Sensitive data reachable from internet — data exfiltration risk",
    ),
    (
        lambda f: f.get("environment") == "production" and f.get("severity") == "critical",
        "Critical vuln in production — immediate blast radius, no staging buffer",
    ),
    (
        lambda f: (f.get("context") or {}).get("criticality") == "high"
                  and f.get("severity") in ("critical", "high"),
        "High-criticality service carrying a severe vulnerability — compounded business impact",
    ),
    (
        lambda f: (f.get("context") or {}).get("public_facing")
                  and f.get("sensitive_data"),
        "Public-facing service handling sensitive data — regulatory and reputational exposure",
    ),
]


def correlate(findings: list[dict]) -> list[CorrelationResult]:
    results = []
    for f in findings:
        notes = []
        for predicate, template in _RULES:
            if predicate(f):
                notes.append(template.format(severity=f.get("severity", "unknown")))
        results.append(CorrelationResult(
            finding_id=f["id"],
            notes=notes,
            has_correlation=bool(notes),
        ))
    return results


def correlate_as_map(findings: list[dict]) -> dict[str, CorrelationResult]:
    return {r.finding_id: r for r in correlate(findings)}
