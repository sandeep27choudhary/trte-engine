def parse_webhook_body(body: object) -> tuple[str, list[dict]]:
    """
    Accept three real-world payload shapes and return (scanner, findings_list).

    A) Raw list:       [{ finding }, ...]
    B) Wrapped object: { "scanner": "...", "findings": [...] }
    C) Single finding: { "id": "...", "severity": "...", ... }

    Raises ValueError with a human-readable message on unrecognisable input.
    """
    if isinstance(body, list):
        return "unknown", body

    if isinstance(body, dict):
        if "findings" in body:
            findings = body["findings"]
            if not isinstance(findings, list):
                raise ValueError("'findings' must be an array")
            return body.get("scanner") or "unknown", findings

        # Single finding dict — wrap it
        if any(k in body for k in ("id", "severity", "service", "type", "description")):
            return body.get("scanner") or "unknown", [body]

    raise ValueError(
        'Invalid payload: expected a list of findings or { "findings": [...] }'
    )
