import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

import pytest
from webhook_parser import parse_webhook_body as _parse_webhook_body


class TestRawList:
    def test_list_returns_unknown_scanner(self):
        scanner, findings = _parse_webhook_body([{"id": "x", "severity": "high"}])
        assert scanner == "unknown"

    def test_list_returns_all_items(self):
        body = [{"id": "a"}, {"id": "b"}]
        _, findings = _parse_webhook_body(body)
        assert len(findings) == 2

    def test_empty_list_accepted(self):
        _, findings = _parse_webhook_body([])
        assert findings == []


class TestWrappedObject:
    def test_extracts_scanner(self):
        scanner, _ = _parse_webhook_body({"scanner": "trivy", "findings": []})
        assert scanner == "trivy"

    def test_missing_scanner_defaults_to_unknown(self):
        scanner, _ = _parse_webhook_body({"findings": []})
        assert scanner == "unknown"

    def test_extracts_findings_list(self):
        body = {"scanner": "snyk", "findings": [{"id": "vuln-1"}, {"id": "vuln-2"}]}
        _, findings = _parse_webhook_body(body)
        assert len(findings) == 2

    def test_findings_not_list_raises(self):
        with pytest.raises(ValueError, match="'findings' must be an array"):
            _parse_webhook_body({"findings": "not-a-list"})


class TestSingleFinding:
    def test_single_finding_dict_wrapped(self):
        body = {"id": "vuln-1", "severity": "critical", "service": "api"}
        scanner, findings = _parse_webhook_body(body)
        assert len(findings) == 1
        assert findings[0]["id"] == "vuln-1"

    def test_single_finding_scanner_unknown(self):
        scanner, _ = _parse_webhook_body({"severity": "high", "service": "api"})
        assert scanner == "unknown"


class TestInvalidPayloads:
    def test_plain_string_raises(self):
        with pytest.raises(ValueError):
            _parse_webhook_body("just a string")

    def test_integer_raises(self):
        with pytest.raises(ValueError):
            _parse_webhook_body(42)

    def test_empty_dict_raises(self):
        with pytest.raises(ValueError):
            _parse_webhook_body({})

    def test_dict_without_known_keys_raises(self):
        with pytest.raises(ValueError):
            _parse_webhook_body({"foo": "bar", "baz": 1})
