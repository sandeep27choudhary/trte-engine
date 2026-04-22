import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from normalizer import normalize_finding, SEVERITY_MAP, ENV_MAP, _to_bool


class TestSeverityAliases:
    def test_crit_maps_to_critical(self):
        assert normalize_finding({"severity": "CRIT"})["severity"] == "critical"

    def test_p0_maps_to_critical(self):
        assert normalize_finding({"severity": "p0"})["severity"] == "critical"

    def test_sev1_maps_to_critical(self):
        assert normalize_finding({"severity": "sev-1"})["severity"] == "critical"

    def test_p1_maps_to_high(self):
        assert normalize_finding({"severity": "P1"})["severity"] == "high"

    def test_moderate_maps_to_medium(self):
        assert normalize_finding({"severity": "moderate"})["severity"] == "medium"

    def test_informational_maps_to_low(self):
        assert normalize_finding({"severity": "informational"})["severity"] == "low"

    def test_unknown_severity_defaults_to_low(self):
        assert normalize_finding({"severity": "bananas"})["severity"] == "low"

    def test_missing_severity_defaults_to_low(self):
        assert normalize_finding({})["severity"] == "low"


class TestEnvironmentAliases:
    def test_prod_maps_to_production(self):
        assert normalize_finding({"environment": "prod"})["environment"] == "production"

    def test_prd_maps_to_production(self):
        assert normalize_finding({"environment": "PRD"})["environment"] == "production"

    def test_live_maps_to_production(self):
        assert normalize_finding({"environment": "live"})["environment"] == "production"

    def test_stg_maps_to_staging(self):
        assert normalize_finding({"environment": "stg"})["environment"] == "staging"

    def test_qa_maps_to_staging(self):
        assert normalize_finding({"environment": "qa"})["environment"] == "staging"

    def test_local_maps_to_development(self):
        assert normalize_finding({"environment": "local"})["environment"] == "development"

    def test_missing_environment_defaults_to_development(self):
        assert normalize_finding({})["environment"] == "development"


class TestBoolNormalization:
    def test_string_true(self):
        assert _to_bool("true") is True

    def test_string_yes(self):
        assert _to_bool("yes") is True

    def test_string_1(self):
        assert _to_bool("1") is True

    def test_string_on(self):
        assert _to_bool("on") is True

    def test_string_false(self):
        assert _to_bool("false") is False

    def test_int_1(self):
        assert _to_bool(1) is True

    def test_int_0(self):
        assert _to_bool(0) is False

    def test_bool_passthrough(self):
        assert _to_bool(True) is True
        assert _to_bool(False) is False


class TestMissingFields:
    def test_auto_id_generated(self):
        f = normalize_finding({"severity": "high"})
        assert f["id"].startswith("auto-")

    def test_explicit_id_preserved(self):
        f = normalize_finding({"id": "my-id", "severity": "high"})
        assert f["id"] == "my-id"

    def test_missing_service_defaults_to_unknown(self):
        assert normalize_finding({})["service"] == "unknown"

    def test_missing_type_defaults_to_unknown(self):
        assert normalize_finding({})["type"] == "unknown"

    def test_missing_cve_is_none(self):
        assert normalize_finding({})["cve"] is None

    def test_empty_cve_is_none(self):
        assert normalize_finding({"cve": ""})["cve"] is None
