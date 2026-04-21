from rule_engine import score


class TestEnvironment:
    def test_production_adds_40(self):
        f = {"environment": "production", "severity": "low", "internet_exposed": False, "sensitive_data": False}
        assert score(f) == 42

    def test_non_production_adds_0(self):
        f = {"environment": "staging", "severity": "low", "internet_exposed": False, "sensitive_data": False}
        assert score(f) == 2


class TestFlags:
    def test_internet_exposed_adds_30(self):
        f = {"environment": "staging", "severity": "low", "internet_exposed": True, "sensitive_data": False}
        assert score(f) == 32

    def test_sensitive_data_adds_20(self):
        f = {"environment": "staging", "severity": "low", "internet_exposed": False, "sensitive_data": True}
        assert score(f) == 22


class TestSeverity:
    def test_critical_adds_30(self):
        assert score({"severity": "critical"}) == 30

    def test_high_adds_20(self):
        assert score({"severity": "high"}) == 20

    def test_medium_adds_10(self):
        assert score({"severity": "medium"}) == 10

    def test_low_adds_2(self):
        assert score({"severity": "low"}) == 2

    def test_unknown_severity_adds_0(self):
        assert score({"severity": "unknown"}) == 0

    def test_severity_case_insensitive(self):
        assert score({"severity": "CRITICAL"}) == 30


class TestEdgeCases:
    def test_max_score_without_context(self):
        f = {"environment": "production", "severity": "critical", "internet_exposed": True, "sensitive_data": True}
        assert score(f) == 120

    def test_empty_dict_returns_0(self):
        assert score({}) == 0

    def test_none_values_return_0(self):
        f = {"environment": None, "severity": None, "internet_exposed": None, "sensitive_data": None}
        assert score(f) == 0


class TestContext:
    def test_high_criticality_adds_20(self):
        f = {"severity": "low", "context": {"criticality": "high"}}
        assert score(f) == 22  # 2 (low) + 20 (high criticality)

    def test_medium_criticality_adds_10(self):
        f = {"severity": "low", "context": {"criticality": "medium"}}
        assert score(f) == 12  # 2 (low) + 10 (medium criticality)

    def test_low_criticality_adds_0(self):
        f = {"severity": "low", "context": {"criticality": "low"}}
        assert score(f) == 2

    def test_public_facing_adds_15_when_not_internet_exposed(self):
        f = {"severity": "low", "internet_exposed": False, "context": {"public_facing": True}}
        assert score(f) == 17  # 2 + 15

    def test_public_facing_no_bonus_when_already_internet_exposed(self):
        f = {"severity": "low", "internet_exposed": True, "context": {"public_facing": True}}
        assert score(f) == 32  # 2 + 30 — no double-count

    def test_max_score_with_context(self):
        # production(40) + internet_exposed(30) + sensitive(20) + critical(30) + high_criticality(20) = 140
        f = {
            "environment": "production",
            "severity": "critical",
            "internet_exposed": True,
            "sensitive_data": True,
            "context": {"criticality": "high"},
        }
        assert score(f) == 140

    def test_no_context_field_is_fine(self):
        f = {"severity": "medium", "environment": "staging"}
        assert score(f) == 10

    def test_empty_context_is_fine(self):
        f = {"severity": "medium", "context": {}}
        assert score(f) == 10
