"""Tests for Terraform plan risk scorer."""

from infraguard.common.severity import Severity
from infraguard.plan_risk.parser import parse_plan
from infraguard.plan_risk.scorer import _detect_environment, score_changes


class TestScorer:
    def test_simple_create_low_risk(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "simple_create.json")
        report = score_changes(changes)
        # create(1) * MEDIUM(4) * dev(1.0) = 4 per resource
        assert report.total_score == 8
        assert len(report.changes) == 2

    def test_destroy_database_high_risk(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "destroy_database.json")
        report = score_changes(changes)

        # Find the database delete
        db_change = next(c for c in report.changes if "db_instance" in c.address)
        # delete(5) * CRITICAL(10) * prod(2.0) = 100
        assert db_change.risk_score == 100
        assert db_change.criticality == Severity.CRITICAL

        # Total should be high
        assert report.total_score > 100

    def test_environment_multiplier_prod(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "destroy_database.json")
        report = score_changes(changes)

        db_change = next(c for c in report.changes if "prod_main" in c.address)
        assert db_change.environment_multiplier == 2.0

    def test_environment_multiplier_staging(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "mixed_changes.json")
        report = score_changes(changes)

        vpc_change = next(c for c in report.changes if "staging_vpc" in c.address)
        assert vpc_change.environment_multiplier == 1.5

    def test_environment_multiplier_dev(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "mixed_changes.json")
        report = score_changes(changes)

        lambda_change = next(c for c in report.changes if "dev_processor" in c.address)
        assert lambda_change.environment_multiplier == 1.0

    def test_changes_sorted_by_risk_descending(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "destroy_database.json")
        report = score_changes(changes)

        scores = [c.risk_score for c in report.changes]
        assert scores == sorted(scores, reverse=True)

    def test_summary_contains_totals(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "destroy_database.json")
        report = score_changes(changes)

        assert "total_changes" in report.summary
        assert "total_risk_score" in report.summary
        assert "highest_risk" in report.summary
        assert report.summary["total_changes"] == 4

    def test_report_to_json(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "simple_create.json")
        report = score_changes(changes)
        json_str = report.to_json()
        assert "plan-risk" in json_str
        assert "changes" in json_str

    def test_custom_criticality_overrides(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "simple_create.json")
        overrides = {"aws_instance": Severity.CRITICAL}
        report = score_changes(changes, criticality_overrides=overrides)

        instance = next(c for c in report.changes if "aws_instance" in c.resource_type)
        assert instance.criticality == Severity.CRITICAL


class TestEnvironmentDetection:
    def test_prod_in_address(self):
        assert _detect_environment("aws_db_instance.prod_main", {
            "prod": 2.0, "staging": 1.5, "dev": 1.0
        }) == 2.0

    def test_staging_in_module_path(self):
        assert _detect_environment("module.staging_vpc.aws_vpc.main", {
            "prod": 2.0, "staging": 1.5, "dev": 1.0
        }) == 1.5

    def test_dev_in_name(self):
        assert _detect_environment("aws_lambda_function.dev_processor", {
            "prod": 2.0, "staging": 1.5, "dev": 1.0
        }) == 1.0

    def test_no_environment_match(self):
        assert _detect_environment("aws_instance.web_server", {
            "prod": 2.0, "staging": 1.5, "dev": 1.0
        }) == 1.0  # Falls back to DEFAULT_ENVIRONMENT_MULTIPLIER

    def test_avoids_false_positive_product(self):
        """'product' should NOT match 'prod'."""
        assert _detect_environment("aws_instance.product_service", {
            "prod": 2.0, "dev": 1.0
        }) == 1.0
