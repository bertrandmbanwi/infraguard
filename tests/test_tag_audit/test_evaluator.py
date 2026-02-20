"""Tests for tag compliance evaluator."""

from infraguard.common.severity import Severity
from infraguard.tag_audit.evaluator import evaluate
from infraguard.tag_audit.scanner import scan_from_file


class TestEvaluator:
    def test_fully_compliant_resource(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        # First resource has all required tags
        report = evaluate([resources[0]])
        assert len(report.findings) == 0
        assert report.summary["compliance_percentage"] == 100.0

    def test_missing_tags_detected(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        # Second resource only has "Name" — missing Environment, Team, Service, ManagedBy
        report = evaluate([resources[1]])
        missing = [f for f in report.findings if "Missing" in f.title]
        assert len(missing) == 4
        assert all(f.severity == Severity.HIGH for f in missing)

    def test_invalid_tag_values(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        # Resource with Environment=invalid-env
        invalid_env = resources[5]
        report = evaluate([invalid_env])
        invalid_findings = [f for f in report.findings if "Invalid tag value" in f.title]
        assert len(invalid_findings) >= 1

    def test_empty_tag_value(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        # Resource with Team="" (empty)
        resource = resources[5]
        report = evaluate([resource])
        empty_findings = [f for f in report.findings if "Empty/invalid" in f.title]
        assert len(empty_findings) >= 1

    def test_compliance_percentage(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        report = evaluate(resources)
        pct = report.summary["compliance_percentage"]
        assert 0 <= pct <= 100

    def test_service_breakdown(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        report = evaluate(resources)
        by_service = report.summary["by_service"]
        assert "ec2" in by_service
        assert "s3" in by_service
        assert "rds" in by_service
        assert "lambda" in by_service

    def test_custom_required_tags(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        custom_tags = [{"key": "CostCenter", "pattern": r"^CC-\d{4}$"}]
        report = evaluate(resources, required_tags=custom_tags)
        # Most resources don't have CostCenter at all
        assert len(report.findings) > 0

    def test_resource_overrides(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        overrides = {
            "aws_s3_bucket": {"additional_required": ["DataClassification"]},
        }
        report = evaluate(resources, resource_overrides=overrides)
        s3_findings = [f for f in report.findings if "s3" in f.resource and "DataClassification" in f.title]
        assert len(s3_findings) >= 1

    def test_report_to_json(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        report = evaluate(resources)
        json_str = report.to_json()
        assert "tag-audit" in json_str
        assert "compliance_percentage" in json_str
