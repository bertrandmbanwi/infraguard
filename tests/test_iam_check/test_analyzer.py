"""Tests for IAM policy analyzer."""

from infraguard.common.severity import Severity
from infraguard.iam_check.analyzer import analyze_policy_file


class TestAnalyzer:
    def test_admin_policy_critical(self, iam_fixtures):
        report = analyze_policy_file(iam_fixtures / "admin_policy.json")
        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("admin" in f.title.lower() for f in critical)

    def test_overpermissive_policy_findings(self, iam_fixtures):
        report = analyze_policy_file(iam_fixtures / "overpermissive_policy.json")
        assert len(report.findings) > 0

        # Should find s3:* wildcard
        s3_wild = [f for f in report.findings if "s3:*" in f.title]
        assert len(s3_wild) >= 1

        # Should find dangerous actions (iam:PassRole, sts:AssumeRole)
        dangerous = [f for f in report.findings if "Dangerous action" in f.title]
        assert len(dangerous) >= 1

    def test_least_privilege_policy_clean(self, iam_fixtures):
        report = analyze_policy_file(iam_fixtures / "least_privilege_policy.json")
        # Well-scoped policy should have zero or very few findings
        high_plus = [f for f in report.findings if f.severity >= Severity.HIGH]
        assert len(high_plus) == 0

    def test_missing_conditions_on_sensitive_actions(self, iam_fixtures):
        report = analyze_policy_file(iam_fixtures / "overpermissive_policy.json")
        condition_findings = [f for f in report.findings if "Missing Condition" in f.title]
        assert len(condition_findings) >= 1

    def test_wildcard_resource_detection(self, iam_fixtures):
        report = analyze_policy_file(iam_fixtures / "overpermissive_policy.json")
        wildcard_res = [f for f in report.findings if "Wildcard resource" in f.title]
        assert len(wildcard_res) >= 1

    def test_suggestions_provided(self, iam_fixtures):
        report = analyze_policy_file(iam_fixtures / "overpermissive_policy.json")
        with_suggestions = [f for f in report.findings if f.suggestion]
        assert len(with_suggestions) > 0

    def test_summary_counts(self, iam_fixtures):
        report = analyze_policy_file(iam_fixtures / "overpermissive_policy.json")
        assert report.summary["policies_analyzed"] == 1
        assert report.summary["total_findings"] == len(report.findings)
        assert "severity_counts" in report.summary

    def test_report_to_json(self, iam_fixtures):
        report = analyze_policy_file(iam_fixtures / "overpermissive_policy.json")
        json_str = report.to_json()
        assert "iam-check" in json_str
        assert "findings" in json_str
