"""Tests for individual IAM policy checks."""

from infraguard.common.severity import Severity
from infraguard.iam_check.checks import (
    check_admin_access,
    check_cross_account_access,
    check_dangerous_actions,
    check_missing_conditions,
    check_wildcard_actions,
)


class TestAdminAccess:
    def test_full_admin(self):
        stmt = {"Effect": "Allow", "Action": "*", "Resource": "*"}
        findings = check_admin_access(stmt, 0, "test")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_deny_not_flagged(self):
        stmt = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        findings = check_admin_access(stmt, 0, "test")
        assert len(findings) == 0

    def test_scoped_not_admin(self):
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        findings = check_admin_access(stmt, 0, "test")
        assert len(findings) == 0


class TestWildcardActions:
    def test_service_wildcard(self):
        stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        findings = check_wildcard_actions(stmt, 0, "test")
        assert len(findings) == 1
        assert "s3:*" in findings[0].title

    def test_sensitive_service_is_high(self):
        stmt = {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
        findings = check_wildcard_actions(stmt, 0, "test")
        assert findings[0].severity == Severity.HIGH

    def test_non_sensitive_is_medium(self):
        stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        findings = check_wildcard_actions(stmt, 0, "test")
        assert findings[0].severity == Severity.MEDIUM

    def test_specific_action_not_flagged(self):
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        findings = check_wildcard_actions(stmt, 0, "test")
        assert len(findings) == 0

    def test_suggestion_provided(self):
        stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        findings = check_wildcard_actions(stmt, 0, "test")
        assert "s3:GetObject" in findings[0].suggestion


class TestDangerousActions:
    def test_pass_role_flagged(self):
        stmt = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
        findings = check_dangerous_actions(stmt, 0, "test")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_delete_trail_critical(self):
        stmt = {"Effect": "Allow", "Action": "cloudtrail:DeleteTrail", "Resource": "*"}
        findings = check_dangerous_actions(stmt, 0, "test")
        assert findings[0].severity == Severity.CRITICAL

    def test_safe_action_clean(self):
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        findings = check_dangerous_actions(stmt, 0, "test")
        assert len(findings) == 0


class TestMissingConditions:
    def test_sensitive_without_condition(self):
        stmt = {"Effect": "Allow", "Action": ["sts:AssumeRole", "iam:PassRole"], "Resource": "*"}
        findings = check_missing_conditions(stmt, 0, "test")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_with_condition_clean(self):
        stmt = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}},
        }
        findings = check_missing_conditions(stmt, 0, "test")
        assert len(findings) == 0

    def test_non_sensitive_no_finding(self):
        stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        findings = check_missing_conditions(stmt, 0, "test")
        assert len(findings) == 0


class TestCrossAccountAccess:
    def test_wildcard_principal_no_condition(self):
        stmt = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}
        findings = check_cross_account_access(stmt, 0, "test")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_root_principal_no_condition(self):
        stmt = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
        }
        findings = check_cross_account_access(stmt, 0, "test")
        assert len(findings) == 1

    def test_with_condition_clean(self):
        stmt = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": "*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}},
        }
        findings = check_cross_account_access(stmt, 0, "test")
        assert len(findings) == 0
