"""Default IAM policy analysis rules and dangerous permission definitions."""

from __future__ import annotations

from infraguard.common.severity import Severity

DANGEROUS_ACTIONS: dict[str, Severity] = {
    "iam:CreateUser": Severity.HIGH,
    "iam:CreateRole": Severity.HIGH,
    "iam:AttachUserPolicy": Severity.CRITICAL,
    "iam:AttachRolePolicy": Severity.CRITICAL,
    "iam:AttachGroupPolicy": Severity.CRITICAL,
    "iam:PutUserPolicy": Severity.CRITICAL,
    "iam:PutRolePolicy": Severity.CRITICAL,
    "iam:PutGroupPolicy": Severity.CRITICAL,
    "iam:CreateAccessKey": Severity.HIGH,
    "iam:CreateLoginProfile": Severity.HIGH,
    "iam:UpdateAssumeRolePolicy": Severity.CRITICAL,
    "iam:PassRole": Severity.HIGH,
    "iam:CreatePolicyVersion": Severity.HIGH,
    "iam:SetDefaultPolicyVersion": Severity.HIGH,

    "sts:AssumeRole": Severity.MEDIUM,
    "sts:AssumeRoleWithSAML": Severity.MEDIUM,
    "sts:AssumeRoleWithWebIdentity": Severity.MEDIUM,
    "sts:GetFederationToken": Severity.MEDIUM,

    "s3:DeleteBucket": Severity.HIGH,
    "s3:PutBucketPolicy": Severity.HIGH,
    "s3:PutBucketAcl": Severity.HIGH,

    "ec2:TerminateInstances": Severity.HIGH,
    "ec2:DeleteSecurityGroup": Severity.MEDIUM,
    "ec2:AuthorizeSecurityGroupIngress": Severity.MEDIUM,
    "ec2:ModifyInstanceAttribute": Severity.MEDIUM,

    "rds:DeleteDBInstance": Severity.HIGH,
    "rds:DeleteDBCluster": Severity.HIGH,
    "rds:ModifyDBInstance": Severity.MEDIUM,

    "lambda:CreateFunction": Severity.MEDIUM,
    "lambda:UpdateFunctionCode": Severity.HIGH,
    "lambda:AddPermission": Severity.HIGH,
    "lambda:CreateEventSourceMapping": Severity.MEDIUM,

    "kms:Decrypt": Severity.MEDIUM,
    "kms:ScheduleKeyDeletion": Severity.CRITICAL,
    "kms:DisableKey": Severity.HIGH,
    "kms:PutKeyPolicy": Severity.CRITICAL,

    "organizations:LeaveOrganization": Severity.CRITICAL,
    "organizations:DeleteOrganization": Severity.CRITICAL,

    "cloudtrail:DeleteTrail": Severity.CRITICAL,
    "cloudtrail:StopLogging": Severity.CRITICAL,
    "cloudtrail:UpdateTrail": Severity.HIGH,

    "guardduty:DeleteDetector": Severity.CRITICAL,
    "guardduty:DisassociateFromMasterAccount": Severity.HIGH,
}

SENSITIVE_SERVICE_PREFIXES: list[str] = [
    "iam:",
    "sts:",
    "kms:",
    "cloudtrail:",
    "guardduty:",
    "organizations:",
    "config:",
    "securityhub:",
    "access-analyzer:",
]

WILDCARD_SUGGESTIONS: dict[str, list[str]] = {
    "s3:*": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
    "ec2:*": ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs"],
    "lambda:*": ["lambda:InvokeFunction", "lambda:GetFunction", "lambda:ListFunctions"],
    "dynamodb:*": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan"],
    "sqs:*": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
    "sns:*": ["sns:Publish", "sns:Subscribe", "sns:ListTopics"],
    "logs:*": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
    "iam:*": ["iam:GetRole", "iam:ListRoles", "iam:GetPolicy"],
}
