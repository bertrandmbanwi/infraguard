"""Default tag compliance rules for AWS resource auditing."""

from __future__ import annotations

# ── Default required tags ─────────────────────────────────────
# Every resource should have at minimum these tags.

DEFAULT_REQUIRED_TAGS: list[dict] = [
    {
        "key": "Environment",
        "allowed_values": ["production", "staging", "development", "sandbox"],
    },
    {
        "key": "Team",
    },
    {
        "key": "Service",
    },
    {
        "key": "ManagedBy",
        "allowed_values": ["terraform", "cloudformation", "manual", "pulumi", "cdk"],
    },
]

# ── Service-to-boto3 mapping ──────────────────────────────────
# Maps service names to the boto3 calls needed to scan them.

SUPPORTED_SERVICES: dict[str, dict] = {
    "ec2": {
        "client": "ec2",
        "method": "describe_instances",
        "resource_path": "Reservations[].Instances[]",
        "id_key": "InstanceId",
        "tag_key": "Tags",
        "resource_type": "aws_instance",
    },
    "rds": {
        "client": "rds",
        "method": "describe_db_instances",
        "resource_path": "DBInstances",
        "id_key": "DBInstanceIdentifier",
        "tag_key": "TagList",
        "resource_type": "aws_db_instance",
    },
    "s3": {
        "client": "s3",
        "method": "list_buckets",
        "resource_path": "Buckets",
        "id_key": "Name",
        "tag_key": None,  # Requires separate get_bucket_tagging call
        "resource_type": "aws_s3_bucket",
    },
    "lambda": {
        "client": "lambda",
        "method": "list_functions",
        "resource_path": "Functions",
        "id_key": "FunctionName",
        "tag_key": "Tags",
        "resource_type": "aws_lambda_function",
    },
    "ecs": {
        "client": "ecs",
        "method": "list_clusters",
        "resource_path": "clusterArns",
        "id_key": None,  # ARN is the id
        "tag_key": "tags",
        "resource_type": "aws_ecs_cluster",
    },
    "dynamodb": {
        "client": "dynamodb",
        "method": "list_tables",
        "resource_path": "TableNames",
        "id_key": None,  # Name is the id
        "tag_key": None,  # Requires separate list_tags_of_resource
        "resource_type": "aws_dynamodb_table",
    },
    "sns": {
        "client": "sns",
        "method": "list_topics",
        "resource_path": "Topics",
        "id_key": "TopicArn",
        "tag_key": None,  # Requires separate list_tags_for_resource
        "resource_type": "aws_sns_topic",
    },
    "sqs": {
        "client": "sqs",
        "method": "list_queues",
        "resource_path": "QueueUrls",
        "id_key": None,  # URL is the id
        "tag_key": None,  # Requires separate list_queue_tags
        "resource_type": "aws_sqs_queue",
    },
}

# ── Naming conventions ────────────────────────────────────────

DEFAULT_NAMING_RULES: dict = {
    "prohibited_prefixes": ["aws:", "temp_", "test_"],
    "prohibited_values": ["", "null", "none", "undefined", "N/A"],
}
