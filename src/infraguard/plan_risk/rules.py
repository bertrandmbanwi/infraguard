"""Default scoring rules for Terraform plan risk analysis."""

from __future__ import annotations

from infraguard.common.severity import Severity

ACTION_WEIGHTS: dict[str, int] = {
    "delete": 5,
    "replace": 4,
    "update": 2,
    "create": 1,
    "read": 0,
    "no-op": 0,
}

RESOURCE_CRITICALITY: dict[str, Severity] = {
    "aws_db_instance": Severity.CRITICAL,
    "aws_rds_cluster": Severity.CRITICAL,
    "aws_rds_cluster_instance": Severity.CRITICAL,
    "aws_dynamodb_table": Severity.CRITICAL,
    "aws_s3_bucket": Severity.CRITICAL,
    "aws_iam_role": Severity.CRITICAL,
    "aws_iam_policy": Severity.CRITICAL,
    "aws_iam_user": Severity.CRITICAL,
    "aws_kms_key": Severity.CRITICAL,
    "aws_secretsmanager_secret": Severity.CRITICAL,
    "aws_elasticache_replication_group": Severity.CRITICAL,
    "google_sql_database_instance": Severity.CRITICAL,
    "google_storage_bucket": Severity.CRITICAL,
    "azurerm_mssql_database": Severity.CRITICAL,
    "azurerm_storage_account": Severity.CRITICAL,

    "aws_lb": Severity.HIGH,
    "aws_alb": Severity.HIGH,
    "aws_ecs_service": Severity.HIGH,
    "aws_ecs_cluster": Severity.HIGH,
    "aws_eks_cluster": Severity.HIGH,
    "aws_elasticache_cluster": Severity.HIGH,
    "aws_route53_zone": Severity.HIGH,
    "aws_route53_record": Severity.HIGH,
    "aws_cloudfront_distribution": Severity.HIGH,
    "aws_nat_gateway": Severity.HIGH,
    "aws_vpn_gateway": Severity.HIGH,
    "aws_elasticsearch_domain": Severity.HIGH,
    "aws_opensearch_domain": Severity.HIGH,
    "google_container_cluster": Severity.HIGH,
    "azurerm_kubernetes_cluster": Severity.HIGH,

    "aws_instance": Severity.MEDIUM,
    "aws_security_group": Severity.MEDIUM,
    "aws_security_group_rule": Severity.MEDIUM,
    "aws_vpc": Severity.MEDIUM,
    "aws_subnet": Severity.MEDIUM,
    "aws_lambda_function": Severity.MEDIUM,
    "aws_ecs_task_definition": Severity.MEDIUM,
    "aws_sqs_queue": Severity.MEDIUM,
    "aws_sns_topic": Severity.MEDIUM,
    "aws_api_gateway_rest_api": Severity.MEDIUM,
    "aws_apigatewayv2_api": Severity.MEDIUM,
    "aws_acm_certificate": Severity.MEDIUM,
    "google_compute_instance": Severity.MEDIUM,
    "azurerm_virtual_machine": Severity.MEDIUM,

    "aws_cloudwatch_log_group": Severity.LOW,
    "aws_cloudwatch_metric_alarm": Severity.LOW,
    "aws_ssm_parameter": Severity.LOW,
    "aws_autoscaling_group": Severity.LOW,
    "aws_launch_template": Severity.LOW,
    "aws_ecr_repository": Severity.LOW,

    "aws_autoscaling_tag": Severity.INFO,
}

DEFAULT_CRITICALITY = Severity.MEDIUM

ENVIRONMENT_MULTIPLIERS: dict[str, float] = {
    "prod": 2.0,
    "production": 2.0,
    "prd": 2.0,
    "staging": 1.5,
    "stage": 1.5,
    "stg": 1.5,
    "uat": 1.5,
    "dev": 1.0,
    "development": 1.0,
    "test": 1.0,
    "sandbox": 1.0,
}

DEFAULT_ENVIRONMENT_MULTIPLIER = 1.0
