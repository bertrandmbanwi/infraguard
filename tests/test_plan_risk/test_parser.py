"""Tests for Terraform plan JSON parser."""

from infraguard.plan_risk.parser import parse_plan


class TestParser:
    def test_simple_create(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "simple_create.json")
        assert len(changes) == 2
        assert changes[0].action == "create"
        assert changes[0].resource_type == "aws_instance"
        assert changes[0].address == "aws_instance.web"

    def test_destroy_database(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "destroy_database.json")
        assert len(changes) == 4

        actions = {c.address: c.action for c in changes}
        assert actions["aws_db_instance.prod_main"] == "delete"
        assert actions["aws_ecs_service.api"] == "replace"
        assert actions["aws_security_group.web"] == "update"
        assert actions["aws_cloudwatch_log_group.app"] == "create"

    def test_mixed_changes_skips_data_sources(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "mixed_changes.json")
        # data.aws_ami.latest should be skipped
        addresses = [c.address for c in changes]
        assert "data.aws_ami.latest" not in addresses
        assert len(changes) == 4

    def test_replace_action_normalization(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "destroy_database.json")
        ecs = next(c for c in changes if "ecs_service" in c.address)
        assert ecs.action == "replace"

    def test_resource_types_extracted(self, terraform_fixtures):
        changes = parse_plan(terraform_fixtures / "mixed_changes.json")
        types = {c.resource_type for c in changes}
        assert "aws_vpc" in types
        assert "aws_s3_bucket" in types
        assert "aws_lambda_function" in types
        assert "aws_ssm_parameter" in types
