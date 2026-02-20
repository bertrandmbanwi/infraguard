"""Tests for tag audit scanner."""

from infraguard.tag_audit.scanner import scan_from_file


class TestScanner:
    def test_load_from_file(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        assert len(resources) == 6

    def test_resource_fields(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        first = resources[0]
        assert first.resource_id == "i-0abc123def456"
        assert first.resource_type == "aws_instance"
        assert first.service == "ec2"
        assert first.region == "us-east-1"
        assert first.tags["Environment"] == "production"

    def test_resource_with_missing_tags(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        # Second resource only has "Name" tag
        sparse = resources[1]
        assert sparse.resource_id == "i-0def789abc012"
        assert len(sparse.tags) == 1
        assert "Name" in sparse.tags

    def test_resource_with_arn(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        s3 = next(r for r in resources if r.service == "s3")
        assert s3.arn == "arn:aws:s3:::my-data-bucket"

    def test_to_dict(self, aws_fixtures):
        resources = scan_from_file(aws_fixtures / "tagged_resources.json")
        d = resources[0].to_dict()
        assert "resource_id" in d
        assert "tags" in d
        assert isinstance(d["tags"], dict)
