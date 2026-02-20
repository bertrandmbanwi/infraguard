"""AWS resource scanner — fetches resources and their tags via boto3 or JSON file."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TaggedResource:
    """A single AWS resource with its tags."""

    resource_id: str
    resource_type: str
    service: str
    region: str
    tags: dict[str, str] = field(default_factory=dict)
    arn: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "service": self.service,
            "region": self.region,
            "tags": self.tags,
            "arn": self.arn,
        }

def scan_from_file(path: Path) -> list[TaggedResource]:
    """Load resource data from a JSON file (offline/CI mode).

    Expected format:
    {
        "resources": [
            {
                "resource_id": "i-0abc123",
                "resource_type": "aws_instance",
                "service": "ec2",
                "region": "us-east-1",
                "tags": {"Environment": "production", "Team": "platform"},
                "arn": "arn:aws:ec2:..."
            }
        ]
    }
    """
    with open(path) as f:
        data = json.load(f)

    resources = []
    for item in data.get("resources", []):
        resources.append(
            TaggedResource(
                resource_id=item.get("resource_id", "unknown"),
                resource_type=item.get("resource_type", "unknown"),
                service=item.get("service", "unknown"),
                region=item.get("region", "unknown"),
                tags=item.get("tags", {}),
                arn=item.get("arn", ""),
            )
        )
    return resources

def scan_aws(
    services: list[str] | None = None,
    profile: str | None = None,
    region: str = "us-east-1",
) -> list[TaggedResource]:
    """Scan AWS resources using boto3.

    Requires `infraguard[aws]` (boto3).
    """
    try:
        import boto3
    except ImportError:
        raise RuntimeError(
            "boto3 is required for live AWS scanning. "
            "Install with: pip install 'infraguard[aws]'"
        )

    from infraguard.tag_audit.rules import SUPPORTED_SERVICES

    target_services = services or list(SUPPORTED_SERVICES.keys())
    session = boto3.Session(profile_name=profile, region_name=region)
    resources: list[TaggedResource] = []

    for svc_name in target_services:
        if svc_name not in SUPPORTED_SERVICES:
            continue

        svc_config = SUPPORTED_SERVICES[svc_name]
        try:
            client = session.client(svc_config["client"])
            resources.extend(_scan_service(client, svc_name, svc_config, region, session))
        except Exception:

            continue

    return resources

def _scan_service(
    client: Any,
    svc_name: str,
    svc_config: dict,
    region: str,
    session: Any,
) -> list[TaggedResource]:
    """Scan a single AWS service for resources and tags."""
    resources: list[TaggedResource] = []

    if svc_name == "ec2":
        resp = client.describe_instances()
        for reservation in resp.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                resources.append(
                    TaggedResource(
                        resource_id=instance["InstanceId"],
                        resource_type="aws_instance",
                        service="ec2",
                        region=region,
                        tags=tags,
                        arn=instance.get("InstanceId", ""),
                    )
                )

    elif svc_name == "rds":
        resp = client.describe_db_instances()
        for db in resp.get("DBInstances", []):
            tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
            resources.append(
                TaggedResource(
                    resource_id=db["DBInstanceIdentifier"],
                    resource_type="aws_db_instance",
                    service="rds",
                    region=region,
                    tags=tags,
                    arn=db.get("DBInstanceArn", ""),
                )
            )

    elif svc_name == "s3":
        resp = client.list_buckets()
        for bucket in resp.get("Buckets", []):
            name = bucket["Name"]
            try:
                tag_resp = client.get_bucket_tagging(Bucket=name)
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagSet", [])}
            except Exception:
                tags = {}
            resources.append(
                TaggedResource(
                    resource_id=name,
                    resource_type="aws_s3_bucket",
                    service="s3",
                    region="global",
                    tags=tags,
                    arn=f"arn:aws:s3:::{name}",
                )
            )

    elif svc_name == "lambda":
        resp = client.list_functions()
        for fn in resp.get("Functions", []):

            tags = fn.get("Tags", {}) or {}
            resources.append(
                TaggedResource(
                    resource_id=fn["FunctionName"],
                    resource_type="aws_lambda_function",
                    service="lambda",
                    region=region,
                    tags=tags,
                    arn=fn.get("FunctionArn", ""),
                )
            )

    return resources
