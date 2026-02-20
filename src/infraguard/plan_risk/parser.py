"""Parse Terraform plan JSON output into structured change objects."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ResourceChange:
    """A single resource change from a Terraform plan."""

    address: str
    resource_type: str
    action: str
    name: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None

    @property
    def tags_before(self) -> dict[str, str]:
        if self.before and isinstance(self.before.get("tags"), dict):
            return self.before["tags"]
        return {}

    @property
    def tags_after(self) -> dict[str, str]:
        if self.after and isinstance(self.after.get("tags"), dict):
            return self.after["tags"]
        return {}

def parse_plan(source: Path | None = None) -> list[ResourceChange]:
    """Parse terraform plan JSON from a file or stdin.

    Expects the output of: ``terraform show -json <planfile>``
    """
    if source:
        with open(source) as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)

    return _extract_changes(data)

def _extract_changes(data: dict[str, Any]) -> list[ResourceChange]:
    """Extract resource changes from a terraform plan JSON structure."""
    changes: list[ResourceChange] = []

    for rc in data.get("resource_changes", []):
        if rc.get("mode") == "data":
            continue

        change = rc.get("change", {})
        actions = change.get("actions", [])
        action = _normalize_action(actions)

        if action == "no-op":
            continue

        address = rc.get("address", "unknown")
        resource_type = rc.get("type", "unknown")
        name = rc.get("name", "unknown")

        changes.append(
            ResourceChange(
                address=address,
                resource_type=resource_type,
                action=action,
                name=name,
                before=change.get("before"),
                after=change.get("after"),
            )
        )

    return changes

def _normalize_action(actions: list[str]) -> str:
    """Normalize terraform action list to a single action string.

    Terraform represents actions as a list:
    - ["create"] → create
    - ["delete"] → delete
    - ["update"] → update
    - ["delete", "create"] → replace
    - ["create", "delete"] → replace
    - ["read"] → read
    - ["no-op"] → no-op
    """
    action_set = set(actions)

    if action_set == {"delete", "create"} or action_set == {"create", "delete"}:
        return "replace"
    if "delete" in action_set:
        return "delete"
    if "create" in action_set:
        return "create"
    if "update" in action_set:
        return "update"
    if "read" in action_set:
        return "read"
    return "no-op"
