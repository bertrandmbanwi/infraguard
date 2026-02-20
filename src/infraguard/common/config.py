"""YAML rule loading and merging for infraguard modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_rules(path: Path) -> dict[str, Any]:
    """Load a YAML rules file and return its contents."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return data if data else {}


def merge_rules(defaults: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge overrides into defaults. Lists are replaced, dicts are merged."""
    merged = defaults.copy()
    for key, value in overrides.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_rules(merged[key], value)
        else:
            merged[key] = value
    return merged
