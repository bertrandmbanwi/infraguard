"""Severity levels shared across all infraguard modules."""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """Risk/finding severity — higher value means more critical."""

    INFO = 1
    LOW = 2
    MEDIUM = 4
    HIGH = 7
    CRITICAL = 10

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return _COLORS[self]

    @property
    def icon(self) -> str:
        return _ICONS[self]


_COLORS: dict[Severity, str] = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

_ICONS: dict[Severity, str] = {
    Severity.INFO: "ℹ️",
    Severity.LOW: "🔵",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🟠",
    Severity.CRITICAL: "🔴",
}
