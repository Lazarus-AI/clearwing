"""Core domain model dataclasses.

These types provide a structured alternative to raw dicts for data flowing
between scanners, the agent, and reporting. Existing dict-based code
continues to work — adopt these gradually.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Port:
    """A discovered network port."""

    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""


@dataclass
class Service:
    """A detected network service."""

    name: str
    port: int
    protocol: str = "tcp"
    version: str = ""
    banner: str = ""


@dataclass
class Vulnerability:
    """A discovered vulnerability."""

    cve: str = ""
    description: str = ""
    cvss: float = 0.0
    severity: str = "info"
    port: int = 0
    service: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class ExploitResult:
    """Result of an exploitation attempt."""

    vulnerability: str = ""
    success: bool = False
    output: str = ""
    method: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class Credential:
    """A discovered credential."""

    username: str = ""
    password: str = ""
    service: str = ""
    port: int = 0
    method: str = ""
