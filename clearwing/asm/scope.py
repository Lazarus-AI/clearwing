"""The engagement scope — the key that ties a surface together across runs.

A scope is just a named set of roots (domains / CIDRs / seed URLs) plus
exclusions. Its ``name`` is the engagement key used everywhere else (the
:class:`~clearwing.asm.assets.AssetStore` partition, the report directory, the
knowledge-graph namespace) — the ASM analog of a source-hunt ``repo_url``.

Scopes can be defined once in ``~/.clearwing/config.yaml`` under
``asm.scopes.<name>`` and referenced by name, or synthesized on the fly from a
single domain on the command line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_SCOPE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")


class ScopeError(ValueError):
    """A scope definition is malformed or unsafe."""


@dataclass
class Scope:
    """A named attack-surface engagement."""

    name: str
    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    seed_urls: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not _SCOPE_NAME_RE.fullmatch(self.name):
            raise ScopeError(
                f"Invalid scope name {self.name!r}; use letters, digits, '.', '_' or '-'"
            )
        self.domains = [d.strip().lower() for d in self.domains if d.strip()]
        for domain in self.domains:
            if not _DOMAIN_RE.fullmatch(domain):
                raise ScopeError(f"Invalid domain in scope {self.name!r}: {domain!r}")

    def in_scope(self, name: str) -> bool:
        """Whether a discovered name belongs to this scope (and isn't excluded)."""
        candidate = name.strip().lower().rstrip(".")
        if any(candidate == ex or candidate.endswith("." + ex) for ex in self.exclusions):
            return False
        return any(
            candidate == root or candidate.endswith("." + root) for root in self.domains
        )

    @classmethod
    def from_domain(cls, domain: str, name: str | None = None) -> Scope:
        """Build an ad-hoc single-domain scope (the `asm scan <domain>` path)."""
        domain = domain.strip().lower().rstrip(".")
        scope_name = name or domain.replace(".", "_")
        return cls(name=scope_name, domains=[domain])

    @classmethod
    def from_config(cls, name: str, config_section: dict[str, Any]) -> Scope:
        """Load a named scope from an ``asm.scopes`` mapping."""
        scopes = (config_section or {}).get("scopes") or {}
        raw = scopes.get(name)
        if raw is None:
            raise ScopeError(f"No scope named {name!r} configured under asm.scopes")
        return cls(
            name=name,
            domains=list(raw.get("domains") or []),
            cidrs=list(raw.get("cidrs") or []),
            seed_urls=list(raw.get("seed_urls") or []),
            exclusions=[e.strip().lower() for e in (raw.get("exclusions") or [])],
        )

    @classmethod
    def resolve(cls, target: str, config_section: dict[str, Any] | None = None) -> Scope:
        """Resolve a CLI target to a Scope: a configured name, else a bare domain."""
        section = config_section or {}
        if (section.get("scopes") or {}).get(target) is not None:
            return cls.from_config(target, section)
        if _DOMAIN_RE.fullmatch(target.strip().lower().rstrip(".")):
            return cls.from_domain(target)
        raise ScopeError(
            f"{target!r} is neither a configured asm scope nor a valid domain"
        )


__all__ = ["Scope", "ScopeError"]
