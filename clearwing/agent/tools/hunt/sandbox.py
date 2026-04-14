"""Per-hunter sandbox context and sanitizer-variant routing.

`HunterContext` is the mutable state passed to every per-hunter tool
builder (discovery/analysis/reporting). It owns the primary
SandboxContainer plus a cache of sanitizer-variant containers so that
an MSan hunter can transparently spawn a second image without the
caller tracking it.

This file holds ONLY the context dataclass and the argument parser for
the `sanitizer_variant` tool argument. All tool builders live in
sibling modules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from clearwing.sandbox.container import SandboxContainer
from clearwing.sourcehunt.state import Finding

logger = logging.getLogger(__name__)


@dataclass
class HunterContext:
    """Per-hunter mutable context. Closured into every tool for state access."""

    repo_path: str  # absolute host path
    sandbox: SandboxContainer | None = None  # primary sandbox; set by hunt loop
    findings: list[Finding] = field(default_factory=list)
    file_path: str | None = None  # the file this hunter is scoped to
    session_id: str | None = None
    specialist: str = "general"  # "general" | "memory_safety" | "logic_auth" | "propagation"
    seeded_crash: dict | None = None  # v0.2: from harness generator
    # v0.4 MSan variant support: a HunterSandbox manager so tools can
    # spawn alternative-sanitizer containers (e.g. MSan) on demand.
    # Variant containers are cached in `variant_sandboxes` and torn down
    # at hunter cleanup time.
    sandbox_manager: object | None = None  # HunterSandbox (avoiding circular import)
    variant_sandboxes: dict = field(default_factory=dict)  # {variant_key: SandboxContainer}
    default_sanitizers: tuple = ("asan", "ubsan")

    def get_sandbox_for_variant(
        self,
        sanitizer_variant: list[str] | None = None,
    ) -> SandboxContainer | None:
        """Return the SandboxContainer for the requested sanitizer variant.

        - variant=None or matches default → returns self.sandbox (fast path)
        - different variant → spawns from self.sandbox_manager and caches
        - no manager → returns self.sandbox (degraded: the variant is ignored)
        """
        if sanitizer_variant is None:
            return self.sandbox
        chosen = list(sanitizer_variant)
        # If the default variant is requested, reuse the primary sandbox
        if sorted(chosen) == sorted(self.default_sanitizers):
            return self.sandbox
        key = "+".join(sorted(chosen))
        cached = self.variant_sandboxes.get(key)
        if cached is not None:
            return cached
        # Need to spawn a new variant container
        if self.sandbox_manager is None:
            # No manager — degrade to the primary sandbox
            logger.debug(
                "variant=%s requested but no sandbox_manager; using primary",
                chosen,
            )
            return self.sandbox
        try:
            sb = self.sandbox_manager.spawn(  # type: ignore[attr-defined]
                session_id=self.session_id,
                variant=chosen,
            )
        except Exception:
            logger.warning("Failed to spawn variant sandbox %s", chosen, exc_info=True)
            return self.sandbox
        self.variant_sandboxes[key] = sb
        return sb

    def cleanup_variants(self) -> None:
        """Stop every cached variant container. Call when the hunter finishes."""
        for sb in self.variant_sandboxes.values():
            try:
                sb.stop()
            except Exception:
                logger.debug("cleanup_variants stop failed", exc_info=True)
        self.variant_sandboxes.clear()


def _parse_variant_arg(sanitizer_variant: str) -> list[str] | None:
    """Translate the `sanitizer_variant` tool arg into a sanitizer list.

    Accepts:
        "" or None     → None (use the primary default sandbox)
        "msan"          → ["msan"]
        "asan,ubsan"    → ["asan", "ubsan"]
        "asan+ubsan"    → ["asan", "ubsan"]
    """
    if not sanitizer_variant:
        return None
    parts = [p.strip().lower() for p in sanitizer_variant.replace("+", ",").split(",") if p.strip()]
    return parts or None
