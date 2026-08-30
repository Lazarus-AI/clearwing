"""Per-hunter ReAct tools for the source-hunt pipeline.

Public entry points:
- `HunterContext`                  — the mutable per-hunter state (sandbox,
                                      findings list, specialist, session_id).
- `build_hunter_tools(ctx)`        — the static-analysis tool set for
                                      memory_safety / logic_auth / general
                                      specialists.
- `build_propagation_auditor_tools(ctx)` — the Tier C static-analysis set.
- `build_verification_tools(ctx)`      — sandbox tools used only by the
                                      independent verification phase.

Internal layout:
    sandbox.py    — HunterContext dataclass + sanitizer-variant routing
    discovery.py  — read_source_file, list_source_tree, grep_source, find_callers
    analysis.py   — compile_file, run_with_sanitizer, write_test_case, fuzz_harness
    reporting.py  — record_finding

Phase 5a–d split these out of the 791-LOC hunter_tools.py god file.
The per-module `build_*_tools(ctx)` factories are composed here; the
exact tool order is preserved so the tool-registry snapshot test stays
green.

The underscore-prefixed helpers (`_normalize_path`, `_parse_rg_output`,
`_default_libfuzzer_template`, `_parse_sanitizer_report`,
`_parse_variant_arg`, etc.) are re-exported here for the handful of
test files that reach into them. Move them to tests/fixtures/ if the
test reach-ins ever become burdensome.
"""

from __future__ import annotations

from .analysis import (
    _default_libfuzzer_template,
    _parse_sanitizer_report,
    build_analysis_tools,
)
from .deep_agent import build_deep_agent_tools
from .discovery import (
    _container_path,
    _grep_python_fallback,
    _normalize_path,
    _parse_rg_output,
    build_discovery_tools,
    build_semgrep_tool,
)
from .pool_query import build_pool_query_tools
from .reporting import build_reporting_tools
from .sandbox import HunterContext, _parse_variant_arg
from .verification import build_verification_workspace_tools


def build_hunter_tools(ctx: HunterContext) -> list:
    """Static hunter tool set for memory_safety / logic_auth / general specialists.

    Dynamic compile/run/test/fuzz tools belong to verification, not hunting.
    Their builder remains exported for verifier and focused-tool callers.
    """
    tools = [
        *build_discovery_tools(ctx),
        *build_reporting_tools(ctx),
    ]
    if ctx.findings_pool is not None:
        tools.extend(build_pool_query_tools(ctx))
    return tools


def build_propagation_auditor_tools(ctx: HunterContext) -> list:
    """Static tool set for Tier C propagation auditors.

    Tier C auditors grep and reason about downstream usages of definitions.
    """
    tools = [
        *build_discovery_tools(ctx),
        *build_reporting_tools(ctx),
    ]
    if ctx.findings_pool is not None:
        tools.extend(build_pool_query_tools(ctx))
    return tools


def build_verification_tools(ctx: HunterContext) -> list:
    """Build the sandbox tool set for independent dynamic verification.

    The verifier gets the same three primitives a human needs to inspect,
    instrument, build, and run a real checkout. Keeping this palette minimal
    avoids duplicating compile/fuzz helper schemas in every verification turn.
    """
    return build_verification_workspace_tools(ctx)


__all__ = [
    # Public API
    "HunterContext",
    "build_deep_agent_tools",
    "build_hunter_tools",
    "build_propagation_auditor_tools",
    "build_verification_tools",
    # Per-domain builders (for callers that want a narrower tool set)
    "build_discovery_tools",
    "build_semgrep_tool",
    "build_analysis_tools",
    "build_reporting_tools",
    "build_pool_query_tools",
    # Re-exported helpers for test reach-ins
    "_container_path",
    "_default_libfuzzer_template",
    "_grep_python_fallback",
    "_normalize_path",
    "_parse_rg_output",
    "_parse_sanitizer_report",
    "_parse_variant_arg",
]
