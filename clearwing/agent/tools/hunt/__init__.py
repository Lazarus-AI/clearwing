"""Per-hunter ReAct tools for the source-hunt pipeline.

Public entry points:
- `HunterContext`                  — the mutable per-hunter state (sandbox,
                                      findings list, specialist, session_id).
- `build_hunter_tools(ctx)`        — the full 9-tool set for memory_safety /
                                      logic_auth / general specialists.
- `build_propagation_auditor_tools(ctx)` — the narrower Tier C subset that
                                      drops the sandboxed build+execute tools
                                      (compile/run/fuzz/write_test_case).

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
from .discovery import (
    _container_path,
    _grep_python_fallback,
    _normalize_path,
    _parse_rg_output,
    build_discovery_tools,
)
from .deep_agent import build_deep_agent_tools
from .reporting import build_reporting_tools
from .sandbox import HunterContext, _parse_variant_arg


def build_hunter_tools(ctx: HunterContext) -> list:
    """Full hunter tool set for memory_safety / logic_auth / general specialists.

    Composes discovery + analysis + reporting into a single flat list
    in the order the legacy hunter_tools.py closure emitted them.
    """
    return [
        *build_discovery_tools(ctx),
        *build_analysis_tools(ctx),
        *build_reporting_tools(ctx),
    ]


def build_propagation_auditor_tools(ctx: HunterContext) -> list:
    """Narrower tool set for Tier C propagation auditors.

    Tier C auditors don't compile or run — they grep and reason about
    downstream usages of definitions. This subset keeps them cheap and
    on-task: discovery tools (read_source_file, list_source_tree,
    grep_source, find_callers) + record_finding.
    """
    return [
        *build_discovery_tools(ctx),
        *build_reporting_tools(ctx),
    ]


__all__ = [
    # Public API
    "HunterContext",
    "build_deep_agent_tools",
    "build_hunter_tools",
    "build_propagation_auditor_tools",
    # Per-domain builders (for callers that want a narrower tool set)
    "build_discovery_tools",
    "build_analysis_tools",
    "build_reporting_tools",
    # Re-exported helpers for test reach-ins
    "_container_path",
    "_default_libfuzzer_template",
    "_grep_python_fallback",
    "_normalize_path",
    "_parse_rg_output",
    "_parse_sanitizer_report",
    "_parse_variant_arg",
]
