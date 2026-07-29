"""Pool query tool for cross-agent finding discovery (spec 005).

Allows hunters to query the shared findings pool mid-run to find
complementary primitives for exploit chaining.
"""

from __future__ import annotations

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel

from .sandbox import HunterContext


class QueryFindingsPoolInput(ToolInputModel):
    primitive_type: str = Field(
        default="",
        description="Filter by primitive type (e.g. 'info_leak', 'arbitrary_write', 'use_after_free').",
    )
    cwe: str = Field(default="", description="Filter by CWE identifier (e.g. 'CWE-787').")
    file_path: str = Field(default="", description="Filter by repo-relative file path.")


def build_pool_query_tools(ctx: HunterContext) -> list[NativeToolSpec]:
    """Build the pool query tool for cross-agent finding discovery."""

    def query_findings_pool(
        primitive_type: str = "",
        cwe: str = "",
        file_path: str = "",
    ) -> str:
        """Query the shared findings pool for findings from other hunters."""
        if ctx.findings_pool is None:
            return "Findings pool not available."

        results = ctx.findings_pool.query(
            primitive_type=primitive_type or None,
            cwe=cwe or None,
            file_path=file_path or None,
            exclude_session=ctx.session_id,
        )
        if not results:
            return "No matching findings in the pool."

        lines = [f"Found {len(results)} matching findings:"]
        for f in results[:5]:
            lines.append(
                f"- [{f.get('primitive_type', '?')}] {f.get('file', '?')}:"
                f"{f.get('line_number', '?')} ({f.get('cwe', '?')}, "
                f"{f.get('severity', '?')}): {f.get('description', '')[:200]}"
            )
        if len(results) > 5:
            lines.append(f"  ... and {len(results) - 5} more")
        return "\n".join(lines)

    return [
        NativeToolSpec(
            name="query_findings_pool",
            description=(
                "Query findings from other hunters in this campaign. "
                "Filter by primitive_type (e.g. 'info_leak', 'arbitrary_write'), "
                "CWE, or file path. Use to find complementary primitives "
                "for exploit chaining."
            ),
            schema=QueryFindingsPoolInput.model_json_schema(),
            handler=query_findings_pool,
        )
    ]
