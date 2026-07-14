"""Regression guards for Clearwing's genai-pyo3-only LLM runtime."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_litellm_is_not_a_project_dependency() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "litellm" not in pyproject.casefold()


def test_litellm_is_not_imported() -> None:
    offenders: list[str] = []
    for path in (ROOT / "clearwing").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            else:
                continue
            if any(module.split(".", 1)[0].casefold() == "litellm" for module in modules):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []
