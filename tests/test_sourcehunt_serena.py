from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.serena import SERENA_MAX_SEARCH_RESULT_CHARS, SerenaSession


def _fake_client() -> MagicMock:
    client = MagicMock()
    client.list_tools.return_value = [
        {
            "name": "find_symbol",
            "description": "Find a symbol",
            "inputSchema": {
                "type": "object",
                "properties": {"name_path_pattern": {"type": "string"}},
                "required": ["name_path_pattern"],
            },
        },
        {
            "name": "replace_symbol_body",
            "description": "Edit a symbol",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]
    client.call_tool.return_value = {"content": [{"type": "text", "text": "found"}]}
    return client


def test_serena_session_launches_official_image_and_filters_writes(
    tmp_path, caplog
) -> None:
    caplog.set_level("INFO")
    (tmp_path / "src").mkdir()
    (tmp_path / "go.mod").write_text("module example\n")
    client = _fake_client()
    factory = MagicMock(return_value=client)
    session = SerenaSession(str(tmp_path), languages=["go"], client_factory=factory)

    tools = session.start()

    assert "workspace mounted read-only" in caplog.text
    assert f"{tmp_path.resolve()} -> /workspace" in caplog.text
    command, args = factory.call_args.args
    assert command == "docker"
    assert "ghcr.io/oraios/serena:latest" in args
    assert "--entrypoint" in args
    assert "golang-go gopls" in args[-1]
    assert f"{tmp_path.resolve()}:/workspace:ro" in args
    assert any(str(arg).endswith(":/serena-data") for arg in args)
    assert "SERENA_HOME=/serena-data" in args
    assert "SERENA_USAGE_REPORTING=false" in args
    state_mount = next(
        str(arg) for arg in args if str(arg).endswith(":/serena-data")
    )
    config = Path(state_mount.removesuffix(":/serena-data"), "serena_config.yml")
    config_text = config.read_text()
    assert "projects: []" in config_text
    assert '  - "npm/**"' in config_text
    assert '  - "**/*min.js"' in config_text
    assert "--project /workspace" in args[-1]
    assert factory.call_args.kwargs == {
        "initialize_timeout": 300.0,
        "request_timeout": 120.0,
    }
    assert [tool.name for tool in tools] == ["serena_find_symbol"]


def test_serena_bootstraps_clangd_for_c_and_cpp(tmp_path) -> None:
    client = _fake_client()
    factory = MagicMock(return_value=client)
    session = SerenaSession(
        str(tmp_path), languages=["c", "cpp", "rust", "python"], client_factory=factory
    )

    session.start()

    args = factory.call_args.args[1]
    assert "clangd" in args[-1]
    assert "golang-go" not in args[-1]
    state_mount = next(
        str(arg) for arg in args if str(arg).endswith(":/serena-data")
    )
    project_config = Path(
        state_mount.removesuffix(":/serena-data"),
        "projects",
        "workspace",
        ".serena",
        "project.yml",
    ).read_text()
    assert project_config.count("  - cpp\n") == 1
    assert "  - c\n" not in project_config
    assert 'project_name: "workspace"' in project_config
    assert "language_servers:\n  - cpp\n" in project_config
    assert "ls_specific_settings:\n  cpp:\n" in project_config
    assert "compile_commands_dir: /serena-data/compile-db" in project_config
    assert "ls_path: /usr/bin/clangd" in project_config


def test_serena_project_config_preserves_other_detected_languages(tmp_path) -> None:
    client = _fake_client()
    factory = MagicMock(return_value=client)
    session = SerenaSession(
        str(tmp_path), languages=["c", "go", "python"], client_factory=factory
    )

    session.start()

    args = factory.call_args.args[1]
    state_mount = next(
        str(arg) for arg in args if str(arg).endswith(":/serena-data")
    )
    project_config = Path(
        state_mount.removesuffix(":/serena-data"),
        "projects",
        "workspace",
        ".serena",
        "project.yml",
    ).read_text()
    assert "  - cpp\n" in project_config
    assert "  - go\n" in project_config
    assert "  - python\n" in project_config


def test_serena_native_tool_forwards_to_shared_client(tmp_path) -> None:
    client = _fake_client()
    session = SerenaSession(str(tmp_path), client_factory=MagicMock(return_value=client))
    tool = session.start()[0]

    result = tool.invoke({"name_path_pattern": "Queue"})

    client.call_tool.assert_called_once_with("find_symbol", {"name_path_pattern": "Queue"})
    assert result["content"][0]["text"] == "found"
    session.close()
    client.close.assert_called_once()


def test_serena_rejects_overly_broad_search_without_returning_matches(tmp_path) -> None:
    client = _fake_client()
    client.call_tool.return_value = {
        "content": [{"type": "text", "text": "x" * (SERENA_MAX_SEARCH_RESULT_CHARS + 1)}]
    }
    session = SerenaSession(str(tmp_path), client_factory=MagicMock(return_value=client))
    tool = session.start()[0]

    result = tool.invoke({"name_path_pattern": "Queue"})

    assert result["status"] == "query_too_broad"
    assert "no matches were returned" in result["error"]
    assert "x" * 100 not in str(result)
    session.close()


def test_serena_normalizes_its_own_too_long_response(tmp_path) -> None:
    client = _fake_client()
    client.call_tool.return_value = {
        "content": [
            {
                "type": "text",
                "text": "The answer is too long (354881 characters). Adjust your query.",
            }
        ]
    }
    session = SerenaSession(str(tmp_path), client_factory=MagicMock(return_value=client))
    tool = session.start()[0]

    result = tool.invoke({"name_path_pattern": "modInverse"})

    assert result["status"] == "query_too_broad"
    assert result["result_chars"] == 354881
    session.close()


def test_serena_start_failure_closes_process(tmp_path) -> None:
    client = _fake_client()
    client.connect.side_effect = RuntimeError("container failed")
    session = SerenaSession(str(tmp_path), client_factory=MagicMock(return_value=client))

    with pytest.raises(RuntimeError, match="container failed"):
        session.start()

    client.close.assert_called_once()
