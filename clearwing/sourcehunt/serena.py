"""Run-scoped Serena semantic-navigation integration for sourcehunt."""

from __future__ import annotations

import json
import logging
import re
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from clearwing.llm.native import NativeToolSpec
from clearwing.mcp.client import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_SERENA_IMAGE = "ghcr.io/oraios/serena:latest"
SERENA_PROJECT_PATH = "/workspace"
SERENA_DATA_PATH = "/serena-data"
SERENA_MAX_SEARCH_RESULT_CHARS = 32_000
SERENA_SEARCH_TOOLS = {"find_referencing_symbols", "find_symbol", "search_for_pattern"}

# Sourcehunt is an analysis workflow. Do not expose Serena's editing, shell,
# memory-writing, or project-switching capabilities to hunters.
READ_ONLY_SERENA_TOOLS = {
    "find_file",
    "find_referencing_symbols",
    "find_symbol",
    "get_symbols_overview",
    "list_dir",
    "read_file",
    "search_for_pattern",
}


class SerenaSession:
    """One Serena container shared by every hunter in a sourcehunt run."""

    def __init__(
        self,
        repo_path: str,
        *,
        image: str = DEFAULT_SERENA_IMAGE,
        languages: Iterable[str] | None = None,
        client_factory: type[MCPClient] = MCPClient,
    ) -> None:
        self.repo_path = str(Path(repo_path).resolve())
        self.image = image
        self.languages = self._normalize_languages(languages)
        self._client_factory = client_factory
        self._client: MCPClient | None = None
        self._tools: list[NativeToolSpec] = []
        self._project_state: tempfile.TemporaryDirectory[str] | None = None

    @property
    def tools(self) -> list[NativeToolSpec]:
        return list(self._tools)

    def start(self) -> list[NativeToolSpec]:
        """Start Serena and return read-only tools adapted for native hunters."""
        if self._client is not None:
            return self.tools
        self._project_state = tempfile.TemporaryDirectory(prefix="clearwing-serena-")
        Path(self._project_state.name, "serena_config.yml").write_text(
            "project_serena_folder_location: "
            '"/serena-data/projects/$projectFolderName/.serena"\n'
            "trusted_project_path_patterns:\n"
            '  - "/workspace"\n'
            "ignored_paths:\n"
            '  - "npm/**"\n'
            '  - "dist/**"\n'
            '  - "build/**"\n'
            '  - "**/*min.js"\n'
            "projects: []\n"
            "web_dashboard: false\n"
            "web_dashboard_open_on_launch: false\n"
        )
        logger.info(
            "Starting Serena; workspace mounted read-only: %s -> %s "
            "(language-server indexing may take a few minutes)",
            self.repo_path,
            SERENA_PROJECT_PATH,
        )
        args = [
            "run",
            "--rm",
            "-i",
            "-e",
            f"SERENA_HOME={SERENA_DATA_PATH}",
            "-e",
            "SERENA_USAGE_REPORTING=false",
            "-v",
            f"{self.repo_path}:{SERENA_PROJECT_PATH}:ro",
            "-v",
            f"{self._project_state.name}:{SERENA_DATA_PATH}",
        ]
        server_args = [
            "serena",
            "start-mcp-server",
            "--transport",
            "stdio",
            "--context",
            "ide",
            "--project",
            SERENA_PROJECT_PATH,
            "--enable-web-dashboard",
            "false",
            "--open-web-dashboard",
            "false",
            "--enable-gui-log-window",
            "false",
            "--log-level",
            "WARNING",
        ]
        packages = self._required_debian_packages()
        if packages:
            package_list = " ".join(packages)
            logger.info(
                "Serena languages=%s; ensuring container packages are installed: %s",
                ",".join(sorted(self.languages)),
                package_list,
            )
            args.extend(["--entrypoint", "/bin/bash"])
            args.extend([
                self.image,
                "-lc",
                "export DEBIAN_FRONTEND=noninteractive; "
                "apt-get update -qq && apt-get install -y -qq --no-install-recommends "
                f"{package_list}; "
                "source /workspaces/serena/.venv/bin/activate; "
                "exec serena start-mcp-server --transport stdio --context ide "
                "--project /workspace --enable-web-dashboard false "
                "--open-web-dashboard false --enable-gui-log-window false "
                "--log-level WARNING",
            ])
        else:
            args.extend([
                self.image,
                *server_args,
            ])
        client = self._client_factory(
            "docker",
            args,
            initialize_timeout=300.0,
            request_timeout=120.0,
        )
        try:
            client.connect()
            advertised = client.list_tools()
            self._client = client
            self._tools = [
                self._adapt_tool(tool)
                for tool in advertised
                if str(tool.get("name") or "") in READ_ONLY_SERENA_TOOLS
            ]
            logger.info(
                "Serena ready for %s: %d read-only tools",
                self.repo_path,
                len(self._tools),
            )
            return self.tools
        except Exception:
            client.close()
            self._project_state.cleanup()
            self._project_state = None
            raise

    def _normalize_languages(self, languages: Iterable[str] | None) -> set[str]:
        aliases = {"c++": "cpp", "py": "python", "golang": "go"}
        if languages is not None:
            return {
                aliases.get(str(language).lower(), str(language).lower())
                for language in languages
                if str(language).strip()
            }
        suffixes = {
            ".c": "c",
            ".cc": "cpp",
            ".cpp": "cpp",
            ".cxx": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".py": "python",
        }
        detected: set[str] = set()
        for path in Path(self.repo_path).rglob("*"):
            if path.is_file() and path.suffix.lower() in suffixes:
                detected.add(suffixes[path.suffix.lower()])
        return detected

    def _required_debian_packages(self) -> list[str]:
        packages: list[str] = []
        if {"c", "cpp"} & self.languages:
            packages.append("clangd")
        if "go" in self.languages:
            packages.extend(["golang-go", "gopls"])
        return packages

    def _adapt_tool(self, tool: dict[str, Any]) -> NativeToolSpec:
        remote_name = str(tool["name"])
        schema = tool.get("inputSchema") or {"type": "object", "properties": {}}
        description = str(tool.get("description") or f"Serena {remote_name}")

        def invoke(**arguments: Any) -> Any:
            if self._client is None:
                raise RuntimeError("Serena session is closed")
            result = self._client.call_tool(remote_name, arguments)
            if remote_name in SERENA_SEARCH_TOOLS:
                serialized_result = json.dumps(result, ensure_ascii=False, default=str)
                result_chars = len(serialized_result)
                serena_rejected = "answer is too long" in serialized_result.lower()
                reported_size = re.search(r"\(([\d,]+) characters\)", serialized_result)
                if reported_size:
                    result_chars = int(reported_size.group(1).replace(",", ""))
                if result_chars > SERENA_MAX_SEARCH_RESULT_CHARS or serena_rejected:
                    supplied_path = arguments.get("relative_path") or arguments.get(
                        "paths_include_glob"
                    )
                    path_advice = (
                        "Narrow relative_path/paths_include_glob to a smaller source directory "
                        "or file. "
                        if not supplied_path
                        else "Narrow the supplied path or split the query by symbol/pattern. "
                    )
                    return {
                        "status": "query_too_broad",
                        "error": (
                            f"Serena {remote_name} produced {result_chars:,} characters, "
                            f"above the {SERENA_MAX_SEARCH_RESULT_CHARS:,}-character safety "
                            "limit; no matches were returned to model context. "
                            f"{path_advice}Exclude minified/generated files and prefer an "
                            "exact symbol or definition pattern."
                        ),
                        "result_chars": result_chars,
                        "result_limit_chars": SERENA_MAX_SEARCH_RESULT_CHARS,
                        "retry": {
                            "relative_path": "specific/source/path",
                            "paths_include_glob": "src/**/*.{c,cc,cpp,go,rs,py,js}",
                            "pattern": "one exact symbol or definition pattern",
                        },
                    }
            return result

        return NativeToolSpec(
            name=f"serena_{remote_name}",
            description=(
                "Serena semantic navigation for the current repository. " + description
            ),
            schema=schema,
            handler=invoke,
        )

    def close(self) -> None:
        client, self._client = self._client, None
        self._tools = []
        if client is not None:
            client.close()
        if self._project_state is not None:
            self._project_state.cleanup()
            self._project_state = None
