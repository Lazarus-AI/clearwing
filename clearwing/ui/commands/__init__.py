"""CLI subcommand modules."""

from . import (
    ci,
    config,
    graph,
    history,
    interactive,
    mcp,
    operate,
    parallel,
    report,
    scan,
    sessions,
    sourcehunt,
    webui,
)

ALL_COMMANDS = [
    scan,
    report,
    history,
    config,
    interactive,
    graph,
    sessions,
    ci,
    parallel,
    mcp,
    operate,
    webui,
    sourcehunt,
]
