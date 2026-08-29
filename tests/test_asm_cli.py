"""Tests for the `clearwing asm` CLI command (parse + dispatch)."""

from __future__ import annotations

import argparse
import types

import pytest

import clearwing.asm.assets as assets_mod
import clearwing.asm.discovery as discovery_mod
import clearwing.ui.commands.asm as asm_cmd
from clearwing.asm.assets import Asset
from clearwing.ui.commands import ALL_COMMANDS


@pytest.fixture
def parser():
    top = argparse.ArgumentParser()
    sub = top.add_subparsers(dest="command")
    asm_cmd.add_parser(sub)
    return top


@pytest.fixture
def cli(capsys):
    class _Console:
        def print(self, *a, **k):
            print(*a)

    class _Config:
        def get(self, *keys):
            return {} if keys == ("asm",) else None

    return types.SimpleNamespace(console=_Console(), config=_Config())


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    # point every on-disk store at the tmp dir and skip the knowledge graph
    monkeypatch.setattr(assets_mod, "_default_db_path", lambda: tmp_path / "assets.db")
    monkeypatch.setattr("clearwing.core.config.default_results_dir", lambda s: str(tmp_path / "results" / s))
    monkeypatch.setattr(asm_cmd, "_load_kg", lambda: None)
    monkeypatch.setattr(
        discovery_mod,
        "run_discovery",
        lambda scope, opts: types.SimpleNamespace(
            assets=[Asset(scope.name, "domain", "example.com"), Asset(scope.name, "subdomain", "api.example.com")]
        ),
    )


def test_asm_registered_as_command():
    assert asm_cmd in ALL_COMMANDS


def test_scan_records_and_reports(parser, cli, capsys):
    args = parser.parse_args(["asm", "scan", "example.com", "--mode", "recon", "--no-scan"])
    asm_cmd.handle(cli, args)
    out = capsys.readouterr().out
    assert "2 new assets" in out
    assert "Report (json)" in out and "Report (markdown)" in out

    # a second scan finds nothing new (delta)
    asm_cmd.handle(cli, parser.parse_args(["asm", "scan", "example.com", "--no-scan"]))
    assert "0 new assets" in capsys.readouterr().out


def test_list_scopes_then_assets(parser, cli, capsys):
    asm_cmd.handle(cli, parser.parse_args(["asm", "scan", "example.com", "--no-scan"]))
    capsys.readouterr()
    asm_cmd.handle(cli, parser.parse_args(["asm", "list"]))
    assert "example_com" in capsys.readouterr().out
    asm_cmd.handle(cli, parser.parse_args(["asm", "list", "example_com"]))
    out = capsys.readouterr().out
    assert "subdomain" in out and "api.example.com" in out


def test_bad_target_exits(parser, cli):
    args = parser.parse_args(["asm", "scan", "not a domain"])
    with pytest.raises(SystemExit):
        asm_cmd.handle(cli, args)


def test_no_action_prints_help(parser, cli, capsys):
    args = parser.parse_args(["asm"])
    asm_cmd.handle(cli, args)  # should print help, not crash
