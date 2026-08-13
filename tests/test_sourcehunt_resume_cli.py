from __future__ import annotations

import pytest

from clearwing.ui.cli import CLI
from clearwing.ui.commands.sourcehunt import _parse_resume_options


def test_resume_makes_repository_optional():
    args = CLI()._create_parser().parse_args(["sourcehunt", "--resume", "sh-12345678"])
    assert args.repo is None
    assert args.resume == "sh-12345678"


def test_resume_parser_accepts_only_runtime_provider_options(tmp_path):
    options = _parse_resume_options(
        [
            "sourcehunt",
            "--resume",
            "sh-12345678",
            "--output-dir",
            str(tmp_path),
            "--model",
            "replacement",
            "--api-key",
            "fresh-secret",
        ],
        default_output_dir="unused",
    )

    assert options.session_id == "sh-12345678"
    assert options.output_dir == str(tmp_path)
    assert options.model_override == "replacement"


def test_resume_parser_rejects_behavior_override(tmp_path):
    with pytest.raises(SystemExit):
        _parse_resume_options(
            [
                "sourcehunt",
                "--resume",
                "sh-12345678",
                "--output-dir",
                str(tmp_path),
                "--no-verify",
            ],
            default_output_dir="unused",
        )
