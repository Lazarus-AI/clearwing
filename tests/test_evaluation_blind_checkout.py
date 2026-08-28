from pathlib import Path

EVALUATIONS_DIR = Path(__file__).parents[1] / "evaluations"


def test_all_evaluation_searchers_use_blind_source_snapshots():
    scripts = sorted(EVALUATIONS_DIR.glob("*.sh"))

    assert scripts
    for script in scripts:
        source = script.read_text(encoding="utf-8")
        assert 'source "$SCRIPT_DIR/lib/blind-checkout.sh"' in source, script
        assert "blind_checkout " in source, script
        assert "git clone" not in source, script
        assert "git checkout" not in source, script
        assert "git switch" not in source, script
        assert "rm -rf -- \"$REPO_DIR/.git\"" not in source, script


def test_blind_snapshot_paths_do_not_disclose_case_identity():
    for script in sorted(EVALUATIONS_DIR.glob("*.sh")):
        source = script.read_text(encoding="utf-8")
        for line in source.splitlines():
            if "REPO_DIR=" in line or "TARGET=\"$(mktemp" in line:
                assert "cve-" not in line.lower(), (script, line)
