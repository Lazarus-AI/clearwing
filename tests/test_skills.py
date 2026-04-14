"""Tests for the Skills system."""

import tempfile
from pathlib import Path

import pytest

from clearwing.core.skills.loader import SkillInfo, SkillLoader


class TestSkillInfo:
    def test_creation(self):
        info = SkillInfo(name="test", path=Path("/tmp/test.md"), description="A test skill")
        assert info.name == "test"
        assert info.description == "A test skill"


class TestSkillLoader:
    def setup_method(self):
        self.loader = SkillLoader()

    def test_list_skills_returns_builtin(self):
        skills = self.loader.list_skills()
        assert len(skills) >= 10
        names = {s.name for s in skills}
        expected = {
            "sql_injection",
            "xss",
            "ssrf",
            "idor",
            "xxe",
            "auth_bypass",
            "privesc_linux",
            "privesc_windows",
            "command_injection",
            "file_upload",
        }
        assert expected.issubset(names), f"Missing skills: {expected - names}"

    def test_list_skills_have_descriptions(self):
        skills = self.loader.list_skills()
        for skill in skills:
            assert skill.description, f"Skill '{skill.name}' has no description"
            assert len(skill.description) > 10, f"Skill '{skill.name}' description too short"

    def test_load_single_skill(self):
        content = self.loader.load("sql_injection")
        assert "SQL" in content or "sql" in content.lower()
        assert len(content) > 100

    def test_load_multiple_skills(self):
        content = self.loader.load("sql_injection", "xss")
        assert "SQL" in content or "sql" in content.lower()
        assert "XSS" in content or "xss" in content.lower()

    def test_load_nonexistent_raises(self):
        with pytest.raises(ValueError, match="not found"):
            self.loader.load("nonexistent_skill_xyz")

    def test_load_max_skills_enforced(self):
        with pytest.raises(ValueError, match="max_skills"):
            self.loader.load("a", "b", "c", "d", "e", "f", max_skills=5)

    def test_load_max_skills_boundary(self):
        # Should work with exactly max_skills
        skills = self.loader.list_skills()
        names = [s.name for s in skills[:5]]
        content = self.loader.load(*names, max_skills=5)
        assert len(content) > 0

    def test_search_by_name(self):
        results = self.loader.search("sql")
        assert len(results) >= 1
        assert any("sql" in r.name.lower() for r in results)

    def test_search_by_description(self):
        results = self.loader.search("injection")
        assert len(results) >= 1

    def test_search_case_insensitive(self):
        results_lower = self.loader.search("xss")
        results_upper = self.loader.search("XSS")
        assert len(results_lower) == len(results_upper)

    def test_search_no_results(self):
        results = self.loader.search("zzz_nonexistent_zzz")
        assert results == []


class TestSkillLoaderCustomDir:
    def test_custom_skills_loaded(self):
        tmpdir = tempfile.mkdtemp()
        custom_path = Path(tmpdir) / "custom_skill.md"
        custom_path.write_text(
            "# Custom Skill\n\nA custom test skill for testing.\n\n## Details\n\nMore info here.\n"
        )

        loader = SkillLoader()
        original_custom = loader.CUSTOM_DIR
        loader.CUSTOM_DIR = Path(tmpdir)

        try:
            skills = loader.list_skills()
            names = {s.name for s in skills}
            assert "custom_skill" in names

            content = loader.load("custom_skill")
            assert "Custom Skill" in content
        finally:
            loader.CUSTOM_DIR = original_custom


class TestSkillContent:
    """Verify built-in skill files have expected structure."""

    def setup_method(self):
        self.loader = SkillLoader()

    def test_each_skill_starts_with_heading(self):
        for skill in self.loader.list_skills():
            if not skill.path.parent.name == "vulnerabilities":
                continue
            content = skill.path.read_text()
            first_line = content.strip().split("\n")[0]
            assert first_line.startswith("#"), f"{skill.name} doesn't start with heading"

    def test_each_skill_has_minimum_length(self):
        for skill in self.loader.list_skills():
            if not skill.path.parent.name == "vulnerabilities":
                continue
            content = skill.path.read_text()
            lines = content.strip().split("\n")
            assert len(lines) >= 30, f"{skill.name} has only {len(lines)} lines (expected >= 30)"

    def test_sql_injection_has_key_content(self):
        content = self.loader.load("sql_injection")
        lower = content.lower()
        assert "union" in lower
        assert "blind" in lower

    def test_xss_has_key_content(self):
        content = self.loader.load("xss")
        lower = content.lower()
        assert "reflected" in lower or "stored" in lower

    def test_privesc_linux_has_key_content(self):
        content = self.loader.load("privesc_linux")
        lower = content.lower()
        assert "suid" in lower or "sudo" in lower
