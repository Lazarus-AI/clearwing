from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class SkillInfo:
    name: str
    path: Path
    description: str


class SkillLoader:
    """Discovers, searches, and loads vulnerability skill files."""

    BUILTIN_DIR: Path = Path(__file__).parent / "vulnerabilities"
    CRYPTO_DIR: Path = Path(__file__).parent / "crypto"
    CUSTOM_DIR: Path | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_skills(self) -> list[SkillInfo]:
        """Scan builtin and custom directories for .md skill files.

        Returns a list of ``SkillInfo`` objects with the description
        extracted from the first paragraph of each file.
        """
        skills: list[SkillInfo] = []
        if self.CUSTOM_DIR is None:
            from clearwing.core.config import clearwing_home

            self.CUSTOM_DIR = clearwing_home() / "skills" / "custom"
        for directory in (self.BUILTIN_DIR, self.CRYPTO_DIR, self.CUSTOM_DIR):
            if not directory.is_dir():
                continue
            for md_file in sorted(directory.glob("*.md")):
                description = self._extract_description(md_file)
                skills.append(
                    SkillInfo(
                        name=md_file.stem,
                        path=md_file,
                        description=description,
                    )
                )
        return skills

    def load(self, *skill_names: str, max_skills: int = 5) -> str:
        """Load and concatenate the contents of the requested skills.

        Parameters
        ----------
        *skill_names:
            One or more skill names (without the ``.md`` extension).
        max_skills:
            Upper bound on the number of skills that will be loaded.

        Returns
        -------
        str
            The concatenated markdown content of the loaded skills,
            separated by double newlines.

        Raises
        ------
        ValueError
            If a requested skill cannot be found in any known directory.
        """
        if len(skill_names) > max_skills:
            raise ValueError(f"Requested {len(skill_names)} skills but max_skills is {max_skills}")

        skill_map = {s.name: s for s in self.list_skills()}
        parts: list[str] = []

        for name in skill_names:
            info = skill_map.get(name)
            if info is None:
                available = ", ".join(sorted(skill_map.keys()))
                raise ValueError(f"Skill '{name}' not found. Available skills: {available}")
            parts.append(info.path.read_text(encoding="utf-8"))

        return "\n\n".join(parts)

    def search(self, query: str) -> list[SkillInfo]:
        """Case-insensitive substring search across skill names and descriptions."""
        query_lower = query.lower()
        return [
            skill
            for skill in self.list_skills()
            if query_lower in skill.name.lower() or query_lower in skill.description.lower()
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_description(path: Path) -> str:
        """Return the first paragraph after the heading as a description."""
        lines = path.read_text(encoding="utf-8").splitlines()
        paragraph_lines: list[str] = []
        past_heading = False

        for line in lines:
            stripped = line.strip()

            # Skip the leading heading
            if not past_heading:
                if stripped.startswith("#"):
                    past_heading = True
                continue

            # Skip blank lines immediately after the heading
            if not paragraph_lines and stripped == "":
                continue

            # Collect until the next blank line
            if stripped == "":
                break

            paragraph_lines.append(stripped)

        return " ".join(paragraph_lines) if paragraph_lines else ""
