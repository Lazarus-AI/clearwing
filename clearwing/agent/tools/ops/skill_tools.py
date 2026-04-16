"""Skill loading tools."""

from clearwing.agent.tooling import tool
from clearwing.core.skills import SkillLoader


@tool
def load_skills(skill_names: list[str]) -> str:
    """Load detailed vulnerability/technique knowledge by name.

    Args:
        skill_names: List of skill names to load (e.g. ["sql_injection", "xss"]).

    Returns:
        Combined skill content.
    """
    try:
        loader = SkillLoader()
        return loader.load(*skill_names)
    except Exception as e:
        return f"Error loading skills: {e}"


def get_skill_tools() -> list:
    return [load_skills]
