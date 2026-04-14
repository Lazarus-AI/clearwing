"""Memory tools: recall history, store/search knowledge."""

from langchain_core.tools import tool


@tool
def recall_target_history(target: str) -> str:
    """Recall previous findings and interaction history for a target.

    Args:
        target: Target IP address or hostname.

    Returns:
        Formatted string of previous findings for this target.
    """
    try:
        from clearwing.data.memory import EpisodicMemory

        memory = EpisodicMemory()
        episodes = memory.recall(target, limit=30)
        if not episodes:
            return f"No previous history found for {target}."
        lines = []
        for ep in episodes:
            lines.append(f"[{ep.timestamp}] {ep.event_type}: {ep.content}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error recalling history: {e}"


@tool
def store_knowledge(category: str, content: str) -> str:
    """Store a piece of knowledge for cross-session retrieval.

    Args:
        category: Category (successful_exploits, tool_usage_patterns, target_profiles, custom_techniques).
        content: Knowledge content to store.

    Returns:
        Confirmation message.
    """
    try:
        from clearwing.data.memory import SemanticMemory

        memory = SemanticMemory()
        memory.store(category, content)
        return f"Knowledge stored in category '{category}'."
    except Exception as e:
        return f"Error storing knowledge: {e}"


@tool
def search_knowledge(query: str, category: str = None) -> str:
    """Search stored knowledge across sessions.

    Args:
        query: Search query string.
        category: Optional category filter.

    Returns:
        Formatted search results.
    """
    try:
        from clearwing.data.memory import SemanticMemory

        memory = SemanticMemory()
        results = memory.search(query, category=category, top_k=5)
        if not results:
            return "No matching knowledge found."
        lines = []
        for k in results:
            lines.append(f"[{k.category}] {k.content[:200]}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error searching knowledge: {e}"


def get_memory_tools() -> list:
    return [recall_target_history, store_knowledge, search_knowledge]
