"""Knowledge graph query tools."""

from langchain_core.tools import tool


@tool
def query_knowledge_graph(query: str) -> str:
    """Query the knowledge graph for entity relationships.

    Supports queries like:
    - "stats" -- overview of all entities
    - "all targets" -- list all targets
    - "ports for 10.0.0.1" -- ports connected to a target
    - "services on 10.0.0.1:80/tcp" -- services on a port
    - "vulnerabilities for apache" -- CVEs affecting a service

    Args:
        query: Natural language query string.

    Returns:
        Formatted query results.
    """
    try:
        from clearwing.data.knowledge import KnowledgeGraph

        kg = KnowledgeGraph(persist_path="~/.clearwing/knowledge_graph.json")
        return kg.query(query)
    except Exception as e:
        return f"Error querying knowledge graph: {e}"


def get_knowledge_tools() -> list:
    return [query_knowledge_graph]
