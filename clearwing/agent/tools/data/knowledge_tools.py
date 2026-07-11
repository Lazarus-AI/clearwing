"""Knowledge graph query tools."""

from clearwing.agent.tooling import tool
from clearwing.data.knowledge import KnowledgeGraph


@tool
def query_knowledge_graph(query: str) -> str:
    """Query the knowledge graph for entity relationships.

    Supports queries like:
    - "stats" -- overview of all entities
    - "all targets" -- list all targets
    - "ports for 10.0.0.1" -- ports connected to a target
    - "services on 10.0.0.1:80/tcp" -- services on a port
    - "vulnerabilities for apache" -- CVEs affecting a service
    - "all protocols" -- list all crypto protocol entities
    - "all algorithms" -- list all algorithm entities
    - "algorithms for SRP-6a" -- algorithms used by a protocol
    - "key material for target" -- key materials associated with a target
    - "key chain for key:auk:target" -- full key derivation chain
    - "certificates for target" -- TLS certificates
    - "kdf config for target" -- KDF configurations

    Args:
        query: Natural language query string.

    Returns:
        Formatted query results.
    """
    try:
        from clearwing.core.config import clearwing_home

        kg = KnowledgeGraph(persist_path=str(clearwing_home() / "knowledge_graph.json"))
        return kg.query(query)
    except Exception as e:
        return f"Error querying knowledge graph: {e}"


def get_knowledge_tools() -> list:
    return [query_knowledge_graph]
