from typing_extensions import TypedDict

from clearwing.llm import BaseMessage


class AgentState(TypedDict):
    messages: list[BaseMessage]
    target: str | None
    open_ports: list[dict]
    services: list[dict]
    vulnerabilities: list[dict]
    exploit_results: list[dict]
    os_info: str | None
    kali_container_id: str | None
    custom_tool_names: list[str]
    session_id: str | None
    flags_found: list[dict]
    loaded_skills: list[str]
    paused: bool
    total_cost_usd: float
    total_tokens: int
    graph_data: dict
