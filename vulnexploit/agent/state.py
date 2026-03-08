from typing import Annotated, Optional
from typing_extensions import TypedDict
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    target: Optional[str]
    open_ports: list[dict]
    services: list[dict]
    vulnerabilities: list[dict]
    exploit_results: list[dict]
    os_info: Optional[str]
    kali_container_id: Optional[str]
    custom_tool_names: list[str]
    session_id: Optional[str]
    flags_found: list[dict]
    loaded_skills: list[str]
    paused: bool
    total_cost_usd: float
    total_tokens: int
    graph_data: dict
