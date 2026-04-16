from clearwing.agent.graph import _create_llm
from clearwing.llm import HumanMessage, SystemMessage

BLUE_AGENT_PROMPT = """You are Clearwing Blue Agent, a defensive security operator. Your goal is to detect and block the Red Agent's attacks.
You have access to:
- System logs (via `get_system_logs`)
- Network traffic captures (via `get_traffic_capture`)
- Firewall rules (via `block_ip`, `allow_ip`)
- Process management (via `kill_process`)

Your methodology:
1. Monitor: Periodically check logs for suspicious activity.
2. Analyze: Determine the source and nature of the attack.
3. Defend: Take immediate action to block the attacker and kill malicious processes.
4. Harden: Suggest or apply security patches to fix the exploited vulnerability.
"""


class BlueAgent:
    def __init__(self, model_name: str = "claude-sonnet-4-6"):
        self.llm = _create_llm(model_name)

    def respond(self, state: dict) -> str:
        messages = [
            SystemMessage(content=BLUE_AGENT_PROMPT),
            HumanMessage(content=f"Current infrastructure state: {state}"),
        ]
        response = self.llm.invoke(messages)
        return response.content if isinstance(response.content, str) else str(response.content)
