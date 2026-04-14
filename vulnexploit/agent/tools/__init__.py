"""Agent tool registry.

Collects all built-in and optional tools into a single list via get_all_tools().
"""

from .scanner_tools import scan_ports, detect_services, scan_vulnerabilities, detect_os
from .exploit_tools import (
    exploit_vulnerability,
    enumerate_privesc,
    crack_password,
    metasploit_exploit,
    metasploit_list_sessions,
    metasploit_run_command,
)
from .kali_docker_tool import kali_setup, kali_execute, kali_install_tool, kali_cleanup
from .reporting_tools import generate_report, save_report, query_scan_history, search_cves
from .utility_tools import validate_target, calculate_severity
from .dynamic_tool_creator import create_custom_tool, list_custom_tools, get_custom_tools
from .memory_tools import recall_target_history, store_knowledge, search_knowledge
from .skill_tools import load_skills
from .knowledge_tools import query_knowledge_graph
from .mcp_tools import get_mcp_tools
from .exploit_search import get_exploit_search_tools
from .pivot_tools import get_pivot_tools
from .remediation_tools import get_remediation_tools
from .wargame_tools import get_wargame_tools
from .payload_tools import get_payload_tools
from .ot_tools import get_ot_tools
from .sourcehunt_tools import get_sourcehunt_tools


# --- Optional tool imports (graceful fallback) ---

def _get_browser_tools() -> list:
    try:
        from .browser_tools import get_browser_tools
        return get_browser_tools()
    except ImportError:
        return []


def _get_proxy_tools() -> list:
    try:
        from .proxy_tools import get_proxy_tools
        return get_proxy_tools()
    except ImportError:
        return []


def _get_analysis_tools() -> list:
    try:
        from .analysis_tools import analyze_source, clone_and_analyze, trace_taint_flows
        return [analyze_source, clone_and_analyze, trace_taint_flows]
    except ImportError:
        return []


def get_all_tools() -> list:
    """Return all built-in agent tools."""
    tools = [
        # Scanners
        scan_ports, detect_services, scan_vulnerabilities, detect_os,
        # Exploiters
        exploit_vulnerability, enumerate_privesc, crack_password,
        metasploit_exploit, metasploit_list_sessions, metasploit_run_command,
        # Kali Docker
        kali_setup, kali_execute, kali_install_tool, kali_cleanup,
        # Reporting
        generate_report, save_report, query_scan_history, search_cves,
        # Utilities
        validate_target, calculate_severity,
        # Dynamic tool management
        create_custom_tool, list_custom_tools,
        # Memory & knowledge
        recall_target_history, store_knowledge, search_knowledge,
        load_skills, query_knowledge_graph,
    ]

    # Optional tools
    tools.extend(_get_browser_tools())
    tools.extend(_get_proxy_tools())
    tools.extend(_get_analysis_tools())
    tools.extend(get_mcp_tools())
    tools.extend(get_exploit_search_tools())
    tools.extend(get_pivot_tools())
    tools.extend(get_remediation_tools())
    tools.extend(get_wargame_tools())
    tools.extend(get_payload_tools())
    tools.extend(get_ot_tools())
    tools.extend(get_sourcehunt_tools())

    return tools
