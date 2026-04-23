"""Agent tool registry — lazy aggregator.

Importing one tool subpackage should not initialize the entire scanning stack.
Sourcehunt imports `clearwing.agent.tools.hunt`, and that path must stay free
of OT/scapy side effects.
"""

from typing import Any


def get_custom_tools() -> list[Any]:
    from .ops.dynamic_tool_creator import get_custom_tools as _get_custom_tools

    return _get_custom_tools()


def _get_browser_tools() -> list[Any]:
    try:
        from .recon.browser_tools import get_browser_tools

        return get_browser_tools()
    except ImportError:
        return []


def _get_proxy_tools() -> list[Any]:
    try:
        from .recon.proxy_tools import get_proxy_tools

        return get_proxy_tools()
    except ImportError:
        return []


def _get_webcrypto_tools() -> list[Any]:
    try:
        from .recon.webcrypto_hooks import get_webcrypto_tools

        return get_webcrypto_tools()
    except ImportError:
        return []


def _get_auth_recorder_tools() -> list[Any]:
    try:
        from .recon.auth_recorder import get_auth_recorder_tools

        return get_auth_recorder_tools()
    except ImportError:
        return []


def _get_mitm_tools() -> list[Any]:
    try:
        from .recon.mitm_proxy import get_mitm_tools

        return get_mitm_tools()
    except ImportError:
        return []


def _get_crypto_tools() -> list[Any]:
    try:
        from .crypto.srp_tools import get_srp_tools

        return get_srp_tools()
    except ImportError:
        return []


def _get_timing_tools() -> list[Any]:
    try:
        from .crypto.timing_tools import get_timing_tools

        return get_timing_tools()
    except ImportError:
        return []


def _get_kdf_tools() -> list[Any]:
    try:
        from .crypto.kdf_tools import get_kdf_tools

        return get_kdf_tools()
    except ImportError:
        return []


def _get_tls_tools() -> list[Any]:
    try:
        from .scan.tls_tools import get_tls_tools

        return get_tls_tools()
    except ImportError:
        return []


def _get_analysis_tools() -> list[Any]:
    try:
        from .data.analysis_tools import analyze_source, clone_and_analyze, trace_taint_flows

        return [analyze_source, clone_and_analyze, trace_taint_flows]
    except ImportError:
        return []


def get_all_tools() -> list[Any]:
    """Return all built-in agent tools."""
    from .data.knowledge_tools import query_knowledge_graph
    from .data.memory_tools import recall_target_history, search_knowledge, store_knowledge
    from .exploit.exploit_search import get_exploit_search_tools
    from .exploit.exploit_tools import (
        crack_password,
        enumerate_privesc,
        exploit_vulnerability,
        metasploit_exploit,
        metasploit_list_sessions,
        metasploit_run_command,
    )
    from .exploit.payload_tools import get_payload_tools
    from .meta.ot_tools import get_ot_tools
    from .meta.remediation_tools import get_remediation_tools
    from .meta.reporting_tools import generate_report, query_scan_history, save_report, search_cves
    from .meta.sourcehunt_tools import get_sourcehunt_tools
    from .meta.utility_tools import calculate_severity, validate_target
    from .meta.wargame_tools import get_wargame_tools
    from .ops.dynamic_tool_creator import create_custom_tool, list_custom_tools
    from .ops.kali_docker_tool import kali_cleanup, kali_execute, kali_install_tool, kali_setup
    from .ops.mcp_tools import get_mcp_tools
    from .ops.skill_tools import load_skills
    from .recon.pivot_tools import get_pivot_tools
    from .scan.scanner_tools import detect_os, detect_services, scan_ports, scan_vulnerabilities

    tools = [
        scan_ports,
        detect_services,
        scan_vulnerabilities,
        detect_os,
        exploit_vulnerability,
        enumerate_privesc,
        crack_password,
        metasploit_exploit,
        metasploit_list_sessions,
        metasploit_run_command,
        kali_setup,
        kali_execute,
        kali_install_tool,
        kali_cleanup,
        generate_report,
        save_report,
        query_scan_history,
        search_cves,
        validate_target,
        calculate_severity,
        create_custom_tool,
        list_custom_tools,
        recall_target_history,
        store_knowledge,
        search_knowledge,
        load_skills,
        query_knowledge_graph,
    ]

    tools.extend(_get_browser_tools())
    tools.extend(_get_proxy_tools())
    tools.extend(_get_webcrypto_tools())
    tools.extend(_get_auth_recorder_tools())
    tools.extend(_get_mitm_tools())
    tools.extend(_get_crypto_tools())
    tools.extend(_get_timing_tools())
    tools.extend(_get_kdf_tools())
    tools.extend(_get_tls_tools())
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


__all__ = ["get_all_tools", "get_custom_tools"]
