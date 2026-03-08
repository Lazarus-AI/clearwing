# VulnExploit

A comprehensive, modular vulnerability scanner and exploiter with an AI-powered interactive agent. Designed for authorized security testing and vulnerability assessments.

## Features

- **Port Scanning**: SYN and Connect scans with configurable threading
- **Service Detection**: Banner grabbing and version fingerprinting
- **OS Detection**: TTL-based and active TCP fingerprinting
- **Vulnerability Scanning**: Local CVE database + NVD API integration
- **Exploitation**: RCE, privilege escalation, and password cracking modules
- **Metasploit Integration**: Bridge to Metasploit RPC API
- **Reporting**: Text, JSON, HTML, and Markdown report formats
- **Database**: SQLite storage for scan history and results
- **Interactive AI Agent**: LangGraph-powered ReAct loop with Claude for autonomous pentest workflows
- **Kali Docker Integration**: Spin up Kali Linux containers for specialized security tools
- **Runtime Tool Creation**: Create custom tools on the fly during interactive sessions

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnexploit.git
cd vulnexploit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # or: source venv/bin/activate.fish

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Requirements

- Python 3.10+
- Docker (optional, for Kali container features)
- `ANTHROPIC_API_KEY` environment variable (for interactive agent)

## Quick Start

```bash
# Basic scan
python vulnexploit.py scan 192.168.1.1

# Scan specific ports
python vulnexploit.py scan 192.168.1.1 -p 22,80,443

# Scan with exploitation
python vulnexploit.py scan 192.168.1.1 -e

# Generate HTML report
python vulnexploit.py scan 192.168.1.1 -o report.html -f html

# Start interactive AI agent
python vulnexploit.py interactive --target 192.168.1.1

# View scan history
python vulnexploit.py history
```

## Commands

### `scan` -- Run a scan

```
python vulnexploit.py scan <target> [options]

Options:
  -p, --ports PORTS       Ports to scan (e.g., 22,80,443 or 1-1024)
  -t, --threads THREADS   Number of concurrent threads (default: 100)
  -s, --stealth           Stealth mode
  -e, --exploit           Attempt exploitation
  -o, --output FILE       Output file for report
  -f, --format FORMAT     Report format: text, json, html, markdown
  -v, --verbose           Verbose output
```

### `interactive` -- AI agent session

```
python vulnexploit.py interactive [options]

Options:
  --model MODEL   LLM model name (default: claude-sonnet-4-6)
  --target TARGET Initial target IP address
```

The interactive agent provides a conversational interface where you can direct pentest activities in natural language. The agent follows a ReAct (Reason + Act) loop:

1. You describe what you want to do
2. The agent reasons about which tools to use
3. Tools execute (exploits require your approval)
4. Results feed back into the conversation

**Example session:**

```
You: scan 10.0.0.5 for open ports
Agent: [calls scan_ports] Found 3 open ports: 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS)

You: detect what services are running
Agent: [calls detect_services] SSH: OpenSSH 8.2, HTTP: Apache 2.4.41, HTTPS: Apache 2.4.41

You: check for vulnerabilities
Agent: [calls scan_vulnerabilities] Found 2 vulnerabilities: CVE-2017-9788 (CVSS 7.5), ...

You: set up a kali container and run nmap
Agent: [calls kali_setup] Started Kali container abc123
APPROVAL REQUIRED: Approve running in Kali container: nmap -sV 10.0.0.5 [y/n]
```

Type `quit` or `exit` to end the session. Active Kali containers are cleaned up automatically.

### `report` -- Generate report from database

```
python vulnexploit.py report <target> [-o FILE] [-f FORMAT]
```

### `history` -- View scan history

```
python vulnexploit.py history [target]
```

### `config` -- Show or edit configuration

```
python vulnexploit.py config [--set KEY VALUE] [--save FILE]
```

## Architecture

```
vulnexploit/
├── core/                    # Core engine and utilities
│   ├── engine.py            # Linear workflow orchestrator
│   ├── config.py            # YAML configuration management
│   ├── module_loader.py     # Dynamic module loading
│   └── logger.py            # Logging setup
├── scanners/                # Scanning modules
│   ├── port_scanner.py      # SYN/Connect port scanning
│   ├── service_scanner.py   # Banner grabbing, version detection
│   ├── vulnerability_scanner.py  # CVE lookup (local DB + NVD API)
│   └── os_scanner.py        # OS fingerprinting via TTL/TCP
├── exploiters/              # Exploitation modules
│   ├── rce_exploits.py      # Remote code execution exploits
│   ├── privilege_escalation.py  # Linux/Windows privesc checks
│   ├── password_crackers.py # SSH, FTP, SMB, HTTP brute force
│   └── metasploit_bridge.py # Metasploit RPC API bridge
├── agent/                   # AI agent (LangGraph)
│   ├── state.py             # Agent state schema (TypedDict)
│   ├── graph.py             # ReAct loop graph construction
│   ├── prompts.py           # System prompt with dynamic context
│   ├── tools/               # @tool wrappers for all modules
│   │   ├── scanner_tools.py
│   │   ├── exploit_tools.py
│   │   ├── kali_docker_tool.py
│   │   ├── reporting_tools.py
│   │   ├── utility_tools.py
│   │   └── dynamic_tool_creator.py
│   └── custom_tools/        # Runtime-created tools land here
├── reporting/
│   └── report_generator.py  # Text, JSON, HTML, Markdown reports
├── database/
│   └── models.py            # SQLite schema and queries
├── ui/
│   └── cli.py               # Argparse CLI with all commands
└── utils/
    └── helpers.py            # IP validation, CVSS severity, etc.
```

## Agent Tools

The interactive agent has access to 22 built-in tools:

| Category | Tools | Approval Required |
|----------|-------|-------------------|
| **Scanning** | `scan_ports`, `detect_services`, `scan_vulnerabilities`, `detect_os` | No |
| **Exploitation** | `exploit_vulnerability`, `enumerate_privesc`, `crack_password` | Yes |
| **Metasploit** | `metasploit_exploit`, `metasploit_run_command`, `metasploit_list_sessions` | Yes (except list) |
| **Kali Docker** | `kali_setup`, `kali_execute`, `kali_install_tool`, `kali_cleanup` | Yes (execute only) |
| **Reporting** | `generate_report`, `save_report`, `query_scan_history`, `search_cves` | No |
| **Utility** | `validate_target`, `calculate_severity` | No |
| **Meta** | `create_custom_tool`, `list_custom_tools` | No |

Tools marked with "Approval Required" will pause execution and prompt you for confirmation before proceeding.

### Dynamic Tool Creation

The agent can create new tools at runtime. For example, you can ask:

> "Create a tool that checks if a URL returns a 200 status code"

The agent will generate a `@tool`-decorated Python function, save it to `vulnexploit/agent/custom_tools/`, and recompile the graph so the new tool is immediately available in the same session.

## API Usage

### Linear Workflow (CoreEngine)

```python
import asyncio
from vulnexploit.core import CoreEngine, Config, ScanConfig

config = Config()
engine = CoreEngine(config)

scan_config = ScanConfig(
    target='192.168.1.1',
    ports=[22, 80, 443],
    exploit=False
)

result = asyncio.run(engine.scan('192.168.1.1', scan_config))
print(engine.get_report('text'))
```

### Agent (Programmatic)

```python
from vulnexploit.agent import create_agent, AgentState
from langchain_core.messages import HumanMessage

graph = create_agent(model_name="claude-sonnet-4-6")
config = {"configurable": {"thread_id": "my-session"}}

result = graph.invoke(
    {
        "messages": [HumanMessage(content="Scan 192.168.1.1 for open ports")],
        "target": "192.168.1.1",
        "open_ports": [],
        "services": [],
        "vulnerabilities": [],
        "exploit_results": [],
        "os_info": None,
        "kali_container_id": None,
        "custom_tool_names": [],
    },
    config,
)
```

## Configuration

Default configuration can be customized via YAML file or the `config` command:

```yaml
scanning:
  scan_timeout: 1
  max_threads: 100
exploitation:
  auto_exploit: false
  metasploit_host: 127.0.0.1
  metasploit_port: 55553
  metasploit_password: msf
reporting:
  default_format: text
database:
  path: vulnexploit.db
```

## Testing

```bash
# Unit tests (no network or Docker required)
pytest tests/test_agent.py tests/test_dynamic_tools.py -v

# Docker integration tests (requires Docker daemon)
pytest tests/test_kali_docker.py -v

# All tests
pytest tests/ -v
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing, educational purposes, and CTF competitions only. Always ensure you have explicit permission before scanning or exploiting target systems. Unauthorized access to computer systems is illegal.
