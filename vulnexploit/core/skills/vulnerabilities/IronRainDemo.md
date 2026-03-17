# Mission: Iron Rain
## Objective
Execute a high-intensity, autonomous cyber operation to penetrate an adversary's Command & Control (C2) infrastructure and establish a persistent pivot into the internal secure enclave.

## Rules of Engagement (ROE)
1. **Target Identification**: Rapid multi-vector reconnaissance.
2. **Precision Weaponization**: Identify CVEs, adapt PoCs, and verify payloads in the Kali sandbox.
3. **Human-in-the-Loop**: Pause and request "Commander's Authorization" (y/n) before any kinetic exploitation.
4. **Beachhead Operations**: Upon successful exploit, immediately stabilize the shell and deploy a SOCKS5 pivot.
5. **Operational Silence**: Minimize log footprints by using stealth flags and targeted scanning.

## Tactical Phases
### Phase 1: Recon & Acquisition
- Use `scan_ports` with SYN flags across the full port range.
- Run `detect_services` to fingerprint all exposed services and versions.
- Use `detect_os` for OS fingerprinting.
- Query `search_cves` for each discovered service version.
- Update the **Attack Graph** via `query_knowledge_graph` to visualize the adversary's perimeter.
- Load relevant skills with `load_skills` based on discovered services (e.g., sql_injection for web apps, auth_bypass for login portals).

### Phase 2: Weaponization
- Search Exploit-DB and NVD for identified service versions.
- Use `kali_setup` to prepare the Kali container.
- Download PoC code into the Kali container with `kali_execute`.
- Adapt payloads: adjust offsets, fix hardcoded IPs, and verify shellcode compatibility.
- Explain clearly: "Commander, I am adapting the payload offsets and fixing hardcoded IPs for this specific mission."
- Test payloads in the sandbox before live deployment.

### Phase 3: Infiltration
- Request Commander's Authorization before executing any exploit.
- Execute adapted exploit via `exploit_vulnerability` or `kali_execute`.
- Establish initial access and stabilize the shell.
- Capture credentials, flags, and session tokens.
- **Narrative**: "Beachhead established. Host compromised. Transitioning to Lateral Movement."
- Record all findings with `store_knowledge` for cross-session persistence.

### Phase 4: Enclave Penetration
- Deploy SOCKS5 pivot through the compromised host.
- Scan internal network (e.g., `10.0.x.x`) through the tunnel.
- Identify "High-Value Assets" (HVA) such as Domain Controllers or Database Servers.
- Enumerate internal services and check for lateral movement paths.
- Use `enumerate_privesc` to find privilege escalation vectors.
- Attempt credential reuse across discovered internal services.

### Phase 5: Mission After Action Report (AAR)
- Generate a comprehensive report with `generate_report` including:
  - All captured flags and compromised credentials.
  - Timeline of actions taken in each phase.
  - Final Attack Graph state from `query_knowledge_graph`.
  - Severity-rated findings with CVSS scores.
  - Remediation recommendations for each vulnerability exploited.
- Save the report with `save_report` in the preferred format.
