# Mission: Tactical Edge (Disconnected OT/ICS Operations)
## Objective
Execute an air-gapped, zero-comms offensive operation to compromise a hostile ICS/SCADA environment, deploying evasive payloads and establishing a resilient asynchronous C2 mesh.

## Rules of Engagement (ROE)
1. **Disconnected Execution**: Assume zero internet connectivity. Rely exclusively on the local LLM inference engine and internal tools.
2. **Kinetic Target Acquisition**: Prioritize the identification of OT infrastructure (Modbus, S7, DNP3) over standard IT targets.
3. **Ghost in the Wire (OPSEC)**: All python payloads must be passed through the `obfuscate_payload` tool to evade next-gen EDR.
4. **Deconfliction Mandate**: Every deployed script MUST be cryptographically signed using `cryptographically_sign_payload` to prevent cyber fratricide.
5. **Asynchronous Persistence**: Do not use noisy, continuous SSH tunnels. Deploy sleeping beacons using `generate_c2_beacon` configured for high jitter.

## Tactical Phases
### Phase 1: OT Reconnaissance
- Utilize `scan_ot_infrastructure` to identify physical controllers and SCADA systems.
- Map the OT network topology into the Attack Graph.

### Phase 2: Weaponization & Obfuscation
- Adapt exploits for the discovered OT systems.
- Process the final exploit script through the polymorphic obfuscator.
- Sign the payload with the cryptographic watermarker using the operation ID `OP-TACTICAL-EDGE`.

### Phase 3: Stealth Infiltration
- Execute the signed, obfuscated payload.
- Avoid spawning interactive shells.

### Phase 4: Mesh C2 Deployment
- Generate a sleeper beacon with at least a 60-second sleep and 20% jitter.
- Drop and execute the beacon on the compromised controller to establish resilient, asynchronous command and control.

### Phase 5: Exfiltration & AAR
- Confirm beacon check-ins.
- Generate a Markdown summary detailing the OT assets compromised, the obfuscation keys used, and the cryptographic signatures applied.
