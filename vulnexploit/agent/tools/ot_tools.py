from typing import List, Dict, Any
from langchain_core.tools import tool
from ...scanning.ot_scanner import OTScanner

@tool
async def scan_ot_infrastructure(target: str) -> List[Dict[str, Any]]:
    """Kinetic/OT Operations: Scan a target specifically for Industrial Control Systems (ICS) and OT protocols.
    
    This targets specialized ports used by Modbus, DNP3, Siemens S7, and others to identify
    physical infrastructure targets (power, water, manufacturing).
    
    Args:
        target: Target IP address or hostname.
        
    Returns:
        List of open OT ports and their associated services.
    """
    scanner = OTScanner()
    results = await scanner.scan_ot(target)
    return results

def get_ot_tools() -> List:
    return [scan_ot_infrastructure]
