import socket
import asyncio
from typing import List, Dict, Any

OT_PORTS = {
    502: 'Modbus TCP',
    102: 'Siemens S7',
    20000: 'DNP3',
    44818: 'IEC 61850',
    47808: 'EtherNet/IP (CIP)',
    1911: 'Foxboro DNP3',
}

class OTScanner:
    """Kinetic/Operational Technology (OT) & ICS Scanner."""
    
    def __init__(self):
        self.timeout = 2

    async def scan_ot(self, target: str, threads: int = 10) -> List[Dict[str, Any]]:
        """Scan a target for common Industrial Control Systems (ICS) / OT ports."""
        open_ports = []
        semaphore = asyncio.Semaphore(threads)

        async def check_port(port: int, service_name: str) -> None:
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    open_ports.append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service_name,
                        'is_ot': True
                    })
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

        tasks = [check_port(port, name) for port, name in OT_PORTS.items()]
        await asyncio.gather(*tasks)
        
        return sorted(open_ports, key=lambda x: x['port'])
