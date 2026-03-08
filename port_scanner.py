import socket
import concurrent.futures
import struct
import random
from scapy.all import sr1, IP, TCP

# List of common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    2222, 2323, 2525, 3333, 4444, 5555, 6666, 7777, 8888, 9999, 10000, 12345, 20000, 30000, 40000, 50000
]

# Known service names
SERVICE_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCbind',
    135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Proxy', 2222: 'SSH-alt',
    2323: 'Telnet-alt', 2525: 'SMTP-alt', 3333: 'X11', 4444: 'Metasploit', 5555: 'FreeSWITCH',
    6666: 'IRC', 7777: 'IRC', 8888: 'Sun-Webserver', 9999: 'Sun-Webserver', 10000: 'Webmin',
    12345: 'NetBus', 20000: 'Dillo', 30000: 'Unknown', 40000: 'Unknown', 50000: 'Unknown'
}

# Known vulnerabilities and exploits
VULNERABILITIES = {
    'FTP': ['CVE-2015-3306', 'CVE-2012-1823', 'CVE-2010-4221', 'CVE-2010-4220', 'CVE-2010-4219'],
    'SSH': ['CVE-2016-0777', 'CVE-2018-15473', 'CVE-2019-14856', 'CVE-2019-14855', 'CVE-2019-14854'],
    'Telnet': ['CVE-2013-4349', 'CVE-2015-5180', 'CVE-2012-2125', 'CVE-2012-2124', 'CVE-2012-2123'],
    'SMTP': ['CVE-2010-4344', 'CVE-2011-0411', 'CVE-2011-0410', 'CVE-2011-0409', 'CVE-2011-0408'],
    'DNS': ['CVE-2012-5098', 'CVE-2015-5477', 'CVE-2015-5476', 'CVE-2015-5475', 'CVE-2015-5474'],
    'HTTP': ['CVE-2014-0160', 'CVE-2017-5638', 'CVE-2017-9788', 'CVE-2017-9798', 'CVE-2017-9799'],
    'POP3': ['CVE-2012-1182', 'CVE-2015-3223', 'CVE-2015-3222', 'CVE-2015-3221', 'CVE-2015-3220'],
    'RPCbind': ['CVE-2015-7283', 'CVE-2016-5195', 'CVE-2016-5194', 'CVE-2016-5193', 'CVE-2016-5192'],
    'MSRPC': ['CVE-2017-0144', 'CVE-2017-0145', 'CVE-2017-0146', 'CVE-2017-0147', 'CVE-2017-0148'],
    'NetBIOS': ['CVE-2017-0143', 'CVE-2017-0146', 'CVE-2017-0147', 'CVE-2017-0148', 'CVE-2017-0149'],
    'IMAP': ['CVE-2012-2125', 'CVE-2015-3223', 'CVE-2015-3222', 'CVE-2015-3221', 'CVE-2015-3220'],
    'HTTPS': ['CVE-2014-0160', 'CVE-2016-2107', 'CVE-2016-2108', 'CVE-2016-2109', 'CVE-2016-2110'],
    'SMB': ['CVE-2017-0144', 'CVE-2017-0145', 'CVE-2017-0146', 'CVE-2017-0147', 'CVE-2017-0148'],
    'IMAPS': ['CVE-2012-2125', 'CVE-2015-3223', 'CVE-2015-3222', 'CVE-2015-3221', 'CVE-2015-3220'],
    'POP3S': ['CVE-2012-1182', 'CVE-2015-3223', 'CVE-2015-3222', 'CVE-2015-3221', 'CVE-2015-3220'],
    'PPTP': ['CVE-2012-2125', 'CVE-2015-3223', 'CVE-2015-3222', 'CVE-2015-3221', 'CVE-2015-3220'],
    'MySQL': ['CVE-2012-2122', 'CVE-2016-6662', 'CVE-2016-6663', 'CVE-2016-6664', 'CVE-2016-6665'],
    'RDP': ['CVE-2019-0708', 'CVE-2019-1181', 'CVE-2019-1182', 'CVE-2019-1183', 'CVE-2019-1184'],
    'VNC': ['CVE-2015-5195', 'CVE-2016-5195', 'CVE-2016-5196', 'CVE-2016-5197', 'CVE-2016-5198'],
    'HTTP-Proxy': ['CVE-2014-0160', 'CVE-2017-5638', 'CVE-2017-9788', 'CVE-2017-9798', 'CVE-2017-9799'],
    'SSH-alt': ['CVE-2016-0777', 'CVE-2018-15473', 'CVE-2019-14856', 'CVE-2019-14855', 'CVE-2019-14854'],
    'Telnet-alt': ['CVE-2013-4349', 'CVE-2015-5180', 'CVE-2012-2125', 'CVE-2012-2124', 'CVE-2012-2123'],
    'SMTP-alt': ['CVE-2010-4344', 'CVE-2011-0411', 'CVE-2011-0410', 'CVE-2011-0409', 'CVE-2011-0408'],
    'X11': ['CVE-2013-2210', 'CVE-2013-2211', 'CVE-2013-2212', 'CVE-2013-2213', 'CVE-2013-2214'],
    'Metasploit': ['CVE-2015-5195', 'CVE-2016-5195', 'CVE-2016-5196', 'CVE-2016-5197', 'CVE-2016-5198'],
    'FreeSWITCH': ['CVE-2015-5195', 'CVE-2016-5195', 'CVE-2016-5196', 'CVE-2016-5197', 'CVE-2016-5198'],
    'IRC': ['CVE-2015-5195', 'CVE-2016-5195', 'CVE-2016-5196', 'CVE-2016-5197', 'CVE-2016-5198'],
    'Sun-Webserver': ['CVE-2015-5195', 'CVE-2016-5195', 'CVE-2016-5196', 'CVE-2016-5197', 'CVE-2016-5198'],
    'Webmin': ['CVE-2019-15107', 'CVE-2019-15108', 'CVE-2019-15109', 'CVE-2019-15110', 'CVE-2019-15111'],
    'NetBus': ['CVE-2015-5195', 'CVE-2016-5195', 'CVE-2016-5196', 'CVE-2016-5197', 'CVE-2016-5198'],
    'Dillo': ['CVE-2015-5195', 'CVE-2016-5195', 'CVE-2016-5196', 'CVE-2016-5197', 'CVE-2016-5198'],
    'Unknown': ['CVE-2015-5195', 'CVE-2016-5195', 'CVE-2016-5196', 'CVE-2016-5197', 'CVE-2016-5198']
}

def syn_scan(target_ip, port):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=port, flags="S")
    pkt = ip/tcp
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp is None:
        return None
    elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
        return port
    else:
        return None

def detect_service(target_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((target_ip, port))
            sock.sendall(b'GET / HTTP/1.0\r\n\r\n')
            response = sock.recv(4096)
            if b'HTTP' in response:
                return SERVICE_NAMES.get(port, 'Unknown')
            else:
                return 'Unknown'
    except socket.error:
        return 'Unknown'

def detect_os(target_ip):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=80, flags="S")
    pkt = ip/tcp
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp is None:
        return 'Unknown'
    elif resp.haslayer(IP):
        ttl = resp[IP].ttl
        if ttl == 64:
            return 'Linux'
        elif ttl == 128:
            return 'Windows'
        else:
            return 'Unknown'
    else:
        return 'Unknown'

def scan_port(target_ip, port):
    open_port = syn_scan(target_ip, port)
    if open_port:
        service = detect_service(target_ip, port)
        os_guess = detect_os(target_ip)
        vulnerabilities = VULNERABILITIES.get(service, [])
        return {
            'port': port,
            'service': service,
            'os': os_guess,
            'vulnerabilities': vulnerabilities
        }
    return None

def port_scan(target_ip, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, target_ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception as exc:
                print(f'Port {port} generated an exception: {exc}')
    return open_ports

def main():
    target_ip = input("Enter the target IP address: ")
    open_ports = port_scan(target_ip, COMMON_PORTS)
    if open_ports:
        for port_info in open_ports:
            print(f"Port {port_info['port']} is open.")
            print(f"  Service: {port_info['service']}")
            print(f"  OS Guess: {port_info['os']}")
            print(f"  Vulnerabilities: {', '.join(port_info['vulnerabilities']) if port_info['vulnerabilities'] else 'None'}")
            print()
    else:
        print(f"No open ports found on {target_ip} in the common port list.")

if __name__ == "__main__":
    main()
