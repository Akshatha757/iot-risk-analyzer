import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_IOT_PORTS = {
    21: 'FTP (File Transfer)',
    22: 'SSH (Secure Shell)',
    23: 'Telnet (Unencrypted CLI)',
    80: 'HTTP (Web Admin)',
    443: 'HTTPS (Secure Web)',
    554: 'RTSP (Video Stream)',
    1900: 'UPnP (SSDP Discovery)',
    8000: 'HTTP Alt',
    8080: 'HTTP Proxy/Admin'
}

def check_port(ip, port, timeout=0.5):
    """
    Attempts to connect to a specific port on the target IP.
    Returns (port, is_open, service_name).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return (port, True, COMMON_IOT_PORTS.get(port, 'Unknown Service'))
    except Exception:
        pass
    return (port, False, COMMON_IOT_PORTS.get(port, 'Unknown Service'))

def scan_target_ip(ip, ports=None, max_threads=10):
    """
    Scans specified ports (or COMMON_IOT_PORTS) on a target IP address.
    Returns a dict with open_ports list and detailed port status.
    """
    if not ports:
        ports = list(COMMON_IOT_PORTS.keys())
    
    open_ports = []
    port_details = []
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_port, ip, port) for port in ports]
        for future in futures:
            port, is_open, service = future.result()
            if is_open:
                open_ports.append(port)
                port_details.append({
                    'port': port,
                    'service': service,
                    'status': 'Open'
                })
                
    return {
        'target_ip': ip,
        'open_ports': sorted(open_ports),
        'open_ports_str': ', '.join(str(p) for p in sorted(open_ports)),
        'details': port_details
    }
