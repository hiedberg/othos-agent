import ipaddress
import socket
from typing import Optional


def get_local_subnet() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = ipaddress.IPv4Interface(f"{local_ip}/24").network
        return str(network)
    except Exception:
        return None


def get_local_ip() -> str:
    local_ip = str(ipaddress.IPv4Interface(f"{socket.gethostbyname(socket.gethostname())}/24").ip)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    return local_ip
