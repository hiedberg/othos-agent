import ipaddress
import socket
import struct
from typing import Optional


def _get_interface_prefix(local_ip: str) -> int:
    try:
        import fcntl
        import array
        import struct as _struct

        SIOCGIFNETMASK = 0x891B
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifaces = array.array("B", b"\0" * 4096)
        import ctypes
        import platform
        if platform.system() == "Darwin":
            SIOCGIFCONF = 0xC0106924
        else:
            SIOCGIFCONF = 0x8912
        outbytes = struct.unpack("iL", fcntl.ioctl(s.fileno(), SIOCGIFCONF, struct.pack("iL", ifaces.buffer_info()[1], ifaces.buffer_info()[0])))[0]
        s.close()
        namestr = ifaces.tobytes()
        iface_list = []
        i = 0
        while i < outbytes:
            name = namestr[i:i+16].split(b"\0", 1)[0].decode("ascii", errors="ignore")
            try:
                sa_family = struct.unpack_from("H", namestr, i + 16)[0]
                if sa_family == socket.AF_INET:
                    ip_bytes = namestr[i + 20:i + 24]
                    ip = socket.inet_ntoa(ip_bytes)
                    iface_list.append((name, ip))
            except Exception:
                pass
            i += 32
        for name, ip in iface_list:
            if ip == local_ip:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    mask_bytes = fcntl.ioctl(s2.fileno(), SIOCGIFNETMASK, struct.pack("256s", name[:15].encode()))[20:24]
                    mask = socket.inet_ntoa(mask_bytes)
                    prefix = sum(bin(int(x)).count("1") for x in mask.split("."))
                    return prefix
                except Exception:
                    pass
                finally:
                    s2.close()
    except Exception:
        pass
    return 24


def get_all_local_subnets() -> list:
    subnets = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                ip = addr.get("addr", "")
                netmask = addr.get("netmask", "255.255.255.0")
                if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                    continue
                try:
                    prefix = sum(bin(int(x)).count("1") for x in netmask.split("."))
                    prefix = max(prefix, 16)
                    network = str(ipaddress.IPv4Interface(f"{ip}/{prefix}").network)
                    subnets.append((iface, ip, network))
                except Exception:
                    pass
    except ImportError:
        pass
    return subnets


def get_local_subnet() -> Optional[str]:
    try:
        subnets = get_all_local_subnets()
        if subnets:
            _, _, network = subnets[0]
            return network
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        prefix = _get_interface_prefix(local_ip)
        prefix = max(prefix, 16)
        network = ipaddress.IPv4Interface(f"{local_ip}/{prefix}").network
        return str(network)
    except Exception:
        return None


def get_local_ip() -> str:
    try:
        subnets = get_all_local_subnets()
        if subnets:
            return subnets[0][1]
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"
