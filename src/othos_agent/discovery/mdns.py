from __future__ import annotations

import asyncio
import socket
from typing import Optional

from ..config import MDNS_TIMEOUT, SCANNER_MDNS_SERVICES, log
from .base import DiscoveryStrategy
from .escl import probe_escl


def _is_available() -> bool:
    try:
        import zeroconf
        return True
    except ImportError:
        return False


async def _discover_via_zeroconf() -> list[dict]:
    from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf
    from zeroconf.asyncio import AsyncZeroconf

    found = []
    seen_ips: set = set()
    discovered: list = []

    def _on_service_state_change(zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added:
            discovered.append((zeroconf, service_type, name))

    azc = AsyncZeroconf()
    try:
        browsers = [
            ServiceBrowser(azc.zeroconf, service_type, handlers=[_on_service_state_change])
            for service_type in SCANNER_MDNS_SERVICES
        ]
        await asyncio.sleep(MDNS_TIMEOUT)

        for zc, service_type, name in discovered:
            try:
                info = zc.get_service_info(service_type, name, timeout=2000)
            except Exception:
                continue
            if not info or not info.addresses:
                continue
            try:
                ip = socket.inet_ntoa(info.addresses[0])
            except Exception:
                continue
            port = info.port or 80
            if ip in seen_ips:
                continue
            result = await probe_escl(ip, port, timeout=4.0)
            if result:
                seen_ips.add(ip)
                found.append(result)
                log.info(f"[mDNS] Found via Bonjour: {result.get('name', ip)} at {ip}:{port}")
            else:
                properties = info.decoded_properties if hasattr(info, "decoded_properties") else {}
                display_name = properties.get("ty") or info.name or f"Scanner {ip}"
                seen_ips.add(ip)
                found.append({"ip": ip, "port": port, "protocol": "eSCL", "scheme": "http", "name": display_name})
                log.info(f"[mDNS] Found via Bonjour (no eSCL response): {display_name} at {ip}:{port}")
    finally:
        await azc.async_close()

    return found


class MDNSDiscovery(DiscoveryStrategy):

    def is_available(self) -> bool:
        return _is_available()

    async def discover(self, subnet: str, hints: Optional[list] = None) -> list[dict]:
        if not self.is_available():
            return []
        try:
            results = await _discover_via_zeroconf()
            log.info(f"[mDNS] Found {len(results)} scanner(s)")
            return results
        except Exception as e:
            log.warning(f"[mDNS] Discovery failed: {e}")
            return []
