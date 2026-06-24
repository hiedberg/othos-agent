from __future__ import annotations

import asyncio
import platform
from typing import Optional

from ..config import log
from .base import DiscoveryStrategy

_IS_WINDOWS = platform.system() == "Windows"

try:
    if _IS_WINDOWS:
        import win32com.client as _win32com
        _WIA_AVAILABLE = True
    else:
        _WIA_AVAILABLE = False
except ImportError:
    _WIA_AVAILABLE = False


class WIADiscovery(DiscoveryStrategy):

    def is_available(self) -> bool:
        return _WIA_AVAILABLE

    async def discover(self, subnet: str, hints: Optional[list] = None) -> list[dict]:
        if not _WIA_AVAILABLE:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._discover_blocking)

    def _discover_blocking(self) -> list[dict]:
        try:
            wia = _win32com.Dispatch("WIA.DeviceManager")
            devices = wia.DeviceInfos
            log.info(f"[WIA] Found {devices.Count} device(s)")
            found = []
            for i in range(1, devices.Count + 1):
                dev_info = devices.Item(i)
                props = dev_info.Properties
                name = props("Name").Value if "Name" in [p.Name for p in props] else f"WIA Device {i}"
                found.append({
                    "ip": "localhost",
                    "port": 0,
                    "protocol": "WIA",
                    "scheme": "wia",
                    "name": name,
                    "manufacturer": "",
                    "device_id": dev_info.DeviceID,
                })
            return found
        except Exception as e:
            log.warning(f"[WIA] Discovery failed: {e}")
            return []
