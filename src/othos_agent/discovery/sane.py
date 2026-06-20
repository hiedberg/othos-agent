import asyncio
from typing import Optional

from ..config import log
from .base import DiscoveryStrategy

try:
    import sane as _sane_lib
    _SANE_AVAILABLE = True
except ImportError:
    _SANE_AVAILABLE = False


class SANEDiscovery(DiscoveryStrategy):

    def is_available(self) -> bool:
        return _SANE_AVAILABLE

    async def discover(self, subnet: str, hints: Optional[list] = None) -> list[dict]:
        if not _SANE_AVAILABLE:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._discover_blocking)

    def _discover_blocking(self) -> list[dict]:
        try:
            _sane_lib.init()
            devices = _sane_lib.get_devices()
            log.info(f"[SANE] Found {len(devices)} device(s): {devices}")
            found = []
            for dev in devices:
                name, vendor, model, kind = dev
                found.append({
                    "ip": "localhost",
                    "port": 0,
                    "protocol": "SANE",
                    "scheme": "sane",
                    "name": f"{vendor} {model}".strip() or name,
                    "model": model,
                    "manufacturer": vendor,
                    "device_name": name,
                })
            return found
        except Exception as e:
            log.warning(f"[SANE] Discovery failed: {e}")
            return []
        finally:
            try:
                _sane_lib.exit()
            except Exception:
                pass
