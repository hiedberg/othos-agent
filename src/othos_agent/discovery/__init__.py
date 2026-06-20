from typing import Optional

from ..config import log
from .base import DiscoveryStrategy
from .escl import ESCLDiscovery, probe_direct_escl
from .sane import SANEDiscovery
from .wia import WIADiscovery

_strategies: list[DiscoveryStrategy] = [
    ESCLDiscovery(),
    SANEDiscovery(),
    WIADiscovery(),
]


async def discover_all(subnet: str, hints: Optional[list] = None) -> list[dict]:
    found = []
    for strategy in _strategies:
        if not strategy.is_available():
            continue
        try:
            results = await strategy.discover(subnet, hints=hints)
            found.extend(results)
        except Exception as e:
            log.warning(f"[Discovery] {type(strategy).__name__} failed: {e}")
    return found


async def discover_direct(scanner_specs: list, local_ip: str = "") -> list[dict]:
    return await probe_direct_escl(scanner_specs, local_ip=local_ip)


def available_strategies() -> list[str]:
    return [type(s).__name__ for s in _strategies if s.is_available()]
