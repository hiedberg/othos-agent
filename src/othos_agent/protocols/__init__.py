from .base import ScannerProtocol
from .escl import ESCLProtocol
from .sane import SANEProtocol
from .wia import WIAProtocol

_registry: dict[str, ScannerProtocol] = {
    "eSCL": ESCLProtocol(),
    "SANE": SANEProtocol(),
    "WIA": WIAProtocol(),
}


def get_protocol(name: str) -> ScannerProtocol:
    protocol = _registry.get(name)
    if protocol is None:
        raise ValueError(f"Unknown scanner protocol: '{name}'. Supported: {list(_registry.keys())}")
    if not protocol.is_available():
        raise RuntimeError(
            f"Protocol '{name}' is not available on this machine. "
            f"Install the required dependencies for {name}."
        )
    return protocol


def available_protocols() -> list[str]:
    return [name for name, p in _registry.items() if p.is_available()]
