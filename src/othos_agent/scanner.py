from typing import Optional

from .protocols import get_protocol


async def execute_scan(
    ip: str,
    port: int,
    config: dict,
    protocol: str = "eSCL",
    scheme: str = "http",
    ws=None,
    request_id: Optional[str] = None,
    local_ip: str = "",
) -> dict:
    strategy = get_protocol(protocol)
    return await strategy.scan(
        ip=ip,
        port=port,
        config=config,
        scheme=scheme,
        ws=ws,
        request_id=request_id,
        local_ip=local_ip,
    )
