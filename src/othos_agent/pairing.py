import platform
import socket
import ssl
from typing import Optional

import certifi
import httpx

from .config import VERSION, log


def get_ssl_context(insecure: bool = False, ca_bundle: Optional[str] = None) -> ssl.SSLContext:
    if insecure:
        log.warning("SSL verification disabled — insecure mode (development only)")
        ctx = ssl._create_unverified_context()
    else:
        cafile = ca_bundle or certifi.where()
        if ca_bundle:
            log.info(f"Using custom CA bundle: {ca_bundle}")
        ctx = ssl.create_default_context(cafile=cafile)
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


async def pair_agent(server: str, code: str, insecure: bool = False, ca_bundle: Optional[str] = None) -> dict:
    url = f"{server}/api/v1/scanners/agent/pair"
    payload = {
        "code": code,
        "agent_name": f"Othos Agent ({socket.gethostname()})",
        "version": VERSION,
        "platform": f"{platform.system()} {platform.release()}",
    }
    client_kwargs: dict = {"timeout": 15.0}
    if insecure:
        client_kwargs["verify"] = False
    elif ca_bundle:
        client_kwargs["verify"] = ca_bundle

    async with httpx.AsyncClient(**client_kwargs) as client:
        response = await client.post(url, json=payload)

    if response.status_code != 200:
        raise RuntimeError(f"Pairing failed: {response.status_code} {response.text}")
    return response.json()
