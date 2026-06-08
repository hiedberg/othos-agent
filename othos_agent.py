#!/usr/bin/env python3
"""
Othos Scanner Agent
Connects your office printer to the Othos cloud platform.

Usage:
    python othos_agent.py --code ABC-1234-XYZ --server https://api.othos.com
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import platform
import socket
import ssl
import sys
import time
from typing import Optional

import httpx
import websockets
import xml.etree.ElementTree as ET

VERSION = "1.0.0"
HEARTBEAT_INTERVAL = 30
DISCOVERY_INTERVAL = 120
ESCL_PATHS = ["/eSCL/ScannerCapabilities", "/escl/ScannerCapabilities"]
ESCL_PORTS = [80, 8080, 443]
RECONNECT_DELAY = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("othos-agent")


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


async def probe_escl(ip: str, port: int, timeout: float = 2.0) -> Optional[dict]:
    for path in ESCL_PATHS:
        url = f"http://{ip}:{port}{path}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url)
            if response.status_code == 200:
                scanner = {"ip": ip, "port": port, "protocol": "eSCL"}
                try:
                    root = ET.fromstring(response.text)
                    ns = {
                        "pwg": "http://www.pwg.org/schemas/2010/12/sm",
                        "scan": "http://schemas.hp.com/imaging/escl/2011/05/03",
                    }
                    make_model = root.find(".//pwg:MakeAndModel", ns)
                    manufacturer = root.find(".//scan:Manufacturer", ns)
                    if make_model is not None:
                        scanner["name"] = make_model.text
                        scanner["model"] = make_model.text
                    if manufacturer is not None:
                        scanner["manufacturer"] = manufacturer.text
                    else:
                        server = response.headers.get("server", "")
                        if server:
                            scanner["manufacturer"] = server.split(";")[0].strip()
                except Exception:
                    pass
                scanner.setdefault("name", f"Scanner {ip}:{port}")
                return scanner
        except Exception:
            continue
    return None


async def discover_scanners(subnet: str) -> list:
    log.info(f"Scanning subnet {subnet} for eSCL printers...")
    network = ipaddress.IPv4Network(subnet, strict=False)
    found = []

    tasks = []
    for host in list(network.hosts())[:512]:
        for port in ESCL_PORTS:
            tasks.append(probe_escl(str(host), port))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, dict):
            found.append(result)

    log.info(f"Found {len(found)} scanner(s)")
    return found


async def pair_agent(server: str, code: str) -> dict:
    url = f"{server}/api/v1/scanners/agent/pair"
    payload = {
        "code": code,
        "agent_name": f"Othos Agent ({socket.gethostname()})",
        "version": VERSION,
        "platform": f"{platform.system()} {platform.release()}",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(url, json=payload)
    if response.status_code != 200:
        raise RuntimeError(f"Pairing failed: {response.status_code} {response.text}")
    return response.json()


async def run_agent(server: str, agent_id: str, subnet: str):
    ws_url = server.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url}/api/v1/scanners/agent/ws/{agent_id}"

    log.info(f"Connecting to {ws_url}")

    scanners: list = []
    last_discovery = 0.0

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    while True:
        try:
            async with websockets.connect(ws_url, ping_interval=None, ssl=ssl_ctx if ws_url.startswith("wss://") else None) as ws:
                log.info("Connected to Othos cloud ✓")

                async def send_heartbeat():
                    while True:
                        await asyncio.sleep(HEARTBEAT_INTERVAL)
                        try:
                            await ws.send(json.dumps({"type": "heartbeat"}))
                        except Exception:
                            break

                async def run_discovery():
                    nonlocal scanners, last_discovery
                    while True:
                        now = time.time()
                        if now - last_discovery > DISCOVERY_INTERVAL:
                            last_discovery = now
                            scanners = await discover_scanners(subnet)
                            if scanners:
                                log.info(f"Reporting {len(scanners)} scanner(s) to cloud")
                                await ws.send(json.dumps({
                                    "type": "scanners_discovered",
                                    "scanners": scanners,
                                }))
                        await asyncio.sleep(10)

                async def receive_messages():
                    async for raw in ws:
                        try:
                            msg = json.loads(raw)
                            msg_type = msg.get("type")
                            if msg_type == "heartbeat_ack":
                                pass
                            elif msg_type == "scan_request":
                                log.info(f"Scan request received: {msg.get('request_id')}")
                        except Exception as e:
                            log.warning(f"Message error: {e}")

                await asyncio.gather(
                    send_heartbeat(),
                    run_discovery(),
                    receive_messages(),
                )

        except Exception as e:
            log.warning(f"Connection lost: {e}. Reconnecting in {RECONNECT_DELAY}s...")
            await asyncio.sleep(RECONNECT_DELAY)


async def main():
    parser = argparse.ArgumentParser(description="Othos Scanner Agent")
    parser.add_argument("--code", required=True, help="Pairing code from Othos settings")
    parser.add_argument("--server", default="https://api.othos.com", help="Othos server URL")
    parser.add_argument("--subnet", help="Subnet to scan (e.g. 192.168.1.0/24). Auto-detected if omitted.")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════╗
║         Othos Scanner Agent          ║
║         Version {VERSION:<22}║
╚══════════════════════════════════════╝
""")

    subnet = args.subnet or get_local_subnet()
    if not subnet:
        log.error("Could not detect local subnet. Provide --subnet manually.")
        sys.exit(1)

    log.info(f"Local subnet: {subnet}")
    log.info(f"Server: {args.server}")
    log.info("Pairing with Othos...")

    try:
        pair_data = await pair_agent(args.server, args.code)
    except RuntimeError as e:
        log.error(str(e))
        sys.exit(1)

    agent_id = pair_data["agent_id"]
    log.info(f"Paired successfully — Agent ID: {agent_id}")
    log.info("Starting scanner discovery and tunnel...")

    await run_agent(args.server, agent_id, subnet)


if __name__ == "__main__":
    asyncio.run(main())
