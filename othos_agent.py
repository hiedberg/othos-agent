#!/usr/bin/env python3
"""
Othos Scanner Agent
Connects your office printer to the Othos cloud platform.

Usage:
    python othos_agent.py --code ABC-1234-XYZ --server https://api.othos.com
"""

import argparse
import asyncio
import glob
import ipaddress
import json
import logging
import os
import platform
import socket
import ssl
import sys
import tempfile
import time
from typing import Optional
from urllib.parse import urlparse

import httpx
import websockets
import xml.etree.ElementTree as ET

VERSION = "1.0.0"
HEARTBEAT_INTERVAL = 30
DISCOVERY_INTERVAL = 120
ESCL_PATHS = ["/eSCL/ScannerCapabilities", "/escl/ScannerCapabilities"]
ESCL_PORTS = [80, 8080, 443]
RECONNECT_DELAY = 5
SUPPORTED_FORMATS = {"jpeg", "jpg", "pdf", "png", "tiff"}

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
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                response = await client.get(url)
            if response.status_code != 200:
                continue
            content = response.text
            if "ScannerCapabilities" not in content:
                continue
            scanner = {"ip": ip, "port": port, "protocol": "eSCL", "scheme": "http"}
            try:
                root = ET.fromstring(content)
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
                    server_hdr = response.headers.get("server", "")
                    if server_hdr:
                        scanner["manufacturer"] = server_hdr.split(";")[0].strip()
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
    seen = set()
    sem = asyncio.Semaphore(50)

    async def _probe_with_sem(ip: str, port: int):
        async with sem:
            return await probe_escl(ip, port)

    hosts = list(network.hosts())
    tasks = []
    for host in hosts:
        for port in ESCL_PORTS:
            tasks.append(_probe_with_sem(str(host), port))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    candidates = sorted(
        [r for r in results if isinstance(r, dict)],
        key=lambda r: r["port"],
    )
    seen_ips: set = set()
    for result in candidates:
        ip = result["ip"]
        if ip not in seen_ips:
            seen_ips.add(ip)
            found.append(result)
            log.info(f"Found scanner [eSCL]: {result.get('name', ip)} at {ip}:{result['port']}")

    log.info(f"Found {len(found)} scanner(s)")
    return found


async def pair_agent(server: str, code: str, insecure: bool = False, ca_bundle: Optional[str] = None) -> dict:
    url = f"{server}/api/v1/scanners/agent/pair"
    payload = {
        "code": code,
        "agent_name": f"Othos Agent ({socket.gethostname()})",
        "version": VERSION,
        "platform": f"{platform.system()} {platform.release()}",
    }
    client_kwargs = {"timeout": 15.0}
    if insecure:
        client_kwargs["verify"] = False
    elif ca_bundle:
        client_kwargs["verify"] = ca_bundle
    async with httpx.AsyncClient(**client_kwargs) as client:
        response = await client.post(url, json=payload)
    if response.status_code != 200:
        raise RuntimeError(f"Pairing failed: {response.status_code} {response.text}")
    return response.json()


def get_ssl_context(insecure: bool = False, ca_bundle: Optional[str] = None) -> Optional[ssl.SSLContext]:
    if insecure:
        log.warning("SSL verification disabled — insecure mode (development only)")
        return ssl._create_unverified_context()
    if ca_bundle:
        log.info(f"Using custom CA bundle: {ca_bundle}")
        context = ssl.create_default_context(cafile=ca_bundle)
        return context
    return None


async def execute_scan(ip: str, port: int, config: dict, protocol: str = "eSCL", scheme: str = "http", ws=None, request_id: str = None) -> dict:
    base_url = f"{scheme}://{ip}:{port}"
    scan_jobs_url = f"{base_url}/eSCL/ScanJobs"
    scanner_status_url = f"{base_url}/eSCL/ScannerStatus"

    async def _send_progress(sub_state: str, message: str):
        if ws and request_id:
            try:
                await ws.send(json.dumps({
                    "type": "scan_progress",
                    "request_id": request_id,
                    "sub_state": sub_state,
                    "message": message,
                }))
            except Exception:
                pass

    resolution = config.get("resolution", 300)
    color_mode = config.get("color_mode", "color")
    paper_size = config.get("paper_size", "A4")
    duplex = config.get("duplex", False)
    raw_format = config.get("format", "jpeg").lower()
    format_type = raw_format if raw_format in SUPPORTED_FORMATS else "jpeg"

    paper_sizes = {
        "A4": (210, 297),
        "Letter": (215.9, 279.4),
        "Legal": (215.9, 355.6),
    }
    width_mm, height_mm = paper_sizes.get(paper_size, (210, 297))

    color_modes = {
        "color": "RGB24",
        "grayscale": "Grayscale8",
        "bw": "BlackAndWhite1",
    }
    input_color = color_modes.get(color_mode, "RGB24")
    input_source = "ADF" if duplex else "Platen"

    settings_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<scan:ScanSettings xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03" xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm">
    <pwg:Version>2.63</pwg:Version>
    <scan:InputSource>{input_source}</scan:InputSource>
    <scan:ColorMode>{input_color}</scan:ColorMode>
    <pwg:ScanRegions>
        <pwg:ScanRegion>
            <pwg:Height>{int(height_mm * 100)}</pwg:Height>
            <pwg:ContentRegionUnits>escl:HundredthsOfMM</pwg:ContentRegionUnits>
            <pwg:Width>{int(width_mm * 100)}</pwg:Width>
            <pwg:XOffset>0</pwg:XOffset>
            <pwg:YOffset>0</pwg:YOffset>
        </pwg:ScanRegion>
    </pwg:ScanRegions>
    <scan:Resolution>
        <scan:Width>{resolution}</scan:Width>
        <scan:Height>{resolution}</scan:Height>
    </scan:Resolution>
    <scan:DocumentFormat>image/{format_type}</scan:DocumentFormat>
</scan:ScanSettings>'''

    client_kwargs = {"timeout": 30.0, "follow_redirects": False}
    if scheme == "https":
        client_kwargs["verify"] = False

    async with httpx.AsyncClient(**client_kwargs) as client:
        log.info(f"Creating scan job at {scan_jobs_url}")

        job_uri = None
        image_data = None
        max_job_retries = 12
        max_wait = 10

        for job_attempt in range(max_job_retries):
            response = await client.post(
                scan_jobs_url,
                content=settings_xml,
                headers={"Content-Type": "application/xml"},
            )

            if response.status_code in (200, 201, 202):
                location = response.headers.get("Location")
                if location:
                    if location.startswith("http://") or location.startswith("https://"):
                        job_uri = urlparse(location).path
                    else:
                        job_uri = location
                    log.info(f"Job created: {job_uri}")
                break

            if response.status_code == 503:
                log.info(f"Scanner busy (503), checking for existing job (attempt {job_attempt+1}/{max_job_retries})...")
                await _send_progress("busy", f"Scanner busy (attempt {job_attempt+1}/{max_job_retries})...")

                status_resp = await client.get(scanner_status_url)
                if status_resp.status_code == 200:
                    try:
                        root = ET.fromstring(status_resp.text)
                        existing_job = None
                        scanner_state = None

                        for elem in root.iter():
                            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                            if tag == "ScannerState":
                                scanner_state = elem.text
                            elif tag == "JobUri":
                                existing_job = {"uri": elem.text}
                            elif tag == "JobState" and existing_job:
                                existing_job["state"] = elem.text

                        log.info(f"ScannerState: {scanner_state}, existing_job: {existing_job}")

                        if existing_job and existing_job.get("state") in ("Processing", "Pending"):
                            job_uri = existing_job["uri"]
                            if job_uri and (job_uri.startswith("http://") or job_uri.startswith("https://")):
                                job_uri = urlparse(job_uri).path
                            log.info(f"Found existing job after 503: {job_uri}")
                            await _send_progress("scanning", "Resuming existing scan job...")
                            break

                        if scanner_state and scanner_state.lower() in ("idle", "processing"):
                            log.info(f"Scanner state is {scanner_state} — 503 may be transient, retrying...")
                    except Exception:
                        pass

                if job_attempt < max_job_retries - 1:
                    wait_time = min(3 + job_attempt * 2, max_wait)
                    log.info(f"Scanner busy, waiting {wait_time}s before retry ({job_attempt+1}/{max_job_retries})...")
                    await _send_progress("retrying", f"Scanner busy — retrying in {wait_time}s ({job_attempt+1}/{max_job_retries})...")
                    await asyncio.sleep(wait_time)
            else:
                raise Exception(f"Failed to create scan job: HTTP {response.status_code}")

        if not job_uri:
            raise Exception("Scanner is busy and no existing job found. Please wait and try again.")

        for attempt in range(120):
            await asyncio.sleep(1)

            status_resp = await client.get(scanner_status_url)
            if status_resp.status_code == 200:
                try:
                    root = ET.fromstring(status_resp.text)
                    job_info = {}

                    for elem in root.iter():
                        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        if tag == "JobUri":
                            job_info["uri"] = elem.text
                        elif tag == "JobState":
                            job_info["state"] = elem.text
                        elif tag == "ImagesCompleted":
                            job_info["completed"] = int(elem.text) if elem.text else 0
                        elif tag == "ImagesToTransfer":
                            job_info["to_transfer"] = int(elem.text) if elem.text else 0

                    if job_info.get("uri") == job_uri:
                        completed = job_info.get("completed", 0)
                        to_transfer = job_info.get("to_transfer", 0)
                        state = job_info.get("state", "Unknown")
                        log.info(f"Poll {attempt+1}: Job {job_uri} state={state} - {completed}/{to_transfer} images")

                        if state in ("Completed", "Processing") and to_transfer > 0 and not image_data:
                            dl_url = f"{base_url}{job_uri}/NextDocument"
                            dl_resp = await client.get(dl_url)
                            if dl_resp.status_code == 200 and len(dl_resp.content) > 1000:
                                image_data = dl_resp.content
                                log.info(f"Image downloaded: {len(image_data)} bytes")
                                break

                        if state == "Completed" and image_data:
                            break

                except Exception as e:
                    log.debug(f"Error parsing status: {e}")

            if not image_data and attempt % 3 == 0:
                dl_url = f"{base_url}{job_uri}/NextDocument"
                dl_resp = await client.get(dl_url)
                if dl_resp.status_code == 200 and len(dl_resp.content) > 1000:
                    image_data = dl_resp.content
                    log.info(f"Image downloaded: {len(image_data)} bytes")
                    break

        if not image_data:
            raise Exception("Scan did not complete or no image available")

        ext = ".pdf" if format_type == "pdf" else ".jpg"
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            f.write(image_data)
            temp_path = f.name

        log.info(f"Scan saved to {temp_path} ({len(image_data)} bytes)")
        return {"file_path": temp_path, "file_size": len(image_data), "format": format_type}


async def run_agent(server: str, agent_id: str, subnet: str, insecure: bool = False, ca_bundle: Optional[str] = None):
    ws_url = server.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url}/api/v1/scanners/agent/ws/{agent_id}"

    log.info(f"Connecting to {ws_url}")

    ssl_context = get_ssl_context(insecure, ca_bundle)

    scanners: list = []
    last_discovery = 0.0
    scanner_locks: dict = {}
    active_requests: set = set()
    completed_requests: dict = {}

    while True:
        try:
            async with websockets.connect(ws_url, ping_interval=None, ssl=ssl_context) as ws:
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
                                request_id = msg.get("request_id")
                                scanner_ip = msg.get("scanner_ip")
                                scanner_port = msg.get("scanner_port", 80)
                                scanner_protocol = msg.get("scanner_protocol", "eSCL")
                                scanner_scheme = msg.get("scanner_scheme", "http")
                                config = msg.get("config", {})

                                if not scanner_ip or not request_id:
                                    log.error(f"scan_request missing fields: request_id={request_id}, ip={scanner_ip}")
                                    continue

                                if request_id in active_requests:
                                    log.warning(f"Duplicate scan request {request_id} - already in progress")
                                    await ws.send(json.dumps({
                                        "type": "scan_response",
                                        "request_id": request_id,
                                        "status": "error",
                                        "error": "Scan already in progress for this request",
                                    }))
                                    continue

                                if request_id in completed_requests:
                                    log.info(f"Request {request_id} already completed - returning cached result")
                                    await ws.send(json.dumps(completed_requests[request_id]))
                                    continue

                                log.info(f"Scan request received: {request_id} for {scanner_protocol}://{scanner_ip}:{scanner_port}")

                                async def _handle_scan(req_id, s_ip, s_port, cfg, s_protocol, s_scheme):
                                    active_requests.add(req_id)
                                    response_payload = {}
                                    try:
                                        result = await execute_scan(s_ip, s_port, cfg, s_protocol, s_scheme, ws=ws, request_id=req_id)
                                        upload_url = f"{server}/api/v1/scanners/agent/upload"
                                        async with httpx.AsyncClient(timeout=60.0) as upload_client:
                                            with open(result["file_path"], "rb") as f:
                                                upload_resp = await upload_client.post(
                                                    upload_url,
                                                    files={"file": (f"scan.{result['format']}", f, f"image/{result['format']}")},
                                                    data={"request_id": req_id, "agent_id": agent_id},
                                                )
                                        if upload_resp.status_code == 200:
                                            upload_data = upload_resp.json()
                                            log.info(f"Scan uploaded successfully: {upload_data.get('file_id')}")
                                            response_payload = {
                                                "type": "scan_response",
                                                "request_id": req_id,
                                                "status": "success",
                                                "file_id": upload_data.get("file_id"),
                                                "file_url": upload_data.get("file_url"),
                                            }
                                        else:
                                            log.error(f"Upload failed: HTTP {upload_resp.status_code}")
                                            response_payload = {
                                                "type": "scan_response",
                                                "request_id": req_id,
                                                "status": "error",
                                                "error": f"Upload failed: HTTP {upload_resp.status_code}",
                                            }
                                        await ws.send(json.dumps(response_payload))
                                        try:
                                            os.unlink(result["file_path"])
                                        except Exception:
                                            pass
                                    except Exception as e:
                                        log.error(f"Scan failed: {e}")
                                        response_payload = {
                                            "type": "scan_response",
                                            "request_id": req_id,
                                            "status": "error",
                                            "error": str(e),
                                        }
                                        await ws.send(json.dumps(response_payload))
                                    finally:
                                        active_requests.discard(req_id)
                                        if response_payload.get("status") == "success":
                                            completed_requests[req_id] = response_payload
                                            asyncio.get_event_loop().call_later(300, lambda: completed_requests.pop(req_id, None))

                                scanner_key = f"{scanner_ip}:{scanner_port}"
                                if scanner_key not in scanner_locks:
                                    scanner_locks[scanner_key] = asyncio.Lock()

                                async def _handle_scan_locked(req_id, s_ip, s_port, cfg, s_protocol, s_scheme, lock):
                                    async with lock:
                                        await _handle_scan(req_id, s_ip, s_port, cfg, s_protocol, s_scheme)

                                asyncio.create_task(_handle_scan_locked(request_id, scanner_ip, scanner_port, config, scanner_protocol, scanner_scheme, scanner_locks[scanner_key]))
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
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification (development/ngrok only)")
    parser.add_argument("--ca-bundle", dest="ca_bundle", help="Path to custom CA certificate bundle (for on-prem/internal CA)")
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
        pair_data = await pair_agent(args.server, args.code, insecure=args.insecure, ca_bundle=args.ca_bundle)
    except RuntimeError as e:
        log.error(str(e))
        sys.exit(1)

    agent_id = pair_data["agent_id"]
    log.info(f"Paired successfully — Agent ID: {agent_id}")
    log.info("Starting scanner discovery and tunnel...")

    await run_agent(args.server, agent_id, subnet, insecure=args.insecure, ca_bundle=args.ca_bundle)


if __name__ == "__main__":
    asyncio.run(main())
