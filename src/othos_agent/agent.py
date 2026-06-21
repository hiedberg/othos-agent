import asyncio
import json
import os
from typing import Optional

import httpx
import websockets

from .config import DISCOVERY_INTERVAL, HEARTBEAT_INTERVAL, RECONNECT_DELAY, VERSION, log
from .discovery import available_strategies, discover_all, discover_direct
from .pairing import get_ssl_context
from .protocols import available_protocols
from .scanner import execute_scan


async def run_agent(
    server: str,
    agent_id: str,
    subnet: str,
    local_ip: str = "",
    hints: Optional[list] = None,
    scanners_direct: Optional[list] = None,
    insecure: bool = False,
    ca_bundle: Optional[str] = None,
    token: Optional[str] = None,
):
    ws_url = server.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url}/api/v1/scanners/agent/ws/{agent_id}"

    log.info(f"Connecting to {ws_url}")
    log.info(f"Available scan protocols: {available_protocols()}")
    log.info(f"Available discovery strategies: {available_strategies()}")

    ssl_context = get_ssl_context(insecure, ca_bundle)

    extra_headers = {
        "User-Agent": f"OthosAgent/{VERSION}",
        "X-Agent-Version": VERSION,
        "ngrok-skip-browser-warning": "true",
    }
    if token:
        extra_headers["X-Agent-Token"] = token

    while True:
        try:
            await _run_session(
                ws_url=ws_url,
                server=server,
                agent_id=agent_id,
                subnet=subnet,
                local_ip=local_ip,
                hints=hints,
                scanners_direct=scanners_direct,
                ssl_context=ssl_context,
                extra_headers=extra_headers,
            )
        except Exception as e:
            log.warning(f"Connection lost: {e}. Reconnecting in {RECONNECT_DELAY}s...")
            await asyncio.sleep(RECONNECT_DELAY)


async def _run_session(
    ws_url: str,
    server: str,
    agent_id: str,
    subnet: str,
    local_ip: str,
    hints: Optional[list],
    scanners_direct: Optional[list],
    ssl_context,
    extra_headers: dict,
):
    scanners: list = []
    last_discovery = 0.0
    scanner_locks: dict = {}
    active_requests: set = set()
    completed_requests: dict = {}

    log.info("Establishing WebSocket connection...")
    async with websockets.connect(
        ws_url,
        ping_interval=30,
        ping_timeout=10,
        ssl=ssl_context,
        extra_headers=extra_headers,
        compression=None,
    ) as ws:
        log.info("Connected to Othos cloud ✓")

        await asyncio.gather(
            _heartbeat_loop(ws),
            _discovery_loop(ws, subnet, local_ip, hints, scanners_direct, scanners, lambda s: setattr(_discovery_loop, '_scanners', s)),
            _receive_loop(ws, server, agent_id, local_ip, scanner_locks, active_requests, completed_requests),
        )


async def _heartbeat_loop(ws):
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            await ws.send(json.dumps({"type": "heartbeat"}))
        except Exception:
            break


async def _discovery_loop(ws, subnet, local_ip, hints, scanners_direct, scanners, on_update):
    import time
    last_discovery = 0.0
    while True:
        now = time.time()
        if now - last_discovery > DISCOVERY_INTERVAL:
            last_discovery = now
            if scanners_direct:
                found = await discover_direct(scanners_direct, local_ip=local_ip)
            else:
                found = await discover_all(subnet, hints=hints)
            scanners[:] = found
            if found:
                log.info(f"Reporting {len(found)} scanner(s) to cloud")
                await ws.send(json.dumps({"type": "scanners_discovered", "scanners": found}))
        await asyncio.sleep(10)


async def _receive_loop(ws, server, agent_id, local_ip, scanner_locks, active_requests, completed_requests):
    async for raw in ws:
        try:
            msg = json.loads(raw)
            msg_type = msg.get("type")

            if msg_type == "heartbeat_ack":
                continue

            if msg_type == "scan_request":
                await _handle_scan_request(
                    ws=ws,
                    msg=msg,
                    server=server,
                    agent_id=agent_id,
                    local_ip=local_ip,
                    scanner_locks=scanner_locks,
                    active_requests=active_requests,
                    completed_requests=completed_requests,
                )
        except Exception as e:
            log.warning(f"Message error: {e}")


async def _handle_scan_request(ws, msg, server, agent_id, local_ip, scanner_locks, active_requests, completed_requests):
    request_id = msg.get("request_id")
    scanner_ip = msg.get("scanner_ip")
    scanner_port = msg.get("scanner_port", 80)
    scanner_protocol = msg.get("scanner_protocol", "eSCL")
    scanner_scheme = msg.get("scanner_scheme", "http")
    config = msg.get("config", {})

    if not scanner_ip or not request_id:
        log.error(f"scan_request missing fields: request_id={request_id}, ip={scanner_ip}")
        return

    if request_id in active_requests:
        log.warning(f"Duplicate scan request {request_id} — already in progress")
        await ws.send(json.dumps({
            "type": "scan_response",
            "request_id": request_id,
            "status": "error",
            "error": "Scan already in progress for this request",
        }))
        return

    if request_id in completed_requests:
        log.info(f"Request {request_id} already completed — returning cached result")
        await ws.send(json.dumps(completed_requests[request_id]))
        return

    log.info(f"Scan request received: {request_id} for {scanner_protocol}://{scanner_ip}:{scanner_port}")

    scanner_key = f"{scanner_ip}:{scanner_port}"
    if scanner_key not in scanner_locks:
        scanner_locks[scanner_key] = asyncio.Lock()

    asyncio.create_task(_execute_scan_task(
        ws=ws,
        server=server,
        agent_id=agent_id,
        request_id=request_id,
        scanner_ip=scanner_ip,
        scanner_port=scanner_port,
        scanner_protocol=scanner_protocol,
        scanner_scheme=scanner_scheme,
        config=config,
        local_ip=local_ip,
        lock=scanner_locks[scanner_key],
        active_requests=active_requests,
        completed_requests=completed_requests,
    ))


async def _execute_scan_task(
    ws, server, agent_id, request_id,
    scanner_ip, scanner_port, scanner_protocol, scanner_scheme,
    config, local_ip, lock, active_requests, completed_requests,
):
    async with lock:
        active_requests.add(request_id)
        response_payload = {}
        try:
            result = await execute_scan(
                scanner_ip, scanner_port, config,
                scanner_protocol, scanner_scheme,
                ws=ws, request_id=request_id, local_ip=local_ip,
            )
            upload_url = f"{server}/api/v1/scanners/agent/upload"
            async with httpx.AsyncClient(timeout=60.0) as upload_client:
                with open(result["file_path"], "rb") as f:
                    upload_resp = await upload_client.post(
                        upload_url,
                        files={"file": (f"scan.{result['format']}", f, f"image/{result['format']}")},
                        data={"request_id": request_id, "agent_id": agent_id},
                    )
            if upload_resp.status_code == 200:
                upload_data = upload_resp.json()
                log.info(f"Scan uploaded successfully: {upload_data.get('file_id')}")
                response_payload = {
                    "type": "scan_response",
                    "request_id": request_id,
                    "status": "success",
                    "file_id": upload_data.get("file_id"),
                    "file_url": upload_data.get("file_url"),
                }
            else:
                log.error(f"Upload failed: HTTP {upload_resp.status_code}")
                response_payload = {
                    "type": "scan_response",
                    "request_id": request_id,
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
                "request_id": request_id,
                "status": "error",
                "error": str(e),
            }
            await ws.send(json.dumps(response_payload))
        finally:
            active_requests.discard(request_id)
            if response_payload.get("status") == "success":
                completed_requests[request_id] = response_payload
                asyncio.get_event_loop().call_later(300, lambda: completed_requests.pop(request_id, None))
