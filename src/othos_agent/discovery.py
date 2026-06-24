import asyncio
import ipaddress
import xml.etree.ElementTree as ET
from typing import Optional

import httpx

from .config import ESCL_PATHS, ESCL_PORTS, HINT_PROBE_TIMEOUT, SUBNET_SCAN_BATCH_SIZE, SUBNET_SCAN_MAX_PREFIX, log
from .http_client import scanner_http_get

_ESCL_NS = {
    "pwg": "http://www.pwg.org/schemas/2010/12/sm",
    "scan": "http://schemas.hp.com/imaging/escl/2011/05/03",
}


def _parse_capabilities(content: str, ip: str, port: int) -> dict:
    scanner = {"ip": ip, "port": port, "protocol": "eSCL", "scheme": "http"}
    try:
        root = ET.fromstring(content)
        make_model = root.find(".//pwg:MakeAndModel", _ESCL_NS)
        manufacturer = root.find(".//scan:Manufacturer", _ESCL_NS)
        if make_model is not None:
            scanner["name"] = make_model.text
            scanner["model"] = make_model.text
        if manufacturer is not None:
            scanner["manufacturer"] = manufacturer.text
    except Exception:
        pass
    scanner.setdefault("name", f"Scanner {ip}:{port}")
    return scanner


async def probe_escl(ip: str, port: int, timeout: float = 4.0) -> Optional[dict]:
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
            scanner = _parse_capabilities(content, ip, port)
            if "manufacturer" not in scanner:
                server_hdr = response.headers.get("server", "")
                if server_hdr:
                    scanner["manufacturer"] = server_hdr.split(";")[0].strip()
            return scanner
        except httpx.TimeoutException:
            log.debug(f"Timeout probing {url}")
        except httpx.ConnectError:
            pass
        except Exception as e:
            log.debug(f"Error probing {url}: {e}")
    return None


async def probe_hint(ip: str) -> Optional[dict]:
    for port in ESCL_PORTS:
        result = await probe_escl(ip, port, timeout=HINT_PROBE_TIMEOUT)
        if result:
            return result
    return None


async def probe_direct_scanners(scanner_specs: list, local_ip: str = "") -> list:
    found = []
    loop = asyncio.get_event_loop()

    for spec in scanner_specs:
        if ":" in spec:
            ip, port_str = spec.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                log.warning(f"Invalid scanner spec '{spec}' — expected IP:PORT")
                continue
        else:
            ip = spec
            port = 8080

        url = f"http://{ip}:{port}/eSCL/ScannerCapabilities"
        log.info(f"Probing direct scanner at {url}")

        try:
            status, _, body = await loop.run_in_executor(
                None, lambda: scanner_http_get(url, local_ip=local_ip, timeout=10)
            )
            content = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
            log.info(f"Direct probe {url} → HTTP {status} body_len={len(content)}")
            if status == 200 and content and "ScannerCapabilities" in content:
                scanner = _parse_capabilities(content, ip, port)
                found.append(scanner)
                log.info(f"Direct scanner confirmed: {scanner.get('name')} at {ip}:{port}")
            else:
                log.warning(f"Direct scanner {ip}:{port} did not return valid eSCL data — will retry next cycle")
        except Exception as e:
            log.warning(f"Direct scanner {ip}:{port} probe failed: {type(e).__name__}: {e}")

    return found


async def discover_scanners(subnet: str, hints: Optional[list] = None) -> list:
    found = []
    seen_ips: set = set()

    if hints:
        log.info(f"Probing {len(hints)} hint IP(s) first: {', '.join(hints)}")
        hint_results = await asyncio.gather(*[probe_hint(ip) for ip in hints], return_exceptions=True)
        for result in hint_results:
            if isinstance(result, dict):
                ip = result["ip"]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    found.append(result)
                    log.info(f"Found scanner [hint]: {result.get('name', ip)} at {ip}:{result['port']}")
        if found:
            log.info(f"Found {len(found)} scanner(s) via hints — skipping subnet scan")
            return found
        log.info("No scanners found via hints — falling back to subnet scan")

    log.info(f"Scanning subnet {subnet} for eSCL printers...")
    network = ipaddress.IPv4Network(subnet, strict=False)
    if network.prefixlen < SUBNET_SCAN_MAX_PREFIX:
        network = ipaddress.IPv4Network(f"{network.network_address}/{SUBNET_SCAN_MAX_PREFIX}", strict=False)
        log.info(f"Subnet capped to /{SUBNET_SCAN_MAX_PREFIX} for scan: {network}")
    hosts = [str(h) for h in network.hosts()]

    all_results = []
    for i in range(0, len(hosts), SUBNET_SCAN_BATCH_SIZE):
        batch = hosts[i:i + SUBNET_SCAN_BATCH_SIZE]
        tasks = [probe_escl(ip, port) for ip in batch for port in ESCL_PORTS]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        all_results.extend(batch_results)

    candidates = sorted(
        [r for r in all_results if isinstance(r, dict)],
        key=lambda r: r["port"],
    )
    for result in candidates:
        ip = result["ip"]
        if ip not in seen_ips:
            seen_ips.add(ip)
            found.append(result)
            log.info(f"Found scanner [eSCL]: {result.get('name', ip)} at {ip}:{result['port']}")

    log.info(f"Found {len(found)} scanner(s)")
    return found
