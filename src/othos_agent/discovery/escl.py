from __future__ import annotations

import asyncio
import ipaddress
import xml.etree.ElementTree as ET
from typing import Optional

import httpx

from ..config import ESCL_PATHS, ESCL_PORTS, HINT_PROBE_TIMEOUT, SUBNET_SCAN_BATCH_SIZE, SUBNET_SCAN_MAX_PREFIX, log
from ..http_client import scanner_http_get
from .base import DiscoveryStrategy

_ESCL_NS = {
    "pwg": "http://www.pwg.org/schemas/2010/12/sm",
    "scan": "http://schemas.hp.com/imaging/escl/2011/05/03",
}


def _parse_capabilities(content: str, ip: str, port: int) -> dict:
    scanner = {"ip": ip, "port": port, "protocol": "eSCL", "scheme": "http"}
    caps: dict = {}
    try:
        root = ET.fromstring(content)
        make_model = root.find(".//pwg:MakeAndModel", _ESCL_NS)
        manufacturer = root.find(".//scan:Manufacturer", _ESCL_NS)
        if make_model is not None:
            scanner["name"] = make_model.text
            scanner["model"] = make_model.text
        if manufacturer is not None:
            scanner["manufacturer"] = manufacturer.text

        version_elem = root.find("pwg:Version", _ESCL_NS)
        if version_elem is not None and version_elem.text:
            caps["version"] = version_elem.text

        resolutions = []
        for res_elem in root.findall(".//scan:DiscreteResolution", _ESCL_NS):
            x = res_elem.find("scan:XResolution", _ESCL_NS)
            if x is not None and x.text:
                try:
                    resolutions.append(int(x.text))
                except ValueError:
                    pass
        if resolutions:
            caps["resolutions"] = sorted(set(resolutions))

        color_modes_raw = []
        color_modes_ui = []
        _color_map = {"RGB24": "color", "Grayscale8": "grayscale", "BlackAndWhite1": "bw"}
        for cm_elem in root.findall(".//scan:ColorMode", _ESCL_NS):
            if cm_elem.text and cm_elem.text not in color_modes_raw:
                color_modes_raw.append(cm_elem.text)
                mapped = _color_map.get(cm_elem.text, cm_elem.text.lower())
                if mapped not in color_modes_ui:
                    color_modes_ui.append(mapped)
        if color_modes_raw:
            caps["color_modes_raw"] = color_modes_raw
            caps["color_modes"] = color_modes_ui

        paper_sizes = []
        _size_map = {
            "iso_a4_210x297mm": "A4",
            "na_letter_8.5x11in": "Letter",
            "na_legal_8.5x14in": "Legal",
        }
        for region in root.findall(".//pwg:ScanRegion", _ESCL_NS):
            discrete = region.find(".//pwg:DiscreteMediaSize", _ESCL_NS)
            if discrete is not None:
                size_name = discrete.find("pwg:SizeName", _ESCL_NS)
                if size_name is not None and size_name.text:
                    mapped = _size_map.get(size_name.text.lower(), size_name.text)
                    if mapped not in paper_sizes:
                        paper_sizes.append(mapped)
        if not paper_sizes:
            paper_sizes = ["A4", "Letter", "Legal"]
        caps["paper_sizes"] = paper_sizes

        platen_caps = root.find(".//scan:PlatenInputCaps", _ESCL_NS)
        if platen_caps is not None:
            def _int(elem, tag):
                e = elem.find(tag, _ESCL_NS)
                return int(e.text) if e is not None and e.text else None
            caps["platen"] = {
                "min_width": _int(platen_caps, "scan:MinWidth"),
                "max_width": _int(platen_caps, "scan:MaxWidth"),
                "min_height": _int(platen_caps, "scan:MinHeight"),
                "max_height": _int(platen_caps, "scan:MaxHeight"),
            }

        adf_caps = root.find(".//scan:AdfSimplexInputCaps", _ESCL_NS)
        if adf_caps is not None:
            def _int_adf(elem, tag):
                e = elem.find(tag, _ESCL_NS)
                return int(e.text) if e is not None and e.text else None
            caps["adf"] = {
                "min_width": _int_adf(adf_caps, "scan:MinWidth"),
                "max_width": _int_adf(adf_caps, "scan:MaxWidth"),
                "min_height": _int_adf(adf_caps, "scan:MinHeight"),
                "max_height": _int_adf(adf_caps, "scan:MaxHeight"),
            }
            duplex_elem = root.find(".//scan:AdfDuplexer", _ESCL_NS)
            caps["duplex"] = duplex_elem is not None
        else:
            caps["adf"] = None
            caps["duplex"] = False

        intents = []
        for intent_elem in root.findall(".//scan:Intent", _ESCL_NS):
            if intent_elem.text and intent_elem.text not in intents:
                intents.append(intent_elem.text)
        if intents:
            caps["intents"] = intents

        formats = []
        for fmt_elem in root.findall(".//pwg:DocumentFormat", _ESCL_NS):
            if fmt_elem.text and fmt_elem.text not in formats:
                formats.append(fmt_elem.text)
        if formats:
            caps["supported_formats"] = formats

        caps["raw_capabilities_xml"] = content

    except Exception:
        pass

    caps.setdefault("version", "2.0")
    caps.setdefault("resolutions", [150, 300, 600])
    caps.setdefault("color_modes_raw", ["RGB24", "Grayscale8"])
    caps.setdefault("color_modes", ["color", "grayscale"])
    caps.setdefault("paper_sizes", ["A4", "Letter", "Legal"])
    caps.setdefault("adf", None)
    caps.setdefault("duplex", False)
    caps.setdefault("supported_formats", ["image/jpeg", "application/pdf"])
    caps.setdefault("intents", ["Document"])

    scanner["capabilities"] = caps
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
            log.debug(f"[eSCL] Timeout probing {url}")
        except httpx.ConnectError:
            pass
        except Exception as e:
            log.debug(f"[eSCL] Error probing {url}: {e}")
    return None


async def probe_direct_escl(scanner_specs: list, local_ip: str = "") -> list:
    found = []
    loop = asyncio.get_event_loop()
    for spec in scanner_specs:
        if ":" in spec:
            ip, port_str = spec.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                log.warning(f"[eSCL] Invalid spec '{spec}' — expected IP:PORT")
                continue
        else:
            ip, port = spec, 8080
        url = f"http://{ip}:{port}/eSCL/ScannerCapabilities"
        log.info(f"[eSCL] Probing direct scanner at {url}")
        try:
            status, _, body = await loop.run_in_executor(
                None, lambda: scanner_http_get(url, local_ip=local_ip, timeout=10)
            )
            content = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
            if status == 200 and "ScannerCapabilities" in content:
                scanner = _parse_capabilities(content, ip, port)
                found.append(scanner)
                log.info(f"[eSCL] Confirmed: {scanner.get('name')} at {ip}:{port}")
            else:
                log.warning(f"[eSCL] {ip}:{port} did not return valid eSCL data")
        except Exception as e:
            log.warning(f"[eSCL] Probe failed for {ip}:{port}: {type(e).__name__}: {e}")
    return found


class ESCLDiscovery(DiscoveryStrategy):

    def is_available(self) -> bool:
        return True

    async def discover(self, subnet: str, hints: Optional[list] = None) -> list[dict]:
        found = []
        seen_ips: set = set()

        if hints:
            log.info(f"[eSCL] Probing {len(hints)} hint IP(s): {', '.join(hints)}")
            hint_results = await asyncio.gather(
                *[self._probe_hint(ip) for ip in hints], return_exceptions=True
            )
            for result in hint_results:
                if isinstance(result, dict):
                    ip = result["ip"]
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        found.append(result)
                        log.info(f"[eSCL] Found via hint: {result.get('name', ip)} at {ip}:{result['port']}")
            if found:
                log.info(f"[eSCL] Found {len(found)} scanner(s) via hints — skipping subnet scan")
                return found
            log.info("[eSCL] No scanners found via hints — falling back to subnet scan")

        log.info(f"[eSCL] Scanning subnet {subnet}...")
        network = ipaddress.IPv4Network(subnet, strict=False)
        if network.prefixlen < SUBNET_SCAN_MAX_PREFIX:
            network = ipaddress.IPv4Network(f"{network.network_address}/{SUBNET_SCAN_MAX_PREFIX}", strict=False)
            log.info(f"[eSCL] Subnet capped to /{SUBNET_SCAN_MAX_PREFIX} for scan: {network}")
        hosts = [str(h) for h in network.hosts()]
        all_results = []
        for i in range(0, len(hosts), SUBNET_SCAN_BATCH_SIZE):
            batch = hosts[i:i + SUBNET_SCAN_BATCH_SIZE]
            tasks = [probe_escl(ip, port) for ip in batch for port in ESCL_PORTS]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            all_results.extend(batch_results)

        for result in sorted([r for r in all_results if isinstance(r, dict)], key=lambda r: r["port"]):
            ip = result["ip"]
            if ip not in seen_ips:
                seen_ips.add(ip)
                found.append(result)
                log.info(f"[eSCL] Found: {result.get('name', ip)} at {ip}:{result['port']}")

        log.info(f"[eSCL] Found {len(found)} scanner(s)")
        return found

    async def _probe_hint(self, ip: str) -> Optional[dict]:
        for port in ESCL_PORTS:
            result = await probe_escl(ip, port, timeout=HINT_PROBE_TIMEOUT)
            if result:
                return result
        return None
