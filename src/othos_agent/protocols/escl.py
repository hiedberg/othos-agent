from __future__ import annotations

import asyncio
import json
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional
from urllib.parse import urlparse

from ..config import SUPPORTED_FORMATS, log
from ..http_client import scanner_http_get, scanner_http_post
from .base import ScannerProtocol

_PAPER_SIZES = {
    "A4": (210, 297),
    "Letter": (215.9, 279.4),
    "Legal": (215.9, 355.6),
}

_COLOR_MODES = {
    "color": "RGB24",
    "grayscale": "Grayscale8",
    "bw": "BlackAndWhite1",
}


class ESCLProtocol(ScannerProtocol):

    def is_available(self) -> bool:
        return True

    async def scan(
        self,
        ip: str,
        port: int,
        config: dict,
        scheme: str = "http",
        ws=None,
        request_id: Optional[str] = None,
        local_ip: str = "",
    ) -> dict:
        base_url = f"{scheme}://{ip}:{port}"
        scan_jobs_url = f"{base_url}/eSCL/ScanJobs"
        scanner_status_url = f"{base_url}/eSCL/ScannerStatus"
        caps_url = f"{base_url}/eSCL/ScannerCapabilities"
        loop = asyncio.get_event_loop()

        caps = None
        try:
            _, _, caps_body = await loop.run_in_executor(
                None, lambda: scanner_http_get(caps_url, local_ip=local_ip)
            )
            caps_xml = caps_body.decode("utf-8", errors="replace") if isinstance(caps_body, bytes) else caps_body
            if caps_xml and "ScannerCapabilities" in caps_xml:
                from ..discovery.escl import _parse_capabilities
                parsed = _parse_capabilities(caps_xml, ip, port)
                caps = parsed.get("capabilities")
                log.info(f"[eSCL] Capabilities fetched: version={caps.get('version')} resolutions={caps.get('resolutions')} color_modes_raw={caps.get('color_modes_raw')}")
        except Exception as e:
            log.warning(f"[eSCL] Could not fetch capabilities: {e}")

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

        raw_xml_override = config.get("raw_xml")
        if raw_xml_override:
            log.info("[eSCL] Using raw XML override from config")
            settings_xml = raw_xml_override
            format_type = config.get("format", "jpeg").lower()
        elif caps:
            settings_xml, format_type = self._build_settings_xml_from_caps(config, caps)
            log.info("[eSCL] Using caps-derived XML")
        else:
            settings_xml, format_type = self._build_settings_xml(config)
            log.info("[eSCL] Using default XML (no caps available)")

        job_uri = None
        image_data = None
        max_job_retries = 12
        max_wait = 10
        webscan_disabled = False

        log.info(f"[eSCL] Creating scan job at {scan_jobs_url}")

        for job_attempt in range(max_job_retries):
            status, location, body = await loop.run_in_executor(
                None, lambda: scanner_http_post(scan_jobs_url, settings_xml, local_ip=local_ip)
            )
            if status in (200, 201, 202):
                if location:
                    job_uri = urlparse(location).path if location.startswith("http") else location
                    log.info(f"[eSCL] Job created: {job_uri}")
                break
            if status == 400:
                body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body or "")
                if job_attempt == 0 and not raw_xml_override:
                    log.warning(f"[eSCL] HTTP 400 — caps-derived XML rejected. Body: {body_text[:500]}")
                    log.info("[eSCL] Retrying with minimal fallback XML...")
                    settings_xml = self._build_minimal_xml(config)
                    continue
                if job_attempt == 1 and not body_text.strip():
                    webscan_disabled = True
                raise Exception(
                    "WEBSCAN_DISABLED: Web scan is disabled on this printer. "
                    "Enable it via the printer web interface: open http://"
                    f"{ip}:{port} → Scan tab → Webscan → Enable Webscan."
                    if webscan_disabled else
                    f"[eSCL] Failed to create scan job: HTTP 400"
                )
            if status == 503:
                log.info(f"[eSCL] Scanner busy (503), checking existing job (attempt {job_attempt+1}/{max_job_retries})...")
                await _send_progress("busy", f"Scanner busy (attempt {job_attempt+1}/{max_job_retries})...")
                s_status, _, s_body = await loop.run_in_executor(
                    None, lambda: scanner_http_get(scanner_status_url, local_ip=local_ip)
                )
                s_body = s_body if isinstance(s_body, bytes) else s_body.encode()
                if s_status == 200:
                    job_info = self._parse_status(s_body)
                    if job_info.get("state") in ("Processing", "Pending") and job_info.get("uri"):
                        job_uri = job_info["uri"]
                        if job_uri.startswith("http"):
                            job_uri = urlparse(job_uri).path
                        log.info(f"[eSCL] Found existing job after 503: {job_uri}")
                        await _send_progress("scanning", "Resuming existing scan job...")
                        break
                if job_attempt < max_job_retries - 1:
                    wait_time = min(3 + job_attempt * 2, max_wait)
                    await _send_progress("retrying", f"Scanner busy — retrying in {wait_time}s ({job_attempt+1}/{max_job_retries})...")
                    await asyncio.sleep(wait_time)
            else:
                raise Exception(f"[eSCL] Failed to create scan job: HTTP {status}")

        if not job_uri:
            raise Exception("Scanner is busy and no existing job found. Please wait and try again.")

        for attempt in range(120):
            await asyncio.sleep(1)
            s_status, _, s_body = await loop.run_in_executor(
                None, lambda: scanner_http_get(scanner_status_url, local_ip=local_ip)
            )
            s_body = s_body if isinstance(s_body, bytes) else s_body.encode()
            if s_status == 200:
                job_info = self._parse_status(s_body)
                if job_info.get("uri") == job_uri:
                    state = job_info.get("state", "Unknown")
                    completed = job_info.get("completed", 0)
                    to_transfer = job_info.get("to_transfer", 0)
                    log.info(f"[eSCL] Poll {attempt+1}: state={state} {completed}/{to_transfer} images")
                    if state in ("Completed", "Processing") and to_transfer > 0 and not image_data:
                        dl_url = f"{base_url}{job_uri}/NextDocument"
                        _, _, dl_body = await loop.run_in_executor(
                            None, lambda: scanner_http_get(dl_url, local_ip=local_ip, timeout=60)
                        )
                        if len(dl_body) > 1000:
                            image_data = dl_body
                            log.info(f"[eSCL] Image downloaded: {len(image_data)} bytes")
                            break
                    if state == "Completed" and image_data:
                        break
            if not image_data and attempt % 3 == 0:
                dl_url = f"{base_url}{job_uri}/NextDocument"
                try:
                    _, _, dl_body = await loop.run_in_executor(
                        None, lambda: scanner_http_get(dl_url, local_ip=local_ip, timeout=60)
                    )
                    if len(dl_body) > 1000:
                        image_data = dl_body
                        log.info(f"[eSCL] Image downloaded: {len(image_data)} bytes")
                        break
                except Exception:
                    pass

        if not image_data:
            raise Exception("Scan did not complete or no image available")

        ext = ".pdf" if format_type == "pdf" else ".jpg"
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            f.write(image_data)
            temp_path = f.name

        log.info(f"[eSCL] Scan saved to {temp_path} ({len(image_data)} bytes)")
        return {"file_path": temp_path, "file_size": len(image_data), "format": format_type}

    def _build_settings_xml_from_caps(self, config: dict, caps: dict) -> tuple:
        _color_map_ui_to_raw = {
            "color": "RGB24",
            "grayscale": "Grayscale8",
            "bw": "BlackAndWhite1",
        }
        version = caps.get("version", "2.0")
        requested_res = config.get("resolution", 300)
        available_res = caps.get("resolutions", [300])
        resolution = min(available_res, key=lambda r: abs(r - requested_res))

        color_mode_ui = config.get("color_mode", "color")
        raw_color_modes = caps.get("color_modes_raw", ["RGB24"])
        preferred_raw = _color_map_ui_to_raw.get(color_mode_ui, "RGB24")
        input_color = preferred_raw if preferred_raw in raw_color_modes else raw_color_modes[0]

        raw_format = config.get("format", "jpeg").lower()
        doc_format = "application/pdf" if raw_format == "pdf" else "image/jpeg"
        supported_formats = caps.get("supported_formats", ["image/jpeg"])
        if doc_format not in supported_formats:
            doc_format = supported_formats[0]
        format_type = "pdf" if doc_format == "application/pdf" else "jpeg"

        duplex = config.get("duplex", False)
        has_adf = caps.get("adf") is not None
        input_source = "ADF" if (duplex and has_adf) else "Platen"

        intents = caps.get("intents", [])
        intent_line = "    <scan:Intent>Document</scan:Intent>" if "Document" in intents else ""

        platen = caps.get("platen")
        scan_region_block = ""
        if platen and platen.get("max_width") and platen.get("max_height"):
            paper_size = config.get("paper_size", "Letter")
            _paper_mm = {"A4": (210, 297), "Letter": (215.9, 279.4), "Legal": (215.9, 355.6)}
            width_mm, height_mm = _paper_mm.get(paper_size, (215.9, 279.4))
            width_px = min(int(width_mm / 25.4 * resolution), platen["max_width"])
            height_px = min(int(height_mm / 25.4 * resolution), platen["max_height"])
            scan_region_block = f'''    <pwg:ScanRegions mustHonor="false">
        <pwg:ScanRegion>
            <pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>
            <pwg:Height>{height_px}</pwg:Height>
            <pwg:Width>{width_px}</pwg:Width>
            <pwg:XOffset>0</pwg:XOffset>
            <pwg:YOffset>0</pwg:YOffset>
        </pwg:ScanRegion>
    </pwg:ScanRegions>'''

        parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<scan:ScanSettings xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03" xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm">',
            f'    <pwg:Version>{version}</pwg:Version>',
        ]
        if intent_line:
            parts.append(intent_line)
        parts += [
            f'    <scan:InputSource>{input_source}</scan:InputSource>',
            f'    <scan:ColorMode>{input_color}</scan:ColorMode>',
            f'    <scan:XResolution>{resolution}</scan:XResolution>',
            f'    <scan:YResolution>{resolution}</scan:YResolution>',
        ]
        if scan_region_block:
            parts.append(scan_region_block)
        parts += [
            f'    <scan:DocumentFormat>{doc_format}</scan:DocumentFormat>',
            f'    <scan:DocumentFormatExt>{doc_format}</scan:DocumentFormatExt>',
            '</scan:ScanSettings>',
        ]
        return "\n".join(parts), format_type

    def _build_settings_xml(self, config: dict) -> tuple:
        resolution = config.get("resolution", 300)
        color_mode = config.get("color_mode", "color")
        paper_size = config.get("paper_size", "A4")
        duplex = config.get("duplex", False)
        raw_format = config.get("format", "jpeg").lower()
        format_type = raw_format if raw_format in SUPPORTED_FORMATS else "jpeg"
        width_mm, height_mm = _PAPER_SIZES.get(paper_size, (210, 297))
        input_color = _COLOR_MODES.get(color_mode, "RGB24")
        input_source = "ADF" if duplex else "Platen"
        doc_format = "application/pdf" if format_type == "pdf" else "image/jpeg"
        width_px = int(width_mm / 25.4 * resolution)
        height_px = int(height_mm / 25.4 * resolution)
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<scan:ScanSettings xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03" xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm">
    <pwg:Version>2.0</pwg:Version>
    <scan:Intent>Document</scan:Intent>
    <scan:InputSource>{input_source}</scan:InputSource>
    <scan:ColorMode>{input_color}</scan:ColorMode>
    <scan:XResolution>{resolution}</scan:XResolution>
    <scan:YResolution>{resolution}</scan:YResolution>
    <pwg:ScanRegions mustHonor="false">
        <pwg:ScanRegion>
            <pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>
            <pwg:Height>{height_px}</pwg:Height>
            <pwg:Width>{width_px}</pwg:Width>
            <pwg:XOffset>0</pwg:XOffset>
            <pwg:YOffset>0</pwg:YOffset>
        </pwg:ScanRegion>
    </pwg:ScanRegions>
    <scan:DocumentFormat>{doc_format}</scan:DocumentFormat>
    <scan:DocumentFormatExt>{doc_format}</scan:DocumentFormatExt>
</scan:ScanSettings>'''
        return xml, format_type

    def _build_minimal_xml(self, config: dict) -> str:
        resolution = config.get("resolution", 300)
        color_mode = config.get("color_mode", "color")
        raw_format = config.get("format", "jpeg").lower()
        input_color = _COLOR_MODES.get(color_mode, "RGB24")
        doc_format = "application/pdf" if raw_format == "pdf" else "image/jpeg"
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<scan:ScanSettings xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03" xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm">
    <pwg:Version>2.0</pwg:Version>
    <scan:InputSource>Platen</scan:InputSource>
    <scan:ColorMode>{input_color}</scan:ColorMode>
    <scan:XResolution>{resolution}</scan:XResolution>
    <scan:YResolution>{resolution}</scan:YResolution>
    <scan:DocumentFormat>{doc_format}</scan:DocumentFormat>
</scan:ScanSettings>'''

    def _parse_status(self, body: bytes) -> dict:
        job_info = {}
        try:
            root = ET.fromstring(body.decode("utf-8", errors="replace"))
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
        except Exception:
            pass
        return job_info
