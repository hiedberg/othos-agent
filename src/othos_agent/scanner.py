import asyncio
import json
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional
from urllib.parse import urlparse

from .config import SUPPORTED_FORMATS, log
from .http_client import scanner_http_get, scanner_http_post

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


def _build_scan_settings_xml(config: dict) -> tuple[str, str]:
    resolution = config.get("resolution", 300)
    color_mode = config.get("color_mode", "color")
    paper_size = config.get("paper_size", "A4")
    duplex = config.get("duplex", False)
    raw_format = config.get("format", "jpeg").lower()
    format_type = raw_format if raw_format in SUPPORTED_FORMATS else "jpeg"

    width_mm, height_mm = _PAPER_SIZES.get(paper_size, (210, 297))
    input_color = _COLOR_MODES.get(color_mode, "RGB24")
    input_source = "ADF" if duplex else "Platen"

    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
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

    return xml, format_type


def _parse_scanner_status(body: bytes) -> dict:
    job_info = {}
    try:
        root = ET.fromstring(body.decode("utf-8", errors="replace"))
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "ScannerState":
                job_info["scanner_state"] = elem.text
            elif tag == "JobUri":
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
    base_url = f"{scheme}://{ip}:{port}"
    scan_jobs_url = f"{base_url}/eSCL/ScanJobs"
    scanner_status_url = f"{base_url}/eSCL/ScannerStatus"
    loop = asyncio.get_event_loop()

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

    settings_xml, format_type = _build_scan_settings_xml(config)

    job_uri = None
    image_data = None
    max_job_retries = 12
    max_wait = 10

    log.info(f"Creating scan job at {scan_jobs_url}")

    for job_attempt in range(max_job_retries):
        status, location, _ = await loop.run_in_executor(
            None, lambda: scanner_http_post(scan_jobs_url, settings_xml, local_ip=local_ip)
        )

        if status in (200, 201, 202):
            if location:
                job_uri = urlparse(location).path if location.startswith("http") else location
                log.info(f"Job created: {job_uri}")
            break

        if status == 503:
            log.info(f"Scanner busy (503), checking for existing job (attempt {job_attempt+1}/{max_job_retries})...")
            await _send_progress("busy", f"Scanner busy (attempt {job_attempt+1}/{max_job_retries})...")

            s_status, _, s_body = await loop.run_in_executor(
                None, lambda: scanner_http_get(scanner_status_url, local_ip=local_ip)
            )
            s_body = s_body if isinstance(s_body, bytes) else s_body.encode()
            if s_status == 200:
                job_info = _parse_scanner_status(s_body)
                if job_info.get("state") in ("Processing", "Pending") and job_info.get("uri"):
                    job_uri = job_info["uri"]
                    if job_uri.startswith("http"):
                        job_uri = urlparse(job_uri).path
                    log.info(f"Found existing job after 503: {job_uri}")
                    await _send_progress("scanning", "Resuming existing scan job...")
                    break

            if job_attempt < max_job_retries - 1:
                wait_time = min(3 + job_attempt * 2, max_wait)
                log.info(f"Scanner busy, waiting {wait_time}s before retry ({job_attempt+1}/{max_job_retries})...")
                await _send_progress("retrying", f"Scanner busy — retrying in {wait_time}s ({job_attempt+1}/{max_job_retries})...")
                await asyncio.sleep(wait_time)
        else:
            raise Exception(f"Failed to create scan job: HTTP {status}")

    if not job_uri:
        raise Exception("Scanner is busy and no existing job found. Please wait and try again.")

    for attempt in range(120):
        await asyncio.sleep(1)

        s_status, _, s_body = await loop.run_in_executor(
            None, lambda: scanner_http_get(scanner_status_url, local_ip=local_ip)
        )
        s_body = s_body if isinstance(s_body, bytes) else s_body.encode()

        if s_status == 200:
            job_info = _parse_scanner_status(s_body)
            if job_info.get("uri") == job_uri:
                state = job_info.get("state", "Unknown")
                completed = job_info.get("completed", 0)
                to_transfer = job_info.get("to_transfer", 0)
                log.info(f"Poll {attempt+1}: Job {job_uri} state={state} - {completed}/{to_transfer} images")

                if state in ("Completed", "Processing") and to_transfer > 0 and not image_data:
                    dl_url = f"{base_url}{job_uri}/NextDocument"
                    _, _, dl_body = await loop.run_in_executor(
                        None, lambda: scanner_http_get(dl_url, local_ip=local_ip, timeout=60)
                    )
                    if len(dl_body) > 1000:
                        image_data = dl_body
                        log.info(f"Image downloaded: {len(image_data)} bytes")
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
                    log.info(f"Image downloaded: {len(image_data)} bytes")
                    break
            except Exception:
                pass

    if not image_data:
        raise Exception("Scan did not complete or no image available")

    ext = ".pdf" if format_type == "pdf" else ".jpg"
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
        f.write(image_data)
        temp_path = f.name

    log.info(f"Scan saved to {temp_path} ({len(image_data)} bytes)")
    return {"file_path": temp_path, "file_size": len(image_data), "format": format_type}
