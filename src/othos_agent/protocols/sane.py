import asyncio
import tempfile
from typing import Optional

from ..config import log
from .base import ScannerProtocol

try:
    import sane as _sane_lib
    _SANE_AVAILABLE = True
except ImportError:
    _SANE_AVAILABLE = False


class SANEProtocol(ScannerProtocol):

    def is_available(self) -> bool:
        return _SANE_AVAILABLE

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
        if not _SANE_AVAILABLE:
            raise RuntimeError("SANE is not available on this machine. Install python-sane: pip3 install python-sane")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._scan_blocking(ip, config))

    def _scan_blocking(self, ip: str, config: dict) -> dict:
        resolution = config.get("resolution", 300)
        color_mode = config.get("color_mode", "color")
        raw_format = config.get("format", "jpeg").lower()
        format_type = raw_format if raw_format in {"jpeg", "jpg", "png", "tiff", "pdf"} else "jpeg"

        _sane_lib.init()
        devices = _sane_lib.get_devices()
        log.info(f"[SANE] Available devices: {devices}")

        device_name = None
        for dev in devices:
            if ip in str(dev):
                device_name = dev[0]
                break
        if not device_name:
            if devices:
                device_name = devices[0][0]
                log.info(f"[SANE] IP {ip} not found in devices — using first available: {device_name}")
            else:
                raise Exception("[SANE] No SANE devices found on this machine")

        scanner = _sane_lib.open(device_name)
        try:
            scanner.resolution = resolution
            if color_mode == "color":
                scanner.mode = "Color"
            elif color_mode == "grayscale":
                scanner.mode = "Gray"
            else:
                scanner.mode = "Lineart"

            log.info(f"[SANE] Scanning with device={device_name} resolution={resolution} mode={scanner.mode}")
            image = scanner.scan()
        finally:
            scanner.close()
            _sane_lib.exit()

        ext = ".png" if format_type in {"png"} else ".jpg"
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            image.save(f.name)
            temp_path = f.name

        import os
        file_size = os.path.getsize(temp_path)
        log.info(f"[SANE] Scan saved to {temp_path} ({file_size} bytes)")
        return {"file_path": temp_path, "file_size": file_size, "format": format_type}
