import asyncio
import platform
import tempfile
from typing import Optional

from ..config import log
from .base import ScannerProtocol

_IS_WINDOWS = platform.system() == "Windows"

try:
    if _IS_WINDOWS:
        import win32com.client as _win32com
        _WIA_AVAILABLE = True
    else:
        _WIA_AVAILABLE = False
except ImportError:
    _WIA_AVAILABLE = False


class WIAProtocol(ScannerProtocol):

    def is_available(self) -> bool:
        return _WIA_AVAILABLE

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
        if not _IS_WINDOWS:
            raise RuntimeError("[WIA] WIA is only available on Windows")
        if not _WIA_AVAILABLE:
            raise RuntimeError("[WIA] pywin32 is not installed. Run: pip3 install pywin32")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._scan_blocking(config))

    def _scan_blocking(self, config: dict) -> dict:
        resolution = config.get("resolution", 300)
        raw_format = config.get("format", "jpeg").lower()
        format_type = raw_format if raw_format in {"jpeg", "jpg", "png", "tiff", "pdf"} else "jpeg"

        wia = _win32com.Dispatch("WIA.DeviceManager")
        devices = wia.DeviceInfos

        if devices.Count == 0:
            raise Exception("[WIA] No WIA devices found on this machine")

        device_info = devices.Item(1)
        device = device_info.Connect()
        log.info(f"[WIA] Connected to device: {device_info.Properties('Name').Value}")

        scanner_item = device.Items(1)

        wia_format_map = {
            "jpeg": "{B96B3CAE-0728-11D3-9D7B-0000F81EF32E}",
            "jpg": "{B96B3CAE-0728-11D3-9D7B-0000F81EF32E}",
            "png": "{B96B3CAF-0728-11D3-9D7B-0000F81EF32E}",
            "tiff": "{B96B3CB1-0728-11D3-9D7B-0000F81EF32E}",
        }
        wia_format = wia_format_map.get(format_type, wia_format_map["jpeg"])

        image_file = device.Transfer(wia_format)

        ext = ".png" if format_type == "png" else ".jpg"
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            temp_path = f.name

        image_file.SaveFile(temp_path)

        import os
        file_size = os.path.getsize(temp_path)
        log.info(f"[WIA] Scan saved to {temp_path} ({file_size} bytes)")
        return {"file_path": temp_path, "file_size": file_size, "format": format_type}
