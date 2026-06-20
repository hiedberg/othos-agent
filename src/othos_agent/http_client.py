import platform
import subprocess

import httpx

from .config import log

_IS_WINDOWS = platform.system() == "Windows"
_ROUTING_ERRORS = (
    "No route to host",
    "All connection attempts failed",
    "Network is unreachable",
    "ConnectError",
)


def _needs_interface_binding(exc: Exception) -> bool:
    msg = str(exc)
    return any(e in msg for e in _ROUTING_ERRORS)


def _parse_curl_response(raw: bytes) -> tuple:
    header_end = raw.find(b"\r\n\r\n")
    if header_end == -1:
        header_end = raw.find(b"\n\n")
        body = raw[header_end + 2:] if header_end != -1 else raw
    else:
        body = raw[header_end + 4:]
    header_text = raw[:header_end].decode("utf-8", errors="replace") if header_end != -1 else ""
    status = 0
    for line in header_text.splitlines():
        if line.startswith("HTTP/"):
            try:
                status = int(line.split()[1])
            except Exception:
                pass
            break
    return status, header_text, body


def _curl_get(url: str, local_ip: str = "", timeout: int = 30) -> tuple:
    cmd = ["curl", "-sS", "-D", "-", "--max-time", str(timeout)]
    if local_ip and not _IS_WINDOWS:
        cmd += ["--interface", local_ip]
    cmd.append(url)
    result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
    if result.returncode != 0:
        raise Exception(f"curl GET {url} failed (exit {result.returncode}): {result.stderr.decode().strip()}")
    return _parse_curl_response(result.stdout)


def _curl_post(url: str, data: str, content_type: str = "application/xml", local_ip: str = "", timeout: int = 30) -> tuple:
    cmd = [
        "curl", "-sS", "-D", "-", "--max-time", str(timeout),
        "-X", "POST", "-H", f"Content-Type: {content_type}", "--data-binary", data,
    ]
    if local_ip and not _IS_WINDOWS:
        cmd += ["--interface", local_ip]
    cmd.append(url)
    result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
    if result.returncode != 0:
        raise Exception(f"curl POST {url} failed (exit {result.returncode}): {result.stderr.decode().strip()}")
    status, header_text, body = _parse_curl_response(result.stdout)
    location = None
    for line in header_text.splitlines():
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
    return status, location, body


def _httpx_get_sync(url: str, timeout: int = 30) -> tuple:
    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    return response.status_code, "", response.content


def _httpx_post_sync(url: str, data: str, content_type: str = "application/xml", timeout: int = 30) -> tuple:
    response = httpx.post(
        url,
        content=data.encode(),
        headers={"Content-Type": content_type},
        timeout=timeout,
        follow_redirects=False,
    )
    location = response.headers.get("location")
    return response.status_code, location, response.content


def scanner_http_get(url: str, local_ip: str = "", timeout: int = 30) -> tuple:
    try:
        return _httpx_get_sync(url, timeout=timeout)
    except Exception as exc:
        if not _IS_WINDOWS and _needs_interface_binding(exc):
            log.debug(f"httpx GET failed ({exc}), retrying via curl --interface {local_ip}")
            return _curl_get(url, local_ip=local_ip, timeout=timeout)
        raise


def scanner_http_post(url: str, data: str, content_type: str = "application/xml", local_ip: str = "", timeout: int = 30) -> tuple:
    try:
        return _httpx_post_sync(url, data, content_type=content_type, timeout=timeout)
    except Exception as exc:
        if not _IS_WINDOWS and _needs_interface_binding(exc):
            log.debug(f"httpx POST failed ({exc}), retrying via curl --interface {local_ip}")
            return _curl_post(url, data, content_type=content_type, local_ip=local_ip, timeout=timeout)
        raise
