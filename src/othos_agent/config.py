import logging

VERSION = "1.0.0"
HEARTBEAT_INTERVAL = 30
DISCOVERY_INTERVAL = 120
ESCL_PATHS = ["/eSCL/ScannerCapabilities", "/escl/ScannerCapabilities"]
ESCL_PORTS = [80, 8080, 443]
HINT_PROBE_TIMEOUT = 5.0
RECONNECT_DELAY = 5
SUPPORTED_FORMATS = {"jpeg", "jpg", "pdf", "png", "tiff"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("othos-agent")
