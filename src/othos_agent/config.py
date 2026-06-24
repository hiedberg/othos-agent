import logging

VERSION = "1.0.0"
HEARTBEAT_INTERVAL = 30
DISCOVERY_INTERVAL = 120
ESCL_PATHS = ["/eSCL/ScannerCapabilities", "/escl/ScannerCapabilities"]
ESCL_PORTS = [80, 8080, 443]
HINT_PROBE_TIMEOUT = 5.0
RECONNECT_DELAY = 5
SUPPORTED_FORMATS = {"jpeg", "jpg", "pdf", "png", "tiff"}
SUBNET_SCAN_MAX_PREFIX = 16
SUBNET_SCAN_BATCH_SIZE = 50
MDNS_TIMEOUT = 5.0
SCANNER_MDNS_SERVICES = ["_uscan._tcp.local.", "_uscans._tcp.local.", "_scanner._tcp.local.", "_pdl-datastream._tcp.local."]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("othos-agent")
