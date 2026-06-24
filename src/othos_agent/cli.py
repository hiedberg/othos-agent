import argparse
import asyncio
import sys

from .agent import run_agent
from .config import VERSION, log
from .network import get_all_local_subnets, get_local_ip, get_local_subnet
from .pairing import pair_agent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Othos Scanner Agent")
    parser.add_argument("--code", required=True, help="Pairing code from Othos settings")
    parser.add_argument("--server", default="https://api.othos.com", help="Othos server URL")
    parser.add_argument("--subnet", help="Subnet to scan (e.g. 192.168.1.0/24). Auto-detected if omitted.")
    parser.add_argument("--hint", action="append", dest="hints", metavar="IP", help="Known scanner IP(s) to probe first. Can be repeated.")
    parser.add_argument("--scanner", action="append", dest="scanners_direct", metavar="IP:PORT", help="Skip discovery — use known scanner IP:PORT directly. Can be repeated.")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification (development only)")
    parser.add_argument("--ca-bundle", dest="ca_bundle", help="Path to custom CA certificate bundle")
    parser.add_argument("--no-mdns", dest="no_mdns", action="store_true", help="Disable mDNS/Bonjour discovery (use subnet scan only)")
    return parser


async def _main():
    args = _build_parser().parse_args()

    print(f"""
╔══════════════════════════════════════╗
║         Othos Scanner Agent          ║
║         Version {VERSION:<22}║
╚══════════════════════════════════════╝
""")

    all_ifaces = get_all_local_subnets()
    if all_ifaces:
        log.info("Detected network interfaces:")
        for iface, ip, network in all_ifaces:
            log.info(f"  {iface:<12} {ip:<18} subnet: {network}")

    subnet = args.subnet or get_local_subnet()
    if not subnet:
        log.error(
            "Could not detect local subnet. "
            "Pass --subnet manually (e.g. --subnet 10.112.0.0/16)."
        )
        sys.exit(1)

    local_ip = get_local_ip()
    log.info(f"Using subnet: {subnet} (local IP: {local_ip})")
    if not args.subnet and len(all_ifaces) > 1:
        log.info(
            "Tip: scanner may be on a different interface. "
            "Pass --subnet <network> to scan a specific one."
        )
    log.info(f"Server: {args.server}")
    log.info("Pairing with Othos...")

    try:
        pair_data = await pair_agent(args.server, args.code, insecure=args.insecure, ca_bundle=args.ca_bundle)
    except RuntimeError as e:
        log.error(str(e))
        sys.exit(1)

    agent_id = pair_data["agent_id"]
    token = pair_data.get("token")
    log.info(f"Paired successfully — Agent ID: {agent_id}")
    log.info("Starting scanner discovery and tunnel...")

    if args.scanners_direct:
        log.info(f"Direct scanner mode — skipping subnet scan. Targets: {', '.join(args.scanners_direct)}")

    await run_agent(
        args.server, agent_id, subnet,
        local_ip=local_ip,
        hints=args.hints,
        scanners_direct=args.scanners_direct,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        token=token,
        no_mdns=args.no_mdns,
    )


def run():
    asyncio.run(_main())
