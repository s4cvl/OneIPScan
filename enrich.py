#!/usr/bin/env python3
"""
IP Enrichment Tool
Queries ip-api, AbuseIPDB, Shodan, VirusTotal, DNSBLs, and AlienVault OTX in parallel.

Usage:
  python enrich.py 1.2.3.4
  python enrich.py 1.2.3.4 --json
  python enrich.py 1.2.3.4 --batch ips.txt

Importable (for bots/web apps):
  from enrich import enrich_ip
  result = await enrich_ip("1.2.3.4")
"""

import asyncio
import argparse
import sys
import ipaddress
from pathlib import Path
from dotenv import load_dotenv

import httpx

from sources import ipapi, abuseipdb, shodan, virustotal, dnsbl, otx
from output import formatter

# Load .env from the same directory as this script
load_dotenv(Path(__file__).parent / ".env")


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


async def enrich_ip(ip: str) -> dict:
    """
    Core enrichment function. Returns a dict with results from all sources.
    All sources run in parallel. Call this directly when integrating with a bot or web app.
    """
    async with httpx.AsyncClient() as client:
        tasks = [
            ipapi.fetch(ip, client),
            abuseipdb.fetch(ip, client),
            shodan.fetch(ip, client),
            virustotal.fetch(ip, client),
            dnsbl.fetch(ip, client),   # DNS-based, uses thread pool internally
            otx.fetch(ip, client),
        ]
        results_list = await asyncio.gather(*tasks)

    return {r["source"]: r for r in results_list}


async def enrich_batch(ips: list[str], output_json: bool):
    for ip in ips:
        ip = ip.strip()
        if not ip or ip.startswith("#"):
            continue
        if not is_valid_ip(ip):
            formatter.console.print(f"[yellow]Skipping invalid IP: {ip}[/yellow]")
            continue
        results = await enrich_ip(ip)
        if output_json:
            formatter.print_json(ip, results)
        else:
            formatter.print_rich(ip, results)


async def main():
    parser = argparse.ArgumentParser(
        description="Enrich an IP address using ip-api, AbuseIPDB, Shodan, VirusTotal, DNSBLs, and AlienVault OTX."
    )
    parser.add_argument("ip", nargs="?", help="IP address to enrich")
    parser.add_argument("--json", action="store_true", help="Output as JSON (pipe-friendly)")
    parser.add_argument("--batch", metavar="FILE", help="File with one IP per line")
    args = parser.parse_args()

    # Batch mode
    if args.batch:
        batch_file = Path(args.batch)
        if not batch_file.exists():
            print(f"Error: file not found: {args.batch}", file=sys.stderr)
            sys.exit(1)
        raw = batch_file.read_bytes()
        # Handle BOMs: UTF-16 LE/BE (PowerShell default) and UTF-8 BOM
        if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
            text = raw.decode('utf-16')
        elif raw.startswith(b'\xef\xbb\xbf'):
            text = raw.decode('utf-8-sig')
        else:
            text = raw.decode('utf-8')
        ips = text.splitlines()
        await enrich_batch(ips, args.json)
        return

    # Single IP mode
    if not args.ip:
        parser.print_help()
        sys.exit(1)

    if not is_valid_ip(args.ip):
        print(f"Error: '{args.ip}' is not a valid IP address.", file=sys.stderr)
        sys.exit(1)

    results = await enrich_ip(args.ip)

    if args.json:
        formatter.print_json(args.ip, results)
    else:
        formatter.print_rich(args.ip, results)


if __name__ == "__main__":
    asyncio.run(main())
