"""
DNSBL (DNS-based Blackhole Lists) — Free, no key required.
Checks the IP against major spam/abuse blacklists using standard DNS lookups.
Each check = one DNS A record query on the reversed IP + DNSBL zone.
"""

import asyncio
import dns.resolver

# (zone, display_name, category)
DNSBLS = [
    ("zen.spamhaus.org",         "Spamhaus ZEN",      "spam/exploits"),
    ("bl.spamcop.net",           "SpamCop",           "spam"),
    ("dnsbl.sorbs.net",          "SORBS",             "spam/abuse"),
    ("b.barracudacentral.org",   "Barracuda",         "spam"),
    ("psbl.surriel.com",         "PSBL",              "spam"),
    ("dnsbl-1.uceprotect.net",   "UCEPROTECT L1",     "spam"),
    ("cbl.abuseat.org",          "CBL",               "malware/botnet"),
    ("drone.abuse.ch",           "abuse.ch Drone",    "botnet"),
]


def _reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _check_sync(reversed_ip: str, zone: str) -> bool:
    """Synchronous DNS check — runs in thread pool via run_in_executor."""
    try:
        dns.resolver.resolve(f"{reversed_ip}.{zone}", "A", lifetime=4)
        return True   # Listed
    except Exception:
        return False  # Not listed or timeout


async def fetch(ip: str, _client=None) -> dict:
    """
    _client is accepted but unused — keeps signature compatible with other sources.
    All DNS queries run in parallel via thread pool.
    """
    reversed_ip = _reverse_ip(ip)
    loop = asyncio.get_event_loop()

    # Run all DNSBL checks in parallel (DNS is blocking I/O → thread pool)
    tasks = [
        loop.run_in_executor(None, _check_sync, reversed_ip, zone)
        for zone, _, _ in DNSBLS
    ]
    results = await asyncio.gather(*tasks)

    listed = [
        {"name": name, "zone": zone, "category": category}
        for (zone, name, category), hit in zip(DNSBLS, results)
        if hit
    ]

    return {
        "source": "dnsbl",
        "ip": ip,
        "listed_count": len(listed),
        "checked_count": len(DNSBLS),
        "listed_on": listed,
    }
