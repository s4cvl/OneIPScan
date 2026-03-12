"""
Shodan — Tries paid Shodan API first (full data: ports, services, OS, CVEs).
Falls back to Shodan InternetDB (free, no key) for ports, tags, and vulns.
"""

import httpx
import os

SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"


async def fetch(ip: str, client: httpx.AsyncClient) -> dict:
    api_key = os.getenv("SHODAN_API_KEY")

    # Try paid Shodan API first if key is available
    if api_key:
        result = await _fetch_shodan(ip, client, api_key)
        if "error" not in result:
            return result
        # Fall through to InternetDB on any error (403, 404, network, etc.)

    # Fallback: Shodan InternetDB (free, no key required)
    return await _fetch_internetdb(ip, client)


async def _fetch_shodan(ip: str, client: httpx.AsyncClient, api_key: str) -> dict:
    try:
        resp = await client.get(
            SHODAN_URL.format(ip=ip),
            params={"key": api_key},
            timeout=10,
        )

        if resp.status_code == 404:
            return {"source": "shodan", "error": "not found"}

        if resp.status_code != 200:
            return {"source": "shodan", "error": f"HTTP {resp.status_code}"}

        d = resp.json()

        ports = []
        for service in d.get("data", []):
            ports.append({
                "port": service.get("port"),
                "transport": service.get("transport", "tcp"),
                "product": service.get("product") or service.get("_shodan", {}).get("module", "unknown"),
                "version": service.get("version") or "",
            })

        vulns = list(d.get("vulns", {}).keys()) if d.get("vulns") else []

        return {
            "source": "shodan",
            "backend": "shodan-api",
            "ip": d.get("ip_str"),
            "os": d.get("os") or "Unknown",
            "hostnames": d.get("hostnames", []),
            "domains": d.get("domains", []),
            "tags": d.get("tags", []),
            "org": d.get("org") or "N/A",
            "isp": d.get("isp") or "N/A",
            "asn": d.get("asn") or "N/A",
            "country": d.get("country_name") or "N/A",
            "last_update": d.get("last_update") or "N/A",
            "open_ports": ports,
            "port_count": len(ports),
            "vulns": vulns,
            "vuln_count": len(vulns),
        }

    except Exception as e:
        return {"source": "shodan", "error": str(e)}


async def _fetch_internetdb(ip: str, client: httpx.AsyncClient) -> dict:
    """
    Shodan InternetDB — https://internetdb.shodan.io/
    Free, no key. Returns ports, hostnames, CPEs, tags, vulns.
    Less detail than paid API (no service banners, no OS, no org).
    """
    try:
        resp = await client.get(INTERNETDB_URL.format(ip=ip), timeout=8)

        if resp.status_code == 404:
            return {
                "source": "shodan",
                "backend": "internetdb (free fallback)",
                "ip": ip,
                "os": "Unknown",
                "hostnames": [],
                "domains": [],
                "tags": [],
                "org": "N/A",
                "isp": "N/A",
                "asn": "N/A",
                "country": "N/A",
                "last_update": "N/A",
                "open_ports": [],
                "port_count": 0,
                "vulns": [],
                "vuln_count": 0,
                "note": "No data in Shodan InternetDB",
            }

        if resp.status_code != 200:
            return {"source": "shodan", "error": f"InternetDB HTTP {resp.status_code}"}

        d = resp.json()

        # InternetDB returns plain port numbers — normalize to match paid format
        ports = [{"port": p, "transport": "tcp", "product": "unknown", "version": ""} for p in d.get("ports", [])]
        vulns = d.get("vulns", [])

        return {
            "source": "shodan",
            "backend": "internetdb (free fallback)",
            "ip": ip,
            "os": "Unknown",
            "hostnames": d.get("hostnames", []),
            "domains": [],
            "tags": d.get("tags", []),
            "cpes": d.get("cpes", []),
            "org": "N/A",
            "isp": "N/A",
            "asn": "N/A",
            "country": "N/A",
            "last_update": "N/A",
            "open_ports": ports,
            "port_count": len(ports),
            "vulns": vulns,
            "vuln_count": len(vulns),
        }

    except Exception as e:
        return {"source": "shodan", "error": f"InternetDB error: {str(e)}"}
