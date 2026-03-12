"""
VirusTotal — Requires API key (free tier: 500 lookups/day, 4/min).
Returns multi-vendor consensus: malicious, suspicious, harmless counts.
"""

import httpx
import os

BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


async def fetch(ip: str, client: httpx.AsyncClient) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {"source": "virustotal", "error": "No API key (set VIRUSTOTAL_API_KEY in .env)"}

    try:
        resp = await client.get(
            BASE_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=10,
        )

        if resp.status_code == 404:
            return {"source": "virustotal", "error": "IP not found in VirusTotal"}

        if resp.status_code == 429:
            return {"source": "virustotal", "error": "Rate limit reached (4 req/min on free tier)"}

        if resp.status_code != 200:
            return {"source": "virustotal", "error": f"HTTP {resp.status_code}"}

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious   = stats.get("malicious", 0)
        suspicious  = stats.get("suspicious", 0)
        harmless    = stats.get("harmless", 0)
        undetected  = stats.get("undetected", 0)
        total       = malicious + suspicious + harmless + undetected

        # Pull vendors that flagged it
        analysis = attrs.get("last_analysis_results", {})
        flagged_by = [
            vendor for vendor, result in analysis.items()
            if result.get("category") in ("malicious", "suspicious")
        ]

        return {
            "source": "virustotal",
            "ip": ip,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
            "verdict": _verdict(malicious, suspicious),
            "flagged_by": sorted(flagged_by),
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country", "N/A"),
            "asn": attrs.get("asn", "N/A"),
            "as_owner": attrs.get("as_owner", "N/A"),
            "last_analysis": attrs.get("last_modification_date", "N/A"),
        }

    except Exception as e:
        return {"source": "virustotal", "error": str(e)}


def _verdict(malicious: int, suspicious: int) -> str:
    if malicious >= 5:
        return "Malicious"
    elif malicious > 0:
        return "Likely malicious"
    elif suspicious > 0:
        return "Suspicious"
    else:
        return "Clean"
