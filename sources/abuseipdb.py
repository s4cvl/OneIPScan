"""
AbuseIPDB — Requires API key (free tier: 1000 checks/day).
Returns abuse confidence score, total reports, last report date, usage type.
"""

import httpx
import os

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


async def fetch(ip: str, client: httpx.AsyncClient) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {"source": "abuseipdb", "error": "No API key (set ABUSEIPDB_API_KEY in .env)"}

    try:
        resp = await client.get(
            BASE_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=8,
        )

        if resp.status_code != 200:
            return {"source": "abuseipdb", "error": f"HTTP {resp.status_code}"}

        d = resp.json().get("data", {})

        score = d.get("abuseConfidenceScore", 0)

        return {
            "source": "abuseipdb",
            "ip": d.get("ipAddress"),
            "abuse_score": score,
            "abuse_score_label": _score_label(score),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt") or "Never",
            "usage_type": d.get("usageType") or "Unknown",
            "isp": d.get("isp"),
            "domain": d.get("domain") or "N/A",
            "is_tor": d.get("isTor", False),
            "is_whitelisted": d.get("isWhitelisted", False),
            "country": d.get("countryCode"),
        }

    except Exception as e:
        return {"source": "abuseipdb", "error": str(e)}


def _score_label(score: int) -> str:
    if score == 0:
        return "Clean"
    elif score < 25:
        return "Low risk"
    elif score < 75:
        return "Suspicious"
    else:
        return "Malicious"
