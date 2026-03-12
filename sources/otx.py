"""
AlienVault OTX — Requires API key (free at otx.alienvault.com).
Returns threat intelligence pulses: community-reported IOC campaigns this IP appears in.
OTX API can be slow — retries up to 2 times with a 25s timeout each.
"""

import httpx
import os

BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

TIMEOUT   = 25   # seconds — OTX is notoriously slow
MAX_RETRY = 2


async def fetch(ip: str, client: httpx.AsyncClient) -> dict:
    api_key = os.getenv("OTX_API_KEY")

    if not api_key:
        return {"source": "otx", "error": "No API key (set OTX_API_KEY in .env)"}

    last_error = ""
    for attempt in range(1, MAX_RETRY + 1):
        try:
            resp = await client.get(
                BASE_URL.format(ip=ip),
                headers={"X-OTX-API-KEY": api_key},
                timeout=TIMEOUT,
            )

            if resp.status_code != 200:
                return {"source": "otx", "error": f"HTTP {resp.status_code}"}

            d = resp.json()

            pulse_info  = d.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)

            pulses      = pulse_info.get("pulses", [])
            pulse_names = [p.get("name", "") for p in pulses[:5]]
            all_tags    = list({tag for p in pulses for tag in p.get("tags", [])})[:10]

            return {
                "source": "otx",
                "ip": ip,
                "pulse_count": pulse_count,
                "verdict": _verdict(pulse_count),
                "pulse_names": pulse_names,
                "tags": all_tags,
                "reputation": d.get("reputation", 0),
                "country": d.get("country_name", "N/A"),
                "asn": d.get("asn", "N/A"),
            }

        except httpx.ReadTimeout:
            last_error = f"Timeout (attempt {attempt}/{MAX_RETRY})"
        except Exception as e:
            last_error = str(e) or type(e).__name__
            break  # Non-timeout errors — no point retrying

    return {"source": "otx", "error": f"OTX unreachable — {last_error}"}


def _verdict(pulse_count: int) -> str:
    if pulse_count == 0:
        return "Not in any threat campaign"
    elif pulse_count < 5:
        return f"In {pulse_count} pulse(s) — low"
    elif pulse_count < 20:
        return f"In {pulse_count} pulses — moderate"
    else:
        return f"In {pulse_count} pulses — high activity"
