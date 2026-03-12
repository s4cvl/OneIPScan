"""
ip-api.com — Free, no key required.
Returns geo, ASN, ISP, org, hostname, timezone.
"""

import httpx

BASE_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"


async def fetch(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(BASE_URL.format(ip=ip), timeout=8)
        data = resp.json()

        if data.get("status") != "success":
            return {"source": "ip-api", "error": data.get("message", "Unknown error")}

        return {
            "source": "ip-api",
            "ip": data.get("query"),
            "country": f"{data.get('country')} ({data.get('countryCode')})",
            "region": data.get("regionName"),
            "city": data.get("city"),
            "zip": data.get("zip"),
            "coords": f"{data.get('lat')}, {data.get('lon')}",
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "asn_name": data.get("asname"),
            "hostname": data.get("reverse") or "N/A",
        }

    except Exception as e:
        return {"source": "ip-api", "error": str(e)}
