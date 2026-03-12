"""
FastAPI web interface for the IP Enrichment Tool.
Binds to 0.0.0.0 — accessible from any machine on the LAN.

Usage:
  python web/app.py
  → Open http://<your-ip>:8000
"""

import sys
import os
from pathlib import Path

# Allow importing from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

import ipaddress
from fastapi import FastAPI, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from enrich import enrich_ip

app = FastAPI(title="IP Enrichment", docs_url=None, redoc_url=None)

# Serve static files (index.html, etc.)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/enrich")
async def enrich(ip: str = Query(..., description="IP address to enrich")):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{ip}' is not a valid IP address.")

    results = await enrich_ip(ip)
    return {"ip": ip, "results": results}


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    host = "0.0.0.0"
    port = 8000
    print(f"\n  IP Enrichment — Web UI")
    print(f"  Running on http://{host}:{port}")
    print(f"  LAN access: http://<your-ip>:{port}\n")
    uvicorn.run("app:app", host=host, port=port, reload=False, app_dir=str(Path(__file__).parent))
