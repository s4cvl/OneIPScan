# OneIPScan

IP reputation and enrichment tool for sysadmins. Query an IP address across 6 sources in parallel and get a unified report — from the CLI, a web UI, or directly from your own scripts and bots.

Part of the **One** suite of sysadmin tools.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Sources

| Source | What it provides | Auth |
|---|---|---|
| [ip-api](https://ip-api.com) | Geo, ASN, ISP, hostname | Free, no key |
| [AbuseIPDB](https://www.abuseipdb.com) | Abuse score, reports, TOR flag | API key (free tier) |
| [Shodan](https://shodan.io) / [InternetDB](https://internetdb.shodan.io) | Open ports, services, CVEs | API key (paid) / free fallback |
| [VirusTotal](https://www.virustotal.com) | Multi-vendor AV consensus (94 engines) | API key (free tier) |
| DNSBL | Spam/abuse blacklist checks (8 lists) | Free, no key |
| [AlienVault OTX](https://otx.alienvault.com) | Threat intelligence pulses | API key (free) |

## Requirements

- Python 3.10+
- API keys for: AbuseIPDB, VirusTotal, AlienVault OTX
- Optional: Shodan paid key (falls back to InternetDB automatically)

## Installation

```bash
git clone https://github.com/s4cvl/OneIPScan.git
cd OneIPScan

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS

pip install -r requirements.txt

cp .env.example .env
# Edit .env and fill in your API keys
```

## Usage

### CLI

```bash
# Single IP
python enrich.py 1.2.3.4

# JSON output (pipe-friendly)
python enrich.py 1.2.3.4 --json

# Batch from file (one IP per line)
python enrich.py --batch ips.txt
```

### Web UI

```bash
python web/app.py
# → http://localhost:8080
```

Accessible from any machine on the LAN at `http://<your-ip>:8080`.

Features: IP search, 6 source cards with color-coded verdicts, lookup history, JSON export.

### As a library (bots, scripts)

```python
from enrich import enrich_ip

result = await enrich_ip("1.2.3.4")
# result["ip-api"], result["abuseipdb"], result["shodan"],
# result["virustotal"], result["dnsbl"], result["otx"]
```

## API Keys

| Service | Free tier | Link |
|---|---|---|
| AbuseIPDB | 1,000 checks/day | https://www.abuseipdb.com/register |
| VirusTotal | 500/day, 4/min | https://www.virustotal.com/gui/join-us |
| AlienVault OTX | Unlimited | https://otx.alienvault.com |
| Shodan | Limited (InternetDB fallback if missing) | https://account.shodan.io/register |

## Running as a Windows Service

See [Windows service setup](#) using NSSM:

```powershell
# Install NSSM, then:
nssm install OneIPScan "C:\path\to\venv\Scripts\python.exe" "web\app.py"
nssm set OneIPScan AppDirectory "C:\path\to\ip-enrichment"
nssm set OneIPScan Start SERVICE_AUTO_START
nssm start OneIPScan
```

Open port 8080 in Windows Firewall:
```powershell
netsh advfirewall firewall add rule name="OneIPScan" dir=in action=allow protocol=TCP localport=8080
```

## Project Structure

```
OneIPScan/
├── enrich.py              # CLI entry point + importable enrich_ip()
├── sources/
│   ├── ipapi.py           # ip-api.com
│   ├── abuseipdb.py       # AbuseIPDB
│   ├── shodan.py          # Shodan + InternetDB fallback
│   ├── virustotal.py      # VirusTotal
│   ├── dnsbl.py           # DNS blacklist checks
│   └── otx.py             # AlienVault OTX
├── output/
│   └── formatter.py       # Rich terminal + JSON output
├── web/
│   ├── app.py             # FastAPI server
│   └── static/
│       └── index.html     # Web UI
├── .env.example           # API key template
├── requirements.txt
└── start.bat              # NSSM service launcher
```

## License

MIT
