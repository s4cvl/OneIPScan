"""
Handles terminal (rich) and JSON output formatting.
"""

import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def _abuse_color(label: str) -> str:
    return {
        "Clean": "green",
        "Low risk": "yellow",
        "Suspicious": "dark_orange",
        "Malicious": "red",
    }.get(label, "white")


def _vt_color(verdict: str) -> str:
    return {
        "Clean": "green",
        "Suspicious": "dark_orange",
        "Likely malicious": "orange_red1",
        "Malicious": "red",
    }.get(verdict, "white")


def print_rich(ip: str, results: dict):
    geo        = results.get("ip-api", {})
    abuse      = results.get("abuseipdb", {})
    shodan_res = results.get("shodan", {})
    vt         = results.get("virustotal", {})
    dnsbl_res  = results.get("dnsbl", {})
    otx_res    = results.get("otx", {})

    console.print()
    console.rule(f"[bold cyan]IP Enrichment Report — {ip}[/bold cyan]")
    console.print()

    # --- GEO / NETWORK ---
    geo_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    geo_table.add_column("Field", style="dim")
    geo_table.add_column("Value")

    if "error" in geo:
        geo_table.add_row("Error", f"[red]{geo['error']}[/red]")
    else:
        geo_table.add_row("Location", f"{geo.get('city')}, {geo.get('region')}, {geo.get('country')}")
        geo_table.add_row("Coordinates", geo.get("coords", "N/A"))
        geo_table.add_row("Timezone", geo.get("timezone", "N/A"))
        geo_table.add_row("ISP", geo.get("isp", "N/A"))
        geo_table.add_row("Org", geo.get("org", "N/A"))
        geo_table.add_row("ASN", f"{geo.get('asn', 'N/A')} ({geo.get('asn_name', '')})")
        geo_table.add_row("Hostname", geo.get("hostname", "N/A"))

    console.print(Panel(geo_table, title="[bold]Geo / Network[/bold]", border_style="blue"))

    # --- ABUSE ---
    abuse_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    abuse_table.add_column("Field", style="dim")
    abuse_table.add_column("Value")

    if "error" in abuse:
        abuse_table.add_row("Status", f"[yellow]{abuse['error']}[/yellow]")
    else:
        label = abuse.get("abuse_score_label", "Unknown")
        color = _abuse_color(label)
        abuse_table.add_row("Abuse Score", f"[{color}]{abuse.get('abuse_score')}% — {label}[/{color}]")
        abuse_table.add_row("Total Reports", str(abuse.get("total_reports", 0)))
        abuse_table.add_row("Last Reported", abuse.get("last_reported", "N/A"))
        abuse_table.add_row("Usage Type", abuse.get("usage_type", "N/A"))
        abuse_table.add_row("Domain", abuse.get("domain", "N/A"))
        abuse_table.add_row("Is TOR", "Yes" if abuse.get("is_tor") else "No")
        abuse_table.add_row("Whitelisted", "Yes" if abuse.get("is_whitelisted") else "No")

    console.print(Panel(abuse_table, title="[bold]AbuseIPDB[/bold]", border_style="red"))

    # --- SHODAN ---
    shodan_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    shodan_table.add_column("Field", style="dim")
    shodan_table.add_column("Value")

    backend = shodan_res.get("backend", "shodan-api")
    shodan_title = "[bold]Shodan[/bold]"
    if "internetdb" in backend:
        shodan_title = "[bold]Shodan[/bold] [dim](InternetDB fallback — free)[/dim]"

    if "error" in shodan_res:
        shodan_table.add_row("Status", f"[yellow]{shodan_res['error']}[/yellow]")
    else:
        if shodan_res.get("note"):
            shodan_table.add_row("Note", f"[dim]{shodan_res['note']}[/dim]")

        shodan_table.add_row("OS", shodan_res.get("os", "Unknown"))
        shodan_table.add_row("Last Scan", shodan_res.get("last_update", "N/A"))
        shodan_table.add_row("Tags", ", ".join(shodan_res.get("tags", [])) or "None")
        shodan_table.add_row("Hostnames", ", ".join(shodan_res.get("hostnames", [])) or "None")

        if shodan_res.get("domains"):
            shodan_table.add_row("Domains", ", ".join(shodan_res["domains"]))

        if shodan_res.get("cpes"):
            shodan_table.add_row("CPEs", "\n".join(shodan_res["cpes"]))

        port_count = shodan_res.get("port_count", 0)
        shodan_table.add_row("Open Ports", str(port_count))

        if shodan_res.get("open_ports"):
            if "internetdb" in backend:
                ports_str = ", ".join(str(p["port"]) for p in shodan_res["open_ports"])
            else:
                ports_str = ", ".join(
                    f"{p['port']}/{p['transport']} ({p['product']} {p['version']}".strip() + ")"
                    for p in shodan_res["open_ports"]
                )
            shodan_table.add_row("Services", ports_str)

        vuln_count = shodan_res.get("vuln_count", 0)
        vuln_color = "red" if vuln_count > 0 else "green"
        shodan_table.add_row("CVEs", f"[{vuln_color}]{vuln_count} found[/{vuln_color}]")
        if shodan_res.get("vulns"):
            shodan_table.add_row("CVE List", ", ".join(shodan_res["vulns"]))

    console.print(Panel(shodan_table, title=shodan_title, border_style="magenta"))

    # --- VIRUSTOTAL ---
    vt_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    vt_table.add_column("Field", style="dim")
    vt_table.add_column("Value")

    if "error" in vt:
        vt_table.add_row("Status", f"[yellow]{vt['error']}[/yellow]")
    else:
        verdict = vt.get("verdict", "Unknown")
        vcolor  = _vt_color(verdict)
        vt_table.add_row("Verdict",    f"[{vcolor}]{verdict}[/{vcolor}]")
        vt_table.add_row("Detections", f"[{vcolor}]{vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious[/{vcolor}] / {vt.get('total_engines', 0)} engines")
        vt_table.add_row("Reputation", str(vt.get("reputation", 0)))
        if vt.get("flagged_by"):
            vt_table.add_row("Flagged by", ", ".join(vt["flagged_by"]))

    console.print(Panel(vt_table, title="[bold]VirusTotal[/bold]", border_style="green"))

    # --- DNSBL ---
    dnsbl_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    dnsbl_table.add_column("Field", style="dim")
    dnsbl_table.add_column("Value")

    if "error" in dnsbl_res:
        dnsbl_table.add_row("Status", f"[yellow]{dnsbl_res['error']}[/yellow]")
    else:
        listed_count = dnsbl_res.get("listed_count", 0)
        checked      = dnsbl_res.get("checked_count", 0)
        bl_color     = "red" if listed_count > 0 else "green"
        dnsbl_table.add_row("Result", f"[{bl_color}]{listed_count} listed / {checked} checked[/{bl_color}]")
        if dnsbl_res.get("listed_on"):
            for entry in dnsbl_res["listed_on"]:
                dnsbl_table.add_row(f"  {entry['name']}", f"[red]LISTED[/red] [dim]({entry['category']})[/dim]")

    console.print(Panel(dnsbl_table, title="[bold]DNSBL Blacklists[/bold]", border_style="yellow"))

    # --- OTX ---
    otx_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    otx_table.add_column("Field", style="dim")
    otx_table.add_column("Value")

    if "error" in otx_res:
        msg = otx_res["error"] or "Unknown error"
        otx_table.add_row("Status", f"[yellow]{msg}[/yellow]")
    else:
        pulse_count = otx_res.get("pulse_count", 0)
        otx_color   = "red" if pulse_count >= 5 else "dark_orange" if pulse_count > 0 else "green"
        otx_table.add_row("Threat Pulses", f"[{otx_color}]{otx_res.get('verdict', 'N/A')}[/{otx_color}]")
        otx_table.add_row("Reputation",    str(otx_res.get("reputation", 0)))
        if otx_res.get("pulse_names"):
            otx_table.add_row("Campaigns", "\n".join(otx_res["pulse_names"]))
        if otx_res.get("tags"):
            otx_table.add_row("Tags", ", ".join(otx_res["tags"]))

    console.print(Panel(otx_table, title="[bold]AlienVault OTX[/bold]", border_style="cyan"))
    console.print()


def print_json(ip: str, results: dict):
    output = {"ip": ip, "results": results}
    print(json.dumps(output, indent=2, default=str))


def as_dict(ip: str, results: dict) -> dict:
    """Return structured dict — for use when called from a bot or web app."""
    return {"ip": ip, "results": results}
