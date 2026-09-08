"""
OSINTALL Threat Intelligence & Malware Reputation Module
Queries zero-key cybercrime databases (Abuse.ch URLhaus, ThreatFox)
to detect malware distribution, botnet C2 nodes, and compute unified threat risk scores.
"""

import sys
import re
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

DEFAULT_TIMEOUT = 8.0
DEFAULT_USER_AGENT = "OSINTALL-ThreatIntel/2.2 (+https://github.com/AnonymousSOC/OSINTall)"


def query_urlhaus(target_host: str, session: requests.Session) -> dict:
    """
    Queries Abuse.ch URLhaus API for malicious URLs and payloads associated with a domain or IP.
    Endpoint: https://urlhaus-api.abuse.ch/v1/host/
    """
    clean_host = re.sub(r"^https?://", "", target_host).split("/")[0].strip()
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    try:
        resp = session.post(url, data={"host": clean_host}, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                return {
                    "status": "DETECTED",
                    "url_count": data.get("url_count", 0),
                    "first_seen": data.get("firstseen", "Unknown"),
                    "urls": data.get("urls", [])[:10],  # sample of top 10
                    "blacklists": data.get("blacklists", {})
                }
            elif data.get("query_status") == "no_results":
                return {"status": "CLEAN", "url_count": 0, "urls": []}
    except Exception as e:
        return {"status": "ERROR", "error": str(e), "urls": []}
    return {"status": "CLEAN", "url_count": 0, "urls": []}


def query_threatfox(target_term: str, session: requests.Session) -> dict:
    """
    Queries Abuse.ch ThreatFox API for Indicators of Compromise (IoCs) and malware campaigns.
    Endpoint: https://threatfox-api.abuse.ch/v1/
    """
    clean_term = re.sub(r"^https?://", "", target_term).split("/")[0].strip()
    url = "https://threatfox-api.abuse.ch/v1/"
    payload = {"query": "search_ioc", "search_term": clean_term}
    try:
        resp = session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                iocs = data.get("data", [])
                return {
                    "status": "DETECTED",
                    "ioc_count": len(iocs),
                    "iocs": iocs[:10]  # sample of top 10
                }
            elif data.get("query_status") == "no_result":
                return {"status": "CLEAN", "ioc_count": 0, "iocs": []}
    except Exception as e:
        return {"status": "ERROR", "error": str(e), "iocs": []}
    return {"status": "CLEAN", "ioc_count": 0, "iocs": []}


def calculate_threat_score(urlhaus_data: dict, threatfox_data: dict) -> dict:
    """Computes a unified weighted threat risk score between 0 and 100."""
    score = 0
    reasons = []

    # URLhaus factors
    url_count = urlhaus_data.get("url_count", 0)
    if url_count > 0:
        added = min(50, url_count * 15)
        score += added
        reasons.append(f"URLhaus flagged {url_count} malicious malware distribution URL(s) (+{added})")

    # ThreatFox factors
    ioc_count = threatfox_data.get("ioc_count", 0)
    if ioc_count > 0:
        added = min(50, ioc_count * 20)
        score += added
        # Extract malware names
        malware_names = list({ioc.get("malware_printable") for ioc in threatfox_data.get("iocs", []) if ioc.get("malware_printable")})
        mw_str = ", ".join(malware_names[:3]) if malware_names else "Malicious Activity"
        reasons.append(f"ThreatFox confirmed {ioc_count} threat IoC(s) linked to: {mw_str} (+{added})")

    score = min(100, score)

    if score >= 50:
        level = "CRITICAL"
        color = "red"
        label = "🚨 CRITICAL THREAT / ACTIVE MALWARE"
    elif score > 0:
        level = "SUSPICIOUS"
        color = "yellow"
        label = "⚠️ SUSPICIOUS / PREVIOUS INCIDENTS"
    else:
        level = "CLEAN"
        color = "green"
        label = "✅ CLEAN / NO ACTIVE THREATS IDENTIFIED"

    return {
        "score": score,
        "level": level,
        "color": color,
        "label": label,
        "reasons": reasons
    }


def run_threat_intelligence(target: str, proxy: str = None) -> dict:
    """
    Main orchestration entry point for threat intelligence and reputation scoring.
    """
    clean_target = re.sub(r"^https?://", "", target).split("/")[0].strip()
    console.rule(f"[bold cyan]🛡️ ─── THREAT INTELLIGENCE & REPUTATION ({clean_target.upper()}) ───[/bold cyan]")
    console.print(f"[bold blue][*][/bold blue] Querying Abuse.ch URLhaus & ThreatFox databases for: [bold white]{clean_target}[/bold white]...")

    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    # Query engines
    urlhaus_result = query_urlhaus(clean_target, session)
    threatfox_result = query_threatfox(clean_target, session)
    threat_assessment = calculate_threat_score(urlhaus_result, threatfox_result)

    # Display Assessment Panel
    score = threat_assessment["score"]
    color = threat_assessment["color"]
    level = threat_assessment["level"]
    label = threat_assessment["label"]

    panel_text = f"[{color}][bold]{label}[/bold][/{color}]\n"
    panel_text += f"[bold white]Overall Threat Severity Score:[/bold white] [{color}][bold]{score} / 100[/bold][/{color}]\n"
    if threat_assessment["reasons"]:
        panel_text += "\n[bold white]Risk Factors Identified:[/bold white]\n"
        for r in threat_assessment["reasons"]:
            panel_text += f" • [{color}]{r}[/{color}]\n"
    else:
        panel_text += "\n[dim]No malicious URLs, payload drops, or botnet IoCs found in Abuse.ch feeds.[/dim]"

    console.print(Panel(panel_text.strip(), title="[bold white]Threat Reputation Summary[/bold white]", border_style=color))

    # Display URLhaus table if detected
    if urlhaus_result.get("url_count", 0) > 0:
        uh_table = Table(
            title=f"🦠 Abuse.ch URLhaus Malicious URLs ({urlhaus_result['url_count']} Total)",
            show_header=True,
            header_style="bold red",
            border_style="red"
        )
        uh_table.add_column("Malicious URL", style="white")
        uh_table.add_column("Status", style="bold", justify="center")
        uh_table.add_column("Threat Type", style="yellow")
        uh_table.add_column("Tags", style="cyan")

        for u in urlhaus_result.get("urls", []):
            tags = ", ".join(u.get("tags", []) or []) or "-"
            status_style = "[green]Offline[/green]" if u.get("url_status") == "offline" else "[red]ONLINE[/red]"
            uh_table.add_row(
                u.get("url", ""),
                status_style,
                u.get("threat", "Malware"),
                tags
            )
        console.print(uh_table)

    # Display ThreatFox table if detected
    if threatfox_result.get("ioc_count", 0) > 0:
        tf_table = Table(
            title=f"🎯 Abuse.ch ThreatFox Indicators of Compromise ({threatfox_result['ioc_count']} Total)",
            show_header=True,
            header_style="bold magenta",
            border_style="magenta"
        )
        tf_table.add_column("Indicator (IoC)", style="bold white")
        tf_table.add_column("Threat Type", style="cyan")
        tf_table.add_column("Malware Family", style="bold red")
        tf_table.add_column("Confidence", justify="center", style="green")

        for ioc in threatfox_result.get("iocs", []):
            conf = f"{ioc.get('confidence_level', 0)}%"
            tf_table.add_row(
                ioc.get("ioc", ""),
                ioc.get("threat_type_desc", ioc.get("threat_type", "")),
                ioc.get("malware_printable", "Unknown"),
                conf
            )
        console.print(tf_table)

    # Direct external search links
    links_table = Table(title="🔍 Threat Intelligence Search Links", show_header=True, header_style="bold blue")
    links_table.add_column("Threat Engine", style="bold white", width=22)
    links_table.add_column("Direct Threat Profile URL", style="cyan")
    links_table.add_row("Abuse.ch URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={clean_target}")
    links_table.add_row("Abuse.ch ThreatFox", f"https://threatfox.abuse.ch/browse.php?search={clean_target}")
    links_table.add_row("VirusTotal Intelligence", f"https://www.virustotal.com/gui/search/{clean_target}")
    links_table.add_row("AbuseIPDB Lookup", f"https://www.abuseipdb.com/check/{clean_target}")
    console.print(links_table)

    return {
        "target": clean_target,
        "threat_score": score,
        "threat_level": level,
        "threat_label": label,
        "urlhaus": urlhaus_result,
        "threatfox": threatfox_result,
        "assessment": threat_assessment,
        "reputation_links": {
            "urlhaus": f"https://urlhaus.abuse.ch/browse.php?search={clean_target}",
            "threatfox": f"https://threatfox.abuse.ch/browse.php?search={clean_target}",
            "virustotal": f"https://www.virustotal.com/gui/search/{clean_target}",
            "abuseipdb": f"https://www.abuseipdb.com/check/{clean_target}"
        }
    }
