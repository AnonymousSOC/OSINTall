#!/usr/bin/env python3
"""
OSINTALL - Domain & Network Intelligence Module
Covers: WHOIS, DNS Records, crt.sh Subdomains, Shodan, Censys, FOFA, urlscan.io, WiGLE, Amass/Subfinder wrappers
"""

import socket
import ssl
import json
import re
import subprocess
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from modules.banner import console, print_section, print_info, print_success, print_warning, print_error, load_config

def get_dns_records(domain: str) -> dict:
    """Performs DNS lookups for major record types."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 4.0

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except Exception:
            results[rtype] = []
    return results

def get_whois_info(domain: str) -> dict:
    """Performs WHOIS query via RDAP or system whois binary."""
    data = {"raw": "", "registrar": "N/A", "creation_date": "N/A", "expiration_date": "N/A", "name_servers": []}
    
    # 1. Try RDAP (RESTful WHOIS replacement)
    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(rdap_url, timeout=6, headers={"User-Agent": "OSINTALL/1.0"})
        if resp.status_code == 200:
            rdap_json = resp.json()
            data["handle"] = rdap_json.get("handle", "N/A")
            for event in rdap_json.get("events", []):
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")
                if action == "registration":
                    data["creation_date"] = date
                elif action == "expiration":
                    data["expiration_date"] = date
            entities = rdap_json.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry[0] == "fn":
                                data["registrar"] = entry[3]
            data["name_servers"] = [ns.get("ldhName", "") for ns in rdap_json.get("nameservers", [])]
            return data
    except Exception:
        pass

    # 2. Fallback to system whois command if available
    try:
        res = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=8)
        if res.returncode == 0 and res.stdout:
            data["raw"] = res.stdout[:1500]
            for line in res.stdout.splitlines():
                line_lower = line.lower()
                if "registrar:" in line_lower and data["registrar"] == "N/A":
                    data["registrar"] = line.split(":", 1)[1].strip()
                elif ("creation date:" in line_lower or "created:" in line_lower) and data["creation_date"] == "N/A":
                    data["creation_date"] = line.split(":", 1)[1].strip()
                elif ("expiry date:" in line_lower or "expiration date:" in line_lower) and data["expiration_date"] == "N/A":
                    data["expiration_date"] = line.split(":", 1)[1].strip()
    except Exception:
        pass

    return data

def get_subdomains_crtsh(domain: str) -> list:
    """Extracts subdomains from Certificate Transparency logs via crt.sh."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {"User-Agent": "OSINTALL/1.0 (Kali Linux Recon)"}
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if "*" not in sub and sub.endswith(domain):
                        subdomains.add(sub)
    except Exception as e:
        print_warning(f"crt.sh lookup note: {e}")
    return sorted(list(subdomains))

def check_http_headers(domain: str) -> dict:
    """Inspects HTTP & HTTPS response headers and SSL details."""
    headers_info = {}
    for proto in ["https", "http"]:
        url = f"{proto}://{domain}"
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True, headers={"User-Agent": "OSINTALL/1.0"})
            headers_info[proto] = {
                "status_code": resp.status_code,
                "final_url": resp.url,
                "server": resp.headers.get("Server", "Unknown"),
                "security_headers": {
                    "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security", "Missing"),
                    "Content-Security-Policy": "Present" if "Content-Security-Policy" in resp.headers else "Missing",
                    "X-Frame-Options": resp.headers.get("X-Frame-Options", "Missing"),
                    "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options", "Missing"),
                }
            }
            break
        except Exception:
            continue
    return headers_info

def query_shodan_api(ip_or_domain: str, api_key: str) -> dict:
    """Queries Shodan API if API key is provided."""
    if not api_key:
        return {"status": "no_key", "message": "Shodan API Key not configured."}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip_or_domain}?key={api_key}"
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            return {"status": "success", "data": resp.json()}
        else:
            return {"status": "error", "message": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def query_urlscan_api(domain: str, api_key: str = "") -> dict:
    """Queries or generates URLScan.io search results."""
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5"
        headers = {"API-Key": api_key} if api_key else {}
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            return {"status": "success", "results": data.get("results", [])}
    except Exception:
        pass
    return {"status": "search_link", "url": f"https://urlscan.io/search/#{domain}"}

def run_domain_recon(domain: str) -> dict:
    """Main domain reconnaissance orchestrator."""
    config = load_config()
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    print_section(f"Domain & Network Intelligence: {domain}", icon="🌐")
    print_info(f"Initiating target analysis for: [bold cyan]{domain}[/]")

    results = {
        "target": domain,
        "dns": {},
        "whois": {},
        "subdomains": [],
        "http_headers": {},
        "links": {}
    }

    # 1. DNS Records
    print_info("Querying DNS Records (A, AAAA, MX, NS, TXT, SOA)...")
    results["dns"] = get_dns_records(domain)
    
    dns_table = Table(title=f"DNS Records for {domain}", border_style="cyan")
    dns_table.add_column("Type", style="bold yellow", width=10)
    dns_table.add_column("Records", style="white")
    for rtype, records in results["dns"].items():
        if records:
            dns_table.add_row(rtype, "\n".join(records[:5]))
    console.print(dns_table)

    # 2. WHOIS Information
    print_info("Retrieving WHOIS / RDAP Registration Data...")
    results["whois"] = get_whois_info(domain)
    whois_panel = (
        f"[bold cyan]Registrar:[/] {results['whois'].get('registrar', 'N/A')}\n"
        f"[bold cyan]Created Date:[/] {results['whois'].get('creation_date', 'N/A')}\n"
        f"[bold cyan]Expiry Date:[/] {results['whois'].get('expiration_date', 'N/A')}\n"
        f"[bold cyan]Name Servers:[/] {', '.join(results['whois'].get('name_servers', [])) or 'N/A'}"
    )
    console.print(Panel(whois_panel, title="[bold green]WHOIS & Ownership Details[/]", border_style="green"))

    # 3. crt.sh Subdomain Discovery
    print_info("Scanning Certificate Transparency logs via crt.sh...")
    results["subdomains"] = get_subdomains_crtsh(domain)
    if results["subdomains"]:
        print_success(f"Found [bold green]{len(results['subdomains'])}[/] subdomains via Certificate Transparency logs:")
        sub_table = Table(title=f"Discovered Subdomains ({domain})", border_style="magenta")
        sub_table.add_column("#", style="dim", width=5)
        sub_table.add_column("Subdomain", style="bold cyan")
        for idx, sub in enumerate(results["subdomains"][:15], 1):
            sub_table.add_row(str(idx), sub)
        if len(results["subdomains"]) > 15:
            sub_table.add_row("...", f"[dim]+ {len(results['subdomains']) - 15} more subdomains[/dim]")
        console.print(sub_table)
    else:
        print_warning("No subdomains discovered in public CT logs.")

    # 4. HTTP Headers & Security
    print_info("Analyzing HTTP/HTTPS Security Headers...")
    results["http_headers"] = check_http_headers(domain)
    for proto, hdata in results["http_headers"].items():
        header_table = Table(title=f"HTTP Headers & Security ({proto.upper()})", border_style="blue")
        header_table.add_column("Property", style="bold yellow")
        header_table.add_column("Value", style="white")
        header_table.add_row("Status Code", str(hdata.get("status_code")))
        header_table.add_row("Final URL", hdata.get("final_url", "N/A"))
        header_table.add_row("Server", hdata.get("server", "N/A"))
        for sec_name, sec_val in hdata.get("security_headers", {}).items():
            status_style = "[bold green]Present[/]" if sec_val not in ["Missing", None] else "[bold red]Missing[/]"
            header_table.add_row(sec_name, f"{sec_val} ({status_style})")
        console.print(header_table)

    # 5. External Intelligence & Search Dorks
    print_info("Generating Quick Intelligence Links & Search Queries...")
    shodan_key = config.get("api_keys", {}).get("shodan", "")
    censys_id = config.get("api_keys", {}).get("censys_api_id", "")
    
    links = {
        "Shodan": f"https://www.shodan.io/search?query=hostname%3A{domain}",
        "Censys": f"https://search.censys.io/hosts?q={domain}",
        "FOFA": f"https://en.fofa.info/result?qbase64=" + requests.utils.quote(f'domain="{domain}"'),
        "crt.sh": f"https://crt.sh/?q=%.{domain}",
        "DNSDumpster": f"https://dnsdumpster.com/",
        "SecurityTrails": f"https://securitytrails.com/domain/{domain}/dns",
        "WhoisXML": f"https://whois.whoisxmlapi.com/lookup?domainName={domain}",
        "ViewDNS": f"https://viewdns.info/reversewhois/?q={domain}",
        "urlscan.io": f"https://urlscan.io/search/#{domain}",
        "Lookyloo": f"https://lookyloo.circl.lu/",
        "WiGLE (Wi-Fi/Cell)": f"https://wigle.net/"
    }
    results["links"] = links

    link_table = Table(title="OSINT Search Engines & Network Intelligence Links", border_style="yellow")
    link_table.add_column("Engine / Tool", style="bold cyan", width=20)
    link_table.add_column("Direct Intelligence Query URL", style="underline blue")
    for name, url in links.items():
        link_table.add_row(name, url)
    console.print(link_table)

    # 6. Check Kali Built-in Tool Availability
    kali_tools = ["subfinder", "amass", "theharvester"]
    available_tools = [tool for tool in kali_tools if subprocess.run(["which", tool], capture_output=True).returncode == 0]
    if available_tools:
        print_info(f"Kali system tools detected: [bold green]{', '.join(available_tools)}[/]")
        print_info(f"You can also run: [bold cyan]subfinder -d {domain}[/] or [bold cyan]theHarvester -d {domain} -b all[/]")

    return results
