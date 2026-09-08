#!/usr/bin/env python3
"""
OSINTALL - Domain & Network Intelligence Module (Enhanced)
Covers: Multi-Source Subdomain Discovery (crt.sh, AlienVault OTX, HackerTarget),
Active DNS Resolution, CNAME Subdomain Takeover Detection, IP Geolocation & ASN,
WHOIS/RDAP, HTTP Security Headers, SSL/TLS Certificate Audit, SPF/DMARC Security,
and Shodan/URLScan API querying.
"""

import socket
import ssl
import json
import re
import datetime
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from modules.banner import (
    console, print_section, print_info, print_success, print_warning,
    print_error, load_config, get_requests_session, is_tool_available
)

# Known CNAME signatures susceptible to subdomain takeover if dangling
TAKEOVER_SIGNATURES = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3 Bucket",
    "s3-website": "AWS S3 Website",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Services",
    "trafficmanager.net": "Azure Traffic Manager",
    "cloudapp.net": "Azure CloudApp",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket",
    "pantheonsite.io": "Pantheon",
    "zendesk.com": "Zendesk",
    "readme.io": "Readme.io",
    "unbouncepages.com": "Unbounce",
    "helpscoutdocs.com": "HelpScout",
    "wordpress.com": "WordPress",
    "ghost.io": "Ghost",
    "carrd.co": "Carrd",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify"
}

def get_dns_records(domain: str) -> dict:
    """Performs DNS lookups for major record types with fail-safe timeouts."""
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

def get_ip_geolocation(ip: str) -> dict:
    """Queries IP Geolocation, ISP, and ASN for a given IP."""
    if not ip or ip in ("127.0.0.1", "0.0.0.0", "localhost"):
        return {}
    session = get_requests_session()
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        resp = session.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon")
                }
    except Exception:
        pass
    return {}

def audit_email_security(domain: str, txt_records: list) -> dict:
    """Audits SPF and DMARC configurations to assess email spoofing vulnerability."""
    audit = {
        "spf_present": False,
        "spf_record": "Missing",
        "spf_status": "Vulnerable to Spoofing (Missing)",
        "dmarc_present": False,
        "dmarc_record": "Missing",
        "dmarc_policy": "None"
    }

    # 1. Evaluate SPF in TXT records
    for record in txt_records:
        rec_clean = record.strip(' "')
        if rec_clean.startswith("v=spf1"):
            audit["spf_present"] = True
            audit["spf_record"] = rec_clean
            if "-all" in rec_clean:
                audit["spf_status"] = "Hard Fail (-all, Strong)"
            elif "~all" in rec_clean:
                audit["spf_status"] = "Soft Fail (~all, Moderate)"
            elif "?all" in rec_clean or "+all" in rec_clean:
                audit["spf_status"] = "Permissive / Insecure (?all / +all)"
            else:
                audit["spf_status"] = "Present (No explicit all qualifier)"
            break

    # 2. Check DMARC
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt_val = str(rdata).strip(' "')
            if txt_val.startswith("v=DMARC1"):
                audit["dmarc_present"] = True
                audit["dmarc_record"] = txt_val
                m = re.search(r"p=([a-zA-Z]+)", txt_val)
                if m:
                    policy = m.group(1).lower()
                    audit["dmarc_policy"] = policy
                break
    except Exception:
        pass

    return audit

def check_ssl_certificate(domain: str) -> dict:
    """Inspects SSL/TLS certificate validity dates, issuer, and SANs."""
    cert_info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # Expiration date
                    not_after = cert.get("notAfter")
                    if not_after:
                        exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.datetime.utcnow()).days
                        cert_info["expires"] = exp_date.strftime("%Y-%m-%d")
                        cert_info["days_remaining"] = days_left
                        cert_info["is_expired"] = days_left <= 0
                    
                    # Issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    cert_info["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Unknown")
                    
                    # Subject & SANs
                    subj_dict = dict(x[0] for x in cert.get("subject", []))
                    cert_info["common_name"] = subj_dict.get("commonName", domain)
                    
                    sans = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]
                    cert_info["sans_count"] = len(sans)
                    cert_info["sans_sample"] = sans[:10]
    except Exception:
        cert_info = {"error": "Could not connect to HTTPS/443"}
    return cert_info

def get_whois_info(domain: str) -> dict:
    """Performs WHOIS query via RDAP or system whois binary."""
    data = {
        "handle": "N/A",
        "registrar": "N/A",
        "creation_date": "N/A",
        "expiration_date": "N/A",
        "name_servers": [],
        "raw": ""
    }
    session = get_requests_session()

    # 1. Try RDAP (RESTful WHOIS replacement)
    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        resp = session.get(rdap_url, timeout=6)
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

    # 2. Fallback to system whois command if available in Kali/Linux
    if is_tool_available("whois"):
        try:
            import subprocess
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

def get_subdomains_multi_source(domain: str) -> set:
    """Aggregates passive subdomains from crt.sh, AlienVault OTX, and HackerTarget."""
    subdomains = set()
    session = get_requests_session()

    # 1. crt.sh Certificate Transparency logs
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = session.get(url, timeout=9)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if "*" not in sub and (sub == domain or sub.endswith(f".{domain}")):
                        subdomains.add(sub)
    except Exception:
        pass

    # 2. AlienVault OTX Passive DNS (Free, fast, no key)
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        resp = session.get(url, timeout=7)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("passive_dns", []):
                hostname = item.get("hostname", "").strip().lower()
                if hostname and (hostname == domain or hostname.endswith(f".{domain}")):
                    subdomains.add(hostname)
    except Exception:
        pass

    # 3. HackerTarget Host Search (Free tier)
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = session.get(url, timeout=7)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if sub and (sub == domain or sub.endswith(f".{domain}")):
                        subdomains.add(sub)
    except Exception:
        pass

    return subdomains

def resolve_subdomain(subdomain: str) -> dict:
    """Resolves a subdomain to check active IP addresses and CNAME records for takeover analysis."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    info = {
        "subdomain": subdomain,
        "live": False,
        "ips": [],
        "cname": None,
        "takeover_risk": None
    }

    # Check CNAME first
    try:
        cname_answers = resolver.resolve(subdomain, "CNAME")
        cname_target = str(cname_answers[0].target).rstrip(".")
        info["cname"] = cname_target
        for sig, service in TAKEOVER_SIGNATURES.items():
            if sig in cname_target.lower():
                info["takeover_risk"] = service
                break
    except Exception:
        pass

    # Check A records (Live check)
    try:
        a_answers = resolver.resolve(subdomain, "A")
        info["ips"] = [str(rdata) for rdata in a_answers]
        if info["ips"]:
            info["live"] = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # If NXDOMAIN but has CNAME pointing to known service, high takeover risk!
        if info.get("cname") and info.get("takeover_risk"):
            info["takeover_risk"] = f"CRITICAL: Dangling CNAME to {info['takeover_risk']} (NXDOMAIN)"
    except Exception:
        pass

    return info

def check_http_headers(domain: str) -> dict:
    """Inspects HTTP & HTTPS response headers and evaluates security protections."""
    headers_info = {}
    session = get_requests_session()
    
    for proto in ["https", "http"]:
        url = f"{proto}://{domain}"
        try:
            resp = session.get(url, timeout=6, allow_redirects=True)
            sec_headers = {
                "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security", "Missing"),
                "Content-Security-Policy": "Present" if "Content-Security-Policy" in resp.headers else "Missing",
                "X-Frame-Options": resp.headers.get("X-Frame-Options", "Missing"),
                "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options", "Missing"),
                "Referrer-Policy": resp.headers.get("Referrer-Policy", "Missing"),
                "Permissions-Policy": resp.headers.get("Permissions-Policy", "Missing")
            }
            headers_info[proto] = {
                "status_code": resp.status_code,
                "final_url": resp.url,
                "server": resp.headers.get("Server", "Unknown"),
                "powered_by": resp.headers.get("X-Powered-By", "None"),
                "security_headers": sec_headers
            }
            break
        except Exception:
            continue
    return headers_info

def query_shodan_api(ip_or_domain: str, api_key: str) -> dict:
    """Queries Shodan API if an API key is provided."""
    if not api_key:
        return {"status": "no_key", "message": "Shodan API Key not configured."}
    session = get_requests_session()
    try:
        url = f"https://api.shodan.io/shodan/host/{ip_or_domain}?key={api_key}"
        resp = session.get(url, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "status": "success",
                "ip": data.get("ip_str"),
                "org": data.get("org", "N/A"),
                "os": data.get("os", "N/A"),
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
                "tags": data.get("tags", [])
            }
        else:
            return {"status": "error", "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def query_urlscan_api(domain: str, api_key: str = "") -> dict:
    """Queries URLScan.io search results."""
    session = get_requests_session()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5"
        headers = {"API-Key": api_key} if api_key else {}
        resp = session.get(url, headers=headers, timeout=8)
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
        "ip_geolocation": [],
        "email_security": {},
        "ssl_certificate": {},
        "whois": {},
        "subdomains_total": 0,
        "subdomains": [],
        "subdomains_live": [],
        "takeover_warnings": [],
        "http_headers": {},
        "shodan": {},
        "links": {}
    }

    # 1. DNS Records
    print_info("Querying DNS Records (A, AAAA, MX, NS, TXT, SOA, CNAME)...")
    results["dns"] = get_dns_records(domain)
    
    dns_table = Table(title=f"DNS Records for {domain}", border_style="cyan")
    dns_table.add_column("Type", style="bold yellow", width=10)
    dns_table.add_column("Records", style="white")
    for rtype, records in results["dns"].items():
        if records:
            dns_table.add_row(rtype, "\n".join(records[:5]))
    console.print(dns_table)

    # 2. IP Geolocation & ASN Intelligence
    primary_ips = results["dns"].get("A", [])
    if primary_ips:
        print_info("Resolving IP Geolocation & ASN Intelligence...")
        for ip in primary_ips[:3]:
            geo = get_ip_geolocation(ip)
            if geo:
                results["ip_geolocation"].append(geo)
        
        if results["ip_geolocation"]:
            geo_table = Table(title="IP Geolocation & Hosting Infrastructure", border_style="blue")
            geo_table.add_column("IP Address", style="bold cyan", width=16)
            geo_table.add_column("Location", style="white", width=22)
            geo_table.add_column("ISP / Org", style="yellow", width=25)
            geo_table.add_column("ASN", style="magenta")
            for g in results["ip_geolocation"]:
                loc = f"{g['city']}, {g['country']}"
                isp_org = f"{g['isp']} ({g['org']})" if g['isp'] != g['org'] else g['isp']
                geo_table.add_row(g["ip"], loc, isp_org, str(g["asn"]))
            console.print(geo_table)

    # 3. Email Security Audit (SPF & DMARC)
    txt_records = results["dns"].get("TXT", [])
    results["email_security"] = audit_email_security(domain, txt_records)
    sec = results["email_security"]
    
    spf_badge = "[bold green]Configured[/]" if sec["spf_present"] else "[bold red]Vulnerable to Spoofing[/]"
    dmarc_badge = f"[bold green]{sec['dmarc_policy'].upper()}[/]" if sec["dmarc_present"] else "[bold red]Missing[/]"
    
    email_sec_panel = (
        f"[bold yellow]SPF Status:[/]   {sec['spf_status']} ({spf_badge})\n"
        f"[bold cyan]SPF Record:[/]   {sec['spf_record']}\n"
        f"[bold yellow]DMARC Status:[/] Policy={sec['dmarc_policy']} ({dmarc_badge})\n"
        f"[bold cyan]DMARC Record:[/] {sec['dmarc_record']}"
    )
    console.print(Panel(email_sec_panel, title="[bold magenta]📧 Email Spoofing & Domain Security Audit[/]", border_style="magenta"))

    # 4. SSL/TLS Certificate Audit
    print_info("Auditing SSL/TLS Certificate on HTTPS/443...")
    results["ssl_certificate"] = check_ssl_certificate(domain)
    ssl_data = results["ssl_certificate"]
    if "expires" in ssl_data:
        days = ssl_data.get("days_remaining", 0)
        exp_style = "[bold green]" if days > 30 else "[bold red]"
        ssl_panel = (
            f"[bold cyan]Common Name:[/]     {ssl_data.get('common_name')}\n"
            f"[bold cyan]Issuer:[/]          {ssl_data.get('issuer')}\n"
            f"[bold cyan]Expiration Date:[/] {ssl_data.get('expires')} ({exp_style}{days} days remaining[/])\n"
            f"[bold cyan]Total SANs:[/]      {ssl_data.get('sans_count')} alternate names"
        )
        console.print(Panel(ssl_panel, title="[bold green]🔒 SSL/TLS Certificate Details[/]", border_style="green"))

    # 5. WHOIS Information
    print_info("Retrieving WHOIS / RDAP Registration Data...")
    results["whois"] = get_whois_info(domain)
    whois_panel = (
        f"[bold cyan]Registrar:[/]    {results['whois'].get('registrar', 'N/A')}\n"
        f"[bold cyan]Created Date:[/] {results['whois'].get('creation_date', 'N/A')}\n"
        f"[bold cyan]Expiry Date:[/]  {results['whois'].get('expiration_date', 'N/A')}\n"
        f"[bold cyan]Name Servers:[/] {', '.join(results['whois'].get('name_servers', [])) or 'N/A'}"
    )
    console.print(Panel(whois_panel, title="[bold green]WHOIS & Ownership Details[/]", border_style="green"))

    # 6. Multi-Source Subdomain Discovery (crt.sh + AlienVault + HackerTarget)
    print_info("Aggregating subdomains (crt.sh + AlienVault OTX + HackerTarget)...")
    discovered_raw = get_subdomains_multi_source(domain)
    results["subdomains_total"] = len(discovered_raw)
    results["subdomains"] = sorted(list(discovered_raw))

    if discovered_raw:
        print_success(f"Discovered [bold green]{len(discovered_raw)}[/] subdomains across passive intelligence engines.")
        print_info("Probing live DNS resolution and checking CNAME takeover signatures...")

        # Concurrently resolve up to 40 subdomains for fast feedback
        to_resolve = sorted(list(discovered_raw))[:40]
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_sub = {executor.submit(resolve_subdomain, sub): sub for sub in to_resolve}
            for future in as_completed(future_to_sub):
                res = future.result()
                if res.get("live"):
                    results["subdomains_live"].append(res)
                if res.get("takeover_risk"):
                    results["takeover_warnings"].append(res)

        sub_table = Table(title=f"Sample Subdomain Resolution & Status ({domain})", border_style="magenta")
        sub_table.add_column("Subdomain", style="bold cyan")
        sub_table.add_column("Status", style="bold", width=12)
        sub_table.add_column("Resolved IP(s)", style="white")
        sub_table.add_column("CNAME / Takeover Risk", style="yellow")

        for s in results["subdomains_live"][:15]:
            status_str = "[bold green]LIVE[/]" if s["live"] else "[dim]Unresolved[/]"
            cname_str = f"[bold red]⚠️ {s['takeover_risk']}[/]" if s.get("takeover_risk") else (s.get("cname") or "-")
            sub_table.add_row(s["subdomain"], status_str, ", ".join(s["ips"]), cname_str)

        console.print(sub_table)

        if results["takeover_warnings"]:
            for t in results["takeover_warnings"]:
                print_warning(f"Subdomain Takeover Indicator on [bold cyan]{t['subdomain']}[/] -> [bold red]{t['takeover_risk']}[/]")
    else:
        print_warning("No subdomains discovered in public CT logs or passive DNS.")

    # 7. HTTP Headers & Security
    print_info("Analyzing HTTP/HTTPS Security Headers...")
    results["http_headers"] = check_http_headers(domain)
    for proto, hdata in results["http_headers"].items():
        header_table = Table(title=f"HTTP Headers & Security ({proto.upper()})", border_style="blue")
        header_table.add_column("Property", style="bold yellow")
        header_table.add_column("Value", style="white")
        header_table.add_row("Status Code", str(hdata.get("status_code")))
        header_table.add_row("Final URL", hdata.get("final_url", "N/A"))
        header_table.add_row("Server", hdata.get("server", "N/A"))
        header_table.add_row("X-Powered-By", hdata.get("powered_by", "None"))
        for sec_name, sec_val in hdata.get("security_headers", {}).items():
            status_style = "[bold green]Present[/]" if sec_val not in ["Missing", None] else "[bold red]Missing[/]"
            header_table.add_row(sec_name, f"{sec_val} ({status_style})")
        console.print(header_table)

    # 8. Active Shodan API Query (if configured)
    shodan_key = config.get("api_keys", {}).get("shodan", "")
    if shodan_key and primary_ips:
        print_info(f"Querying Shodan API for IP [bold cyan]{primary_ips[0]}[/]...")
        shodan_res = query_shodan_api(primary_ips[0], shodan_key)
        results["shodan"] = shodan_res
        if shodan_res.get("status") == "success":
            print_success(f"Shodan Open Ports: [bold green]{shodan_res.get('ports')}[/]")
            if shodan_res.get("vulns"):
                print_error(f"Shodan Vulnerabilities (CVEs): [bold red]{', '.join(shodan_res.get('vulns'))}[/]")
        else:
            print_warning(f"Shodan: {shodan_res.get('message')}")

    # 9. External Intelligence & Deep Recon Links
    links = {
        "Shodan": f"https://www.shodan.io/search?query=hostname%3A{domain}",
        "Censys": f"https://search.censys.io/hosts?q={domain}",
        "FOFA": f"https://en.fofa.info/result?qbase64=" + requests.utils.quote(f'domain="{domain}"'),
        "crt.sh": f"https://crt.sh/?q=%.{domain}",
        "DNSDumpster": f"https://dnsdumpster.com/",
        "SecurityTrails": f"https://securitytrails.com/domain/{domain}/dns",
        "urlscan.io": f"https://urlscan.io/search/#{domain}",
        "Lookyloo": f"https://lookyloo.circl.lu/",
        "AlienVault OTX": f"https://otx.alienvault.com/indicator/domain/{domain}"
    }
    results["links"] = links

    link_table = Table(title="OSINT Search Engines & Network Intelligence Links", border_style="yellow")
    link_table.add_column("Engine / Tool", style="bold cyan", width=20)
    link_table.add_column("Direct Intelligence Query URL", style="underline blue")
    for name, url in links.items():
        link_table.add_row(name, url)
    console.print(link_table)

    # 10. Check Kali Built-in Tool Availability
    kali_tools = ["subfinder", "amass", "theharvester", "whois"]
    available_tools = [tool for tool in kali_tools if is_tool_available(tool)]
    if available_tools:
        print_info(f"Kali system tools detected: [bold green]{', '.join(available_tools)}[/]")
        print_info(f"You can also run: [bold cyan]subfinder -d {domain}[/] or [bold cyan]theHarvester -d {domain} -b all[/]")

    return results
