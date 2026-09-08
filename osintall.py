#!/usr/bin/env python3
"""
==============================================================================
OSINTALL - Universal Open Source Intelligence Framework (v2.0)
Target Environment: Kali Linux / Linux / Debian
GitHub: https://github.com/AnonymousSOC/OSINTall
==============================================================================
"""

import sys
import os
import argparse
import re

# Ensure UTF-8 stdout/stderr across all platforms
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add parent directory to sys.path to allow local module execution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Check essential dependencies BEFORE importing third-party libraries
MISSING_DEPS = []
for module_name, pip_name in [
    ("rich", "rich"),
    ("requests", "requests"),
    ("dns", "dnspython"),
    ("PIL", "pillow"),
    ("bs4", "beautifulsoup4")
]:
    try:
        __import__(module_name)
    except ImportError:
        MISSING_DEPS.append(pip_name)

if MISSING_DEPS:
    print("\n[!] Missing Python dependencies required by OSINTALL:")
    for dep in MISSING_DEPS:
        print(f"    - {dep}")
    print("\n[*] Please install dependencies by running:")
    print("    pip install -r requirements.txt")
    print("    or run the automated installer on Kali Linux:")
    print("    sudo ./install.sh\n")
    sys.exit(1)

# Third-party imports after verification
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel

from modules.banner import (
    console, show_banner, print_section, print_info, print_success, 
    print_warning, print_error, load_config, set_global_proxy
)
from modules.domain_recon import run_domain_recon, run_search_dorks
from modules.cloud_recon import run_cloud_recon
from modules.threat_intel import run_threat_intelligence
from modules.socmint import scan_username, analyze_email
from modules.phone_recon import scan_phone_number
from modules.breach_intel import check_hibp_password_hash, check_email_breaches, check_infostealer_exposure
from modules.geoint_meta import extract_exif
from modules.darkweb_archives import check_wayback_history, search_darkweb, show_osint_frameworks
from modules.code_secrets import search_code_engines, scan_repo_secrets
from modules.report_generator import save_json_report, save_html_report, save_csv_report, save_maltego_csv

def export_reports(data: dict, target_name: str, output_format: str = "all", include_csv: bool = False):
    """Exports intelligence findings to selected formats (JSON, HTML, CSV, Maltego)."""
    if output_format in ["json", "all"]:
        save_json_report(data, target_name)
    if output_format in ["html", "all"]:
        save_html_report(data, target_name)
    if output_format in ["csv", "all"] or include_csv:
        save_csv_report(data, target_name)
    if output_format in ["maltego", "all"] or include_csv:
        save_maltego_csv(data, target_name)

def interactive_menu():
    """Renders the interactive rich CLI menu for OSINTALL."""
    while True:
        show_banner()
        menu_table = Table(title="[bold yellow]OSINTALL - Main Intelligence Modules (v2.2)[/]", border_style="cyan")
        menu_table.add_column("Option", style="bold green", width=8, justify="center")
        menu_table.add_column("Module Category", style="bold white", width=38)
        menu_table.add_column("Capabilities", style="dim cyan")

        menu_table.add_row("1", "🌐 Domain & Network Intelligence", "WHOIS, DNS, Subdomains, IP Geo, Shodan InternetDB, SSL, Reverse IP")
        menu_table.add_row("2", "👤 Identity & SOCMINT", "Multi-platform Username Scanner (40+ sites), Email Recon, Gravatar, Holehe")
        menu_table.add_row("3", "📱 Phone Number Intelligence (TELINT)", "Carrier & Telecom Lookup, E.164 Formats, WhatsApp/Telegram Footprints")
        menu_table.add_row("4", "☁️ Cloud Storage Recon (CLOUDINT)", "Audit AWS S3, Google Cloud Storage, Azure Blob for Public Data Leaks")
        menu_table.add_row("5", "🛡️ Threat Intelligence & Reputation", "Abuse.ch URLhaus & ThreatFox Malware Telemetry, Automated Threat Scoring")
        menu_table.add_row("6", "🔎 Targeted Search Dorks (DORKINT)", "Automated Google & GitHub Search Dorks for Confidential Docs & Leaks")
        menu_table.add_row("7", "🚨 Breach Intelligence & Leaks", "HIBP k-anonymity Passwords, Hudson Rock Infostealer Malware Telemetry")
        menu_table.add_row("8", "📸 GEOINT & File Metadata", "EXIF/GPS, Device/Camera info, Offline Leaflet.js HTML Map Pin, Reverse Image")
        menu_table.add_row("9", "🏛️ Dark Web & Historical Archives", "Wayback CDX Sensitive Endpoint Mining, Tor SOCKS Proxy Check, Ahmia")
        menu_table.add_row("10", "💻 Code Repos & Secret Detection", "Native Regex Scanner (AWS, PAT, Slack, Stripe, Keys), Gitleaks/TruffleHog")
        menu_table.add_row("11", "🕸️ Link Analysis Frameworks", "Maltego, SpiderFoot, Recon-ng, OSINT Framework directories")
        menu_table.add_row("12", "⚡ Full Automated Recon Suite", "Run Full Domain, Cloud, Threat & Target Recon & Export HTML/CSV/Maltego")
        menu_table.add_row("0", "❌ Exit", "Close OSINTALL")

        console.print(menu_table)
        choice = Prompt.ask("\n[bold cyan]osintall[/] > Select an option", default="1")

        if choice == "1":
            domain = Prompt.ask("[bold yellow]Enter target domain[/] (e.g. example.com)")
            if domain:
                res = run_domain_recon(domain)
                save_option = Prompt.ask("Save reports to disk (HTML, JSON, CSV, Maltego)? (y/n)", choices=["y", "n"], default="y")
                if save_option == "y":
                    export_reports(res, domain, "all", include_csv=True)

        elif choice == "2":
            sub_type = Prompt.ask("Select SOCMINT type", choices=["username", "email"], default="username")
            if sub_type == "username":
                user = Prompt.ask("[bold yellow]Enter target username[/]")
                if user:
                    res = scan_username(user)
                    save_option = Prompt.ask("Save report to disk? (y/n)", choices=["y", "n"], default="y")
                    if save_option == "y":
                        export_reports(res, user, "all", include_csv=True)
            else:
                email = Prompt.ask("[bold yellow]Enter target email[/]")
                if email:
                    res = analyze_email(email)
                    save_option = Prompt.ask("Save report to disk? (y/n)", choices=["y", "n"], default="y")
                    if save_option == "y":
                        export_reports(res, email, "all", include_csv=True)

        elif choice == "3":
            phone = Prompt.ask("[bold yellow]Enter target phone number[/] (e.g. +14155552671)")
            if phone:
                res = scan_phone_number(phone)
                save_option = Prompt.ask("Save executive report to disk? (y/n)", choices=["y", "n"], default="y")
                if save_option == "y":
                    export_reports(res, phone, "all", include_csv=True)

        elif choice == "4":
            target = Prompt.ask("[bold yellow]Enter target keyword or domain for cloud storage audit[/]")
            if target:
                res = run_cloud_recon(target)
                save_option = Prompt.ask("Save cloud reconnaissance report to disk? (y/n)", choices=["y", "n"], default="y")
                if save_option == "y":
                    export_reports(res, target, "all", include_csv=True)

        elif choice == "5":
            target = Prompt.ask("[bold yellow]Enter domain or IP to check against Abuse.ch malware feeds[/]")
            if target:
                res = run_threat_intelligence(target)
                save_option = Prompt.ask("Save threat intelligence report to disk? (y/n)", choices=["y", "n"], default="y")
                if save_option == "y":
                    export_reports(res, target, "all", include_csv=True)

        elif choice == "6":
            domain = Prompt.ask("[bold yellow]Enter target domain to generate automated search dorks[/]")
            if domain:
                run_search_dorks(domain)

        elif choice == "7":
            sub_type = Prompt.ask("Select Breach check", choices=["email", "password", "domain"], default="email")
            if sub_type == "password":
                pwd = Prompt.ask("[bold yellow]Enter password to check[/]", password=True)
                if pwd:
                    check_hibp_password_hash(pwd)
            elif sub_type == "domain":
                target_domain = Prompt.ask("[bold yellow]Enter target domain to audit for infostealer breaches[/]")
                if target_domain:
                    check_infostealer_exposure(target_domain)
            else:
                email = Prompt.ask("[bold yellow]Enter target email[/]")
                if email:
                    res = check_email_breaches(email)
                    export_reports(res, email, "all")

        elif choice == "8":
            filepath = Prompt.ask("[bold yellow]Enter path to image/file[/]")
            if filepath:
                extract_exif(filepath)

        elif choice == "9":
            sub = Prompt.ask("Select Archive or Dark Web", choices=["wayback", "darkweb"], default="wayback")
            if sub == "wayback":
                target = Prompt.ask("[bold yellow]Enter URL / Domain[/]")
                filter_sens = Prompt.ask("Filter for sensitive files (.env, .sql, .bak, .pdf, .xls)?", choices=["y", "n"], default="n") == "y"
                if target:
                    check_wayback_history(target, filter_sensitive=filter_sens)
            else:
                query = Prompt.ask("[bold yellow]Enter Dark Web search query[/]")
                if query:
                    search_darkweb(query)

        elif choice == "10":
            action = Prompt.ask("Scan mode", choices=["query", "local_path"], default="query")
            if action == "local_path":
                path = Prompt.ask("[bold yellow]Enter local file or repository path to scan[/]")
                if path:
                    scan_repo_secrets(path)
            else:
                query = Prompt.ask("[bold yellow]Enter code string or API key token to inspect[/]")
                if query:
                    search_code_engines(query)

        elif choice == "11":
            show_osint_frameworks()

        elif choice == "12":
            target = Prompt.ask("[bold yellow]Enter Target (Domain, Phone, or Username) for Full Recon[/]")
            if target:
                clean_target = target.strip()
                if clean_target.startswith("+") or (clean_target.replace("-", "").isdigit() and len(clean_target) >= 7):
                    print_info(f"Running automated reconnaissance on Phone Number: [bold cyan]{clean_target}[/]")
                    phone_data = scan_phone_number(clean_target)
                    export_reports(phone_data, clean_target, "all", include_csv=True)
                elif "." in clean_target:
                    clean_domain = re.sub(r"^https?://", "", clean_target.lower()).split("/")[0]
                    print_info(f"Running automated reconnaissance on Domain: [bold cyan]{clean_domain}[/]")
                    domain_data = run_domain_recon(clean_domain)
                    cloud_data = run_cloud_recon(clean_domain)
                    threat_data = run_threat_intelligence(clean_domain)
                    snapshots = check_wayback_history(clean_domain, limit=10)
                    infostealer = check_infostealer_exposure(clean_domain)
                    
                    combined = domain_data
                    combined["cloud_buckets"] = cloud_data.get("buckets", [])
                    combined["threat_intel"] = threat_data
                    combined["threat_score"] = threat_data.get("threat_score", 0)
                    combined["urlhaus"] = threat_data.get("urlhaus", {})
                    combined["threatfox"] = threat_data.get("threatfox", {})
                    combined["wayback_snapshots"] = snapshots
                    combined["infostealer"] = infostealer

                    export_reports(combined, clean_domain, "all", include_csv=True)
                else:
                    print_info(f"Running automated reconnaissance on Username: [bold cyan]{clean_target}[/]")
                    user_data = scan_username(clean_target)
                    export_reports(user_data, clean_target, "all", include_csv=True)

        elif choice == "0":
            print_info("Exiting OSINTALL. Happy hunting!")
            break
        else:
            print_warning("Invalid selection. Please choose an option from the menu.")

        Prompt.ask("\n[dim]Press Enter to continue back to main menu...[/dim]")

def main():
    """Main CLI entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="OSINTALL v2.2 - Universal Open Source Intelligence Framework for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  osintall                                     # Launch Interactive Menu (TUI)
  osintall -d example.com                      # Domain Recon (DNS, Subdomains, IP Geo, Headers)
  osintall -u johndoe                          # Cross-Platform Username Scan (40+ sites)
  osintall -e target@company.com               # Email Recon, MX, Gravatar & Infostealer Check
  osintall -n "+14155552671"                   # Telephone Intelligence (TELINT)
  osintall -c example                          # Multi-Cloud Storage Bucket Audit (CLOUDINT)
  osintall --threat example.com                # Abuse.ch Threat Intelligence & Malware Reputation
  osintall --dorks example.com                 # Automated Google & GitHub Search Dorks
  osintall -d example.com --csv                # Export JSON, HTML, CSV & Maltego formats
  osintall -f photo.jpg                        # EXIF Metadata & Offline Leaflet Map Pin
  osintall -p "SuperSecret123"                 # HIBP Password Privacy Hash Exposure Check
  osintall -w example.com --sensitive          # Wayback Machine Sensitive File Archive Search
  osintall --darkweb "target org"              # Dark Web Search Engines & Tor Detection
  osintall -s "AKIAIOSFODNN7EXAMPLE"           # Native Regex Secret Scanner & Code Search
  osintall -d example.com --proxy "http://127.0.0.1:8080" # Route through Burp Suite or Tor
        """
    )
    parser.add_argument("-d", "--domain", help="Target domain for Network & DNS reconnaissance")
    parser.add_argument("-u", "--user", help="Target username for SOCMINT profile discovery")
    parser.add_argument("-e", "--email", help="Target email for verification and breach discovery")
    parser.add_argument("-n", "--phone", help="Target international phone number for TELINT reconnaissance (e.g. +14155552671)")
    parser.add_argument("-c", "--cloud", help="Target domain or keyword for Multi-Cloud storage enumeration (AWS S3, GCP, Azure)")
    parser.add_argument("--threat", help="Target domain or IP for Abuse.ch Threat Intelligence & Malware Reputation scoring")
    parser.add_argument("--dorks", help="Target domain to generate automated Google & GitHub search dorks")
    parser.add_argument("-f", "--file", help="File / Image path for EXIF metadata & GPS extraction")
    parser.add_argument("-p", "--password", help="Check if password exists in public HIBP breaches")
    parser.add_argument("-w", "--wayback", help="Target domain/URL for historical Wayback Machine snapshots")
    parser.add_argument("--sensitive", action="store_true", help="Filter Wayback Machine results for sensitive extensions (.env, .sql, .bak, .pdf)")
    parser.add_argument("--darkweb", help="Search query for Tor / Dark Web search engines")
    parser.add_argument("-s", "--secret-search", help="Scan text/file for secrets or search code repositories")
    parser.add_argument("--scan-path", help="Local directory or git repository to scan with native secret rules")
    parser.add_argument("--frameworks", action="store_true", help="Display links & launchers for major OSINT frameworks")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive terminal menu")
    parser.add_argument("-o", "--output", choices=["json", "html", "csv", "maltego", "all"], default="all", help="Report format to export")
    parser.add_argument("--csv", action="store_true", help="Export flat CSV and Maltego-compatible CSV alongside reports")
    parser.add_argument("--proxy", help="Route requests through HTTP or SOCKS proxy (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050)")

    args = parser.parse_args()

    # Configure global proxy if specified
    if args.proxy:
        set_global_proxy(args.proxy)
        print_info(f"Routing outgoing requests through proxy: [bold cyan]{args.proxy}[/]")

    # If no arguments are provided, default to interactive menu
    if len(sys.argv) == 1 or args.interactive:
        try:
            interactive_menu()
        except KeyboardInterrupt:
            console.print("\n[bold red][!] Operation cancelled by user.[/]")
            sys.exit(0)
        return

    show_banner()

    # CLI Execution Paths
    if args.domain:
        clean_domain = re.sub(r"^https?://", "", args.domain.strip().lower()).split("/")[0]
        res = run_domain_recon(clean_domain)
        export_reports(res, clean_domain, args.output, include_csv=args.csv)

    if args.cloud:
        res = run_cloud_recon(args.cloud)
        export_reports(res, args.cloud, args.output, include_csv=args.csv)

    if args.threat:
        res = run_threat_intelligence(args.threat)
        export_reports(res, args.threat, args.output, include_csv=args.csv)

    if args.dorks:
        run_search_dorks(args.dorks)

    if args.user:
        res = scan_username(args.user)
        export_reports(res, args.user, args.output, include_csv=args.csv)

    if args.email:
        res_email = analyze_email(args.email)
        res_breach = check_email_breaches(args.email)
        combined = {"email_analysis": res_email, "breach_search": res_breach}
        export_reports(combined, args.email, args.output, include_csv=args.csv)

    if args.phone:
        res_phone = scan_phone_number(args.phone)
        export_reports(res_phone, args.phone, args.output, include_csv=args.csv)

    if args.file:
        extract_exif(args.file)

    if args.password:
        check_hibp_password_hash(args.password)

    if args.wayback:
        check_wayback_history(args.wayback, filter_sensitive=args.sensitive)

    if args.darkweb:
        search_darkweb(args.darkweb)

    if args.secret_search:
        search_code_engines(args.secret_search)

    if args.scan_path:
        scan_repo_secrets(args.scan_path)

    if args.frameworks:
        show_osint_frameworks()

if __name__ == "__main__":
    main()
