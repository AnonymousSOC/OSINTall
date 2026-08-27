#!/usr/bin/env python3
"""
==============================================================================
OSINTALL - Universal Open Source Intelligence Framework
Target Environment: Kali Linux / Linux / Debian
GitHub: https://github.com/your-username/osintall
==============================================================================
"""

import sys
import os
import argparse
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel

# Add parent directory to sys.path to allow local module execution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Check essential dependencies before loading modules
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

from modules.banner import (
    console, show_banner, print_section, print_info, print_success, 
    print_warning, print_error, load_config
)
from modules.domain_recon import run_domain_recon
from modules.socmint import scan_username, analyze_email
from modules.breach_intel import check_hibp_password_hash, check_email_breaches
from modules.geoint_meta import extract_exif
from modules.darkweb_archives import check_wayback_history, search_darkweb, show_osint_frameworks
from modules.code_secrets import search_code_engines, scan_repo_secrets
from modules.report_generator import save_json_report, save_html_report

def interactive_menu():
    """Renders the interactive rich CLI menu for OSINTALL."""
    while True:
        show_banner()
        menu_table = Table(title="[bold yellow]OSINTALL - Main Intelligence Modules[/]", border_style="cyan")
        menu_table.add_column("Option", style="bold green", width=8, justify="center")
        menu_table.add_column("Module Category", style="bold white", width=35)
        menu_table.add_column("Description", style="dim cyan")

        menu_table.add_row("1", "🌐 Domain & Network Intelligence", "WHOIS, DNS, crt.sh Subdomains, Shodan, Censys, HTTP Headers")
        menu_table.add_row("2", "👤 Identity & SOCMINT", "Multi-platform Username Scanner, Email Verification, Holehe")
        menu_table.add_row("3", "🛡️ Breach Intelligence & Leaks", "HIBP k-anonymity Passwords, DeHashed, LeakCheck, Snusbase")
        menu_table.add_row("4", "📸 GEOINT & Image / File Metadata", "ExifTool, GPS Map Locator, Reverse Image (Lens/Yandex), SunCalc")
        menu_table.add_row("5", "🏛️ Dark Web & Historical Archives", "Wayback Machine CDX API, Onion Search (Ahmia/Torry), Frameworks")
        menu_table.add_row("6", "💻 Code Repos & Secret Detection", "grep.app, Sourcegraph, PublicWWW, Gitleaks / TruffleHog Scan")
        menu_table.add_row("7", "🕸️ Link Analysis Frameworks", "Maltego, SpiderFoot, Recon-ng, OSINT Framework links")
        menu_table.add_row("8", "⚡ Full Target Recon (Automated)", "Run full OSINT suite on a Domain or Username")
        menu_table.add_row("0", "❌ Exit", "Close OSINTALL")

        console.print(menu_table)
        choice = Prompt.ask("\n[bold cyan]osintall[/] > Select an option", default="1")

        if choice == "1":
            domain = Prompt.ask("[bold yellow]Enter target domain[/] (e.g. example.com)")
            if domain:
                res = run_domain_recon(domain)
                save_option = Prompt.ask("Save report to disk? (y/n)", choices=["y", "n"], default="y")
                if save_option == "y":
                    save_json_report(res, domain)
                    save_html_report(res, domain)

        elif choice == "2":
            sub_type = Prompt.ask("Select SOCMINT type", choices=["username", "email"], default="username")
            if sub_type == "username":
                user = Prompt.ask("[bold yellow]Enter target username[/]")
                if user:
                    res = scan_username(user)
                    save_json_report(res, user)
            else:
                email = Prompt.ask("[bold yellow]Enter target email[/]")
                if email:
                    res = analyze_email(email)
                    save_json_report(res, email)

        elif choice == "3":
            sub_type = Prompt.ask("Select Breach check", choices=["email", "password"], default="email")
            if sub_type == "password":
                pwd = Prompt.ask("[bold yellow]Enter password to check[/]", password=True)
                if pwd:
                    check_hibp_password_hash(pwd)
            else:
                email = Prompt.ask("[bold yellow]Enter target email[/]")
                if email:
                    res = check_email_breaches(email)
                    save_json_report(res, email)

        elif choice == "4":
            filepath = Prompt.ask("[bold yellow]Enter path to image/file[/]")
            if filepath:
                extract_exif(filepath)

        elif choice == "5":
            sub = Prompt.ask("Select Archive or Dark Web", choices=["wayback", "darkweb"], default="wayback")
            if sub == "wayback":
                target = Prompt.ask("[bold yellow]Enter URL / Domain[/]")
                if target:
                    check_wayback_history(target)
            else:
                query = Prompt.ask("[bold yellow]Enter Dark Web search query[/]")
                if query:
                    search_darkweb(query)

        elif choice == "6":
            query = Prompt.ask("[bold yellow]Enter code query / API key string to search[/]")
            if query:
                search_code_engines(query)

        elif choice == "7":
            show_osint_frameworks()

        elif choice == "8":
            target = Prompt.ask("[bold yellow]Enter Target (Domain or Username)[/]")
            if target:
                if "." in target:
                    run_domain_recon(target)
                    check_wayback_history(target)
                else:
                    scan_username(target)

        elif choice == "0":
            print_info("Exiting OSINTALL. Happy hunting!")
            break
        else:
            print_warning("Invalid selection. Please choose an option from the menu.")

        Prompt.ask("\n[dim]Press Enter to continue back to main menu...[/dim]")

def main():
    """Main CLI entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="OSINTALL - Universal Open Source Intelligence Framework for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  osintall                                     # Launch Interactive Menu (TUI)
  osintall -d example.com                      # Domain & Network Recon
  osintall -u johndoe                          # Cross-Platform Username Scan
  osintall -e target@company.com               # Email Recon & Breach Search
  osintall -f photo.jpg                        # EXIF Metadata & GPS Coordinates
  osintall -p "SuperSecret123"                 # HIBP Password Hash Exposure Check
  osintall -w example.com                      # Wayback Machine History
  osintall --darkweb "target organization"     # Dark Web Search Engines
  osintall -s "AIzaSy"                         # Search Code Repos for Leaks
        """
    )
    parser.add_argument("-d", "--domain", help="Target domain for Network & DNS reconnaissance")
    parser.add_argument("-u", "--user", help="Target username for SOCMINT profile discovery")
    parser.add_argument("-e", "--email", help="Target email for verification and breach discovery")
    parser.add_argument("-f", "--file", help="File / Image path for EXIF metadata & GPS extraction")
    parser.add_argument("-p", "--password", help="Check if password exists in public HIBP breaches")
    parser.add_argument("-w", "--wayback", help="Target domain/URL for historical Wayback Machine snapshots")
    parser.add_argument("--darkweb", help="Search query for Tor / Dark Web search engines")
    parser.add_argument("-s", "--secret-search", help="Search code repositories (grep.app, sourcegraph) for strings/keys")
    parser.add_argument("--frameworks", action="store_true", help="Display links & launchers for major OSINT frameworks")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive terminal menu")
    parser.add_argument("-o", "--output", choices=["json", "html", "all"], default="all", help="Report format to export")

    args = parser.parse_args()

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
        res = run_domain_recon(args.domain)
        if args.output in ["json", "all"]:
            save_json_report(res, args.domain)
        if args.output in ["html", "all"]:
            save_html_report(res, args.domain)

    if args.user:
        res = scan_username(args.user)
        if args.output in ["json", "all"]:
            save_json_report(res, args.user)

    if args.email:
        res_email = analyze_email(args.email)
        res_breach = check_email_breaches(args.email)
        combined = {"email_analysis": res_email, "breach_search": res_breach}
        if args.output in ["json", "all"]:
            save_json_report(combined, args.email)

    if args.file:
        extract_exif(args.file)

    if args.password:
        check_hibp_password_hash(args.password)

    if args.wayback:
        check_wayback_history(args.wayback)

    if args.darkweb:
        search_darkweb(args.darkweb)

    if args.secret_search:
        search_code_engines(args.secret_search)

    if args.frameworks:
        show_osint_frameworks()

if __name__ == "__main__":
    main()
