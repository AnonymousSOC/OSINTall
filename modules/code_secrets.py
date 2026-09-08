#!/usr/bin/env python3
"""
OSINTALL - Code Repositories & Secret Leak Detection Module (Enhanced)
Covers: Native High-Speed Regex Secret Scanner (AWS, GitHub PAT, Slack, Stripe, Private Keys, Google API),
Repository Secret Scanning (Gitleaks / TruffleHog wrappers), and Code Search Engine Link Aggregation.
"""

import os
import re
import subprocess
from rich.table import Table
from rich.panel import Panel
from modules.banner import (
    console, print_section, print_info, print_success, print_warning,
    print_error, is_tool_available
)

# Built-in High-Accuracy Secret Regex Signatures
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("GitHub Personal Access Token", re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b")),
    ("Google Cloud API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("Slack API Token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b")),
    ("Stripe Live Secret Key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24})\b")),
    ("RSA / Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic High-Entropy Secret Assignment", re.compile(r"(?i)\b(?:api_key|apikey|secret_key|client_secret|auth_token)\s*[:=]\s*['\"]([0-9a-zA-Z_\-]{16,64})['\"]")),
    ("JSON Web Token (JWT)", re.compile(r"\beyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*\b"))
]

def scan_text_or_file_for_secrets(target: str) -> list:
    """Scans raw text, a file, or a directory recursively for exposed secrets."""
    matches = []
    
    # If target is an existing directory
    if os.path.isdir(target):
        print_info(f"Scanning directory recursively for secrets: [bold cyan]{target}[/]")
        for root, _, files in os.walk(target):
            if any(p in root for p in [".git", "node_modules", ".venv", "__pycache__"]):
                continue
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if os.path.getsize(file_path) < 2 * 1024 * 1024: # max 2MB per file
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            for name, pattern in SECRET_PATTERNS:
                                for m in pattern.finditer(content):
                                    secret_val = m.group(0)[:60]
                                    matches.append({"type": name, "file": file_path, "sample": secret_val})
                except Exception:
                    pass
    # If target is an existing file
    elif os.path.isfile(target):
        print_info(f"Scanning file for secrets: [bold cyan]{target}[/]")
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for name, pattern in SECRET_PATTERNS:
                    for m in pattern.finditer(content):
                        matches.append({"type": name, "file": target, "sample": m.group(0)[:60]})
        except Exception as e:
            print_error(f"Could not read file: {e}")
    # Otherwise treat as raw string / token query
    else:
        for name, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(target):
                matches.append({"type": name, "file": "Input String", "sample": m.group(0)[:60]})

    return matches

def search_code_engines(query: str):
    """Executes native regex scan on string/path and presents code search links."""
    print_section(f"Code & Secret Search: Public Repositories ({query})", icon="💻")
    
    # 1. Native Secret Pattern Match
    native_hits = scan_text_or_file_for_secrets(query)
    if native_hits:
        print_error(f"🚨 MATCH FOUND: Native scanner detected {len(native_hits)} potential secret(s):")
        sec_table = Table(title="Secret Detection Matches", border_style="red")
        sec_table.add_column("Rule Name", style="bold red", width=25)
        sec_table.add_column("Location", style="yellow", width=25)
        sec_table.add_column("Snippet / Match", style="white")
        for h in native_hits[:15]:
            sec_table.add_row(h["type"], os.path.basename(h["file"]), h["sample"][:45] + "...")
        console.print(sec_table)
    else:
        print_info("No obvious hardcoded token signature matched directly in the query.")

    # 2. External Code Engines
    table = Table(title="Source Code Search Engines & Footprint Trackers", border_style="cyan")
    table.add_column("Engine", style="bold yellow", width=20)
    table.add_column("Capability", style="white", width=32)
    table.add_column("Direct Search Link", style="underline blue")

    table.add_row("grep.app", "Search across 500k+ GitHub repos", f"https://grep.app/search?q={query}")
    table.add_row("Sourcegraph", "Universal code search across millions of repos", f"https://sourcegraph.com/search?q=context:global+{query}")
    table.add_row("PublicWWW", "Source code & HTML/JS signature search", f"https://publicwww.com/websites/{query}/")
    table.add_row("GitHub Code Search", "Official GitHub global code index", f"https://github.com/search?q={query}&type=code")
    table.add_row("GitLab Code Search", "Public GitLab snippets and code", f"https://gitlab.com/search?search={query}")
    console.print(table)

def scan_repo_secrets(repo_path_or_url: str):
    """Wraps native scanner, Gitleaks, or TruffleHog to scan a git repository for exposed secrets."""
    print_section(f"Secret Scanner: Scanning Target ({repo_path_or_url})", icon="🔑")

    # 1. Native scanner pass first
    if os.path.exists(repo_path_or_url):
        hits = scan_text_or_file_for_secrets(repo_path_or_url)
        if hits:
            print_error(f"Found [bold red]{len(hits)}[/] secrets via native pattern rules!")

    # 2. Check for Gitleaks or TruffleHog in Kali
    gitleaks_found = is_tool_available("gitleaks")
    trufflehog_found = is_tool_available("trufflehog")

    if gitleaks_found:
        print_info("Running [bold green]gitleaks[/] scan...")
        try:
            cmd = ["gitleaks", "detect", "--source", repo_path_or_url, "-v"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                print_success("Gitleaks: No leaked secrets detected!")
            else:
                print_error(f"Gitleaks detected potential secret leaks:\n{res.stdout[:500]}")
        except Exception as e:
            print_error(f"Error running gitleaks: {e}")

    if trufflehog_found:
        print_info("Running [bold green]trufflehog[/] scan...")
        try:
            cmd = ["trufflehog", "filesystem" if os.path.isdir(repo_path_or_url) else "git", repo_path_or_url]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            console.print(res.stdout[:800])
        except Exception as e:
            print_error(f"Error running trufflehog: {e}")

    if not gitleaks_found and not trufflehog_found and not os.path.exists(repo_path_or_url):
        print_warning("Target is a remote URL and neither 'gitleaks' nor 'trufflehog' is installed.")
        print_info("On Kali Linux, install them with: [bold cyan]sudo apt install gitleaks[/]")
