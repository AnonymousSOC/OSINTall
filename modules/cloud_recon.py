"""
OSINTALL Multi-Cloud Storage Reconnaissance Module (CLOUDINT)
Audits public cloud storage infrastructure (AWS S3, Google Cloud Storage, Azure Blob)
for misconfigured buckets, exposure levels, and public data leaks.
"""

import sys
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

COMMON_MUTATIONS = [
    "",
    "-dev",
    "-stage",
    "-staging",
    "-prod",
    "-production",
    "-test",
    "-backup",
    "-backups",
    "-data",
    "-database",
    "-db",
    "-assets",
    "-media",
    "-static",
    "-files",
    "-docs",
    "-documents",
    "-internal",
    "-corp",
    "-logs",
    "-archive",
    "-public",
    "-private",
    "-temp",
    "-sec",
    "-cloud"
]

DEFAULT_TIMEOUT = 5.0
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OSINTALL/2.2"


def sanitize_keyword(keyword: str) -> str:
    """Extracts a clean base keyword from domain or organization name."""
    clean = keyword.lower().strip()
    clean = re.sub(r"^https?://", "", clean)
    clean = clean.split("/")[0]
    # If domain like example.com or sub.example.co.uk, take the primary name
    parts = clean.split(".")
    if len(parts) > 1:
        # e.g., company.com -> company
        clean = parts[0]
        if clean in ("www", "api", "mail", "dev", "app") and len(parts) > 2:
            clean = parts[1]
    clean = re.sub(r"[^a-z0-9-]", "", clean)
    return clean or "target"


def check_aws_s3(bucket_name: str, session: requests.Session) -> dict:
    """Checks Amazon AWS S3 bucket existence and permissions."""
    url = f"https://{bucket_name}.s3.amazonaws.com"
    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        code = resp.status_code
        if code == 200:
            # Check if XML listing is actually open
            if "<ListBucketResult" in resp.text:
                return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "OPEN", "code": 200, "details": "Public XML Listing Enabled (CRITICAL)"}
            return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "OPEN", "code": 200, "details": "Public Read Access (HTTP 200)"}
        elif code in (403, 401):
            return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "PROTECTED", "code": code, "details": "Bucket Exists (Access Denied)"}
        elif code == 301:
            return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "PROTECTED", "code": 301, "details": "Bucket Exists in Different Region"}
    except requests.RequestException:
        pass
    return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "NOT_FOUND", "code": 404, "details": "Not Found"}


def check_gcp_storage(bucket_name: str, session: requests.Session) -> dict:
    """Checks Google Cloud Storage bucket existence and permissions."""
    url = f"https://storage.googleapis.com/{bucket_name}"
    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        code = resp.status_code
        if code == 200:
            if "<ListBucketResult" in resp.text:
                return {"provider": "Google Cloud Storage", "bucket": bucket_name, "url": url, "status": "OPEN", "code": 200, "details": "Public XML Listing Enabled (CRITICAL)"}
            return {"provider": "Google Cloud Storage", "bucket": bucket_name, "url": url, "status": "OPEN", "code": 200, "details": "Public Read Access (HTTP 200)"}
        elif code in (403, 401):
            return {"provider": "Google Cloud Storage", "bucket": bucket_name, "url": url, "status": "PROTECTED", "code": code, "details": "Bucket Exists (Access Denied)"}
    except requests.RequestException:
        pass
    return {"provider": "Google Cloud Storage", "bucket": bucket_name, "url": url, "status": "NOT_FOUND", "code": 404, "details": "Not Found"}


def check_azure_blob(account_name: str, session: requests.Session) -> dict:
    """Checks Microsoft Azure Blob Storage account existence."""
    # Azure account names must be alphanumeric only (no hyphens) and 3-24 characters
    sanitized = re.sub(r"[^a-z0-9]", "", account_name)
    if len(sanitized) < 3 or len(sanitized) > 24:
        return {"provider": "Azure Blob", "bucket": sanitized, "url": "", "status": "SKIPPED", "code": 0, "details": "Invalid Name Length"}

    url = f"https://{sanitized}.blob.core.windows.net/?comp=list"
    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        code = resp.status_code
        if code == 200:
            return {"provider": "Azure Blob", "bucket": sanitized, "url": url, "status": "OPEN", "code": 200, "details": "Public Container Listing (CRITICAL)"}
        elif code in (400, 403):
            return {"provider": "Azure Blob", "bucket": sanitized, "url": f"https://{sanitized}.blob.core.windows.net/", "status": "PROTECTED", "code": code, "details": "Storage Account Exists"}
    except requests.RequestException:
        pass
    return {"provider": "Azure Blob", "bucket": sanitized, "url": url, "status": "NOT_FOUND", "code": 404, "details": "Not Found"}


def scan_bucket_candidate(name: str, session: requests.Session) -> list:
    """Scans a single bucket candidate name across all supported cloud providers."""
    results = []
    # AWS S3 check
    s3_res = check_aws_s3(name, session)
    if s3_res["status"] in ("OPEN", "PROTECTED"):
        results.append(s3_res)

    # GCS check
    gcs_res = check_gcp_storage(name, session)
    if gcs_res["status"] in ("OPEN", "PROTECTED"):
        results.append(gcs_res)

    # Azure check
    azure_res = check_azure_blob(name, session)
    if azure_res["status"] in ("OPEN", "PROTECTED"):
        results.append(azure_res)

    return results


def run_cloud_recon(target: str, max_workers: int = 12, proxy: str = None) -> dict:
    """
    Main orchestration entry point for cloud storage reconnaissance.
    Performs concurrent enumeration of mutated bucket names across AWS, GCP, and Azure.
    """
    console.rule(f"[bold cyan]☁️ ─── CLOUDINT: MULTI-CLOUD STORAGE ENUMERATION ({target.upper()}) ───[/bold cyan]")
    base_name = sanitize_keyword(target)
    console.print(f"[bold blue][*][/bold blue] Base Target Identifier: [bold white]{base_name}[/bold white]")

    # Build candidates
    candidates = []
    for mutation in COMMON_MUTATIONS:
        candidate = f"{base_name}{mutation}"
        if candidate not in candidates:
            candidates.append(candidate)

    console.print(f"[bold blue][*][/bold blue] Probing [bold cyan]{len(candidates)}[/bold cyan] permutations across AWS S3, Google Cloud, and Azure Blob...")

    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    discovered = []
    total_tested = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_bucket_candidate, name, session): name for name in candidates}
        for future in as_completed(futures):
            total_tested += 1
            try:
                res = future.result()
                if res:
                    for item in res:
                        discovered.append(item)
            except Exception:
                pass

    # Separate open and protected buckets
    open_buckets = [b for b in discovered if b["status"] == "OPEN"]
    protected_buckets = [b for b in discovered if b["status"] == "PROTECTED"]

    # Render Summary Table
    if discovered:
        table = Table(
            title=f"☁️ Discovered Cloud Storage Buckets & Containers ({len(discovered)} Found)",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan"
        )
        table.add_column("Provider", style="bold white", width=22)
        table.add_column("Bucket / Container Name", style="cyan")
        table.add_column("Status", style="bold", justify="center")
        table.add_column("Exposure Details & URL", style="white")

        for b in sorted(discovered, key=lambda x: (x["status"] != "OPEN", x["provider"])):
            status_tag = "[bold red]🚨 OPEN / LEAK[/bold red]" if b["status"] == "OPEN" else "[yellow]🔒 PROTECTED[/yellow]"
            url_display = f"{b['details']}\n[dim]{b['url']}[/dim]" if b.get("url") else b["details"]
            table.add_row(
                b["provider"],
                b["bucket"],
                status_tag,
                url_display
            )
        console.print(table)

        if open_buckets:
            console.print(Panel(
                f"[bold red]⚠️ CRITICAL SECURITY WARNING:[/bold red] Found [bold white]{len(open_buckets)}[/bold white] publicly accessible cloud buckets!\n"
                "These buckets can be read or listed without authentication, potentially exposing sensitive databases, source code, or backups.",
                title="[bold red]Public Exposure Alert[/bold red]",
                border_style="red"
            ))
    else:
        console.print("[dim yellow][-] No active or public cloud buckets identified using default mutation set.[/dim yellow]")

    return {
        "target": target,
        "base_identifier": base_name,
        "total_permutations_tested": len(candidates) * 3,
        "discovered_buckets_count": len(discovered),
        "open_buckets_count": len(open_buckets),
        "protected_buckets_count": len(protected_buckets),
        "buckets": discovered,
        "open_buckets": open_buckets,
        "protected_buckets": protected_buckets
    }
