<p align="center">
  <h1 align="center">🕵️ OSINTALL v2.2</h1>
  <p align="center">
    <strong>Universal Open Source Intelligence (OSINT) Reconnaissance Framework for Kali Linux</strong>
  </p>
  <p align="center">
    <a href="https://www.kali.org/"><img src="https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Debian%20%7C%20Linux-blue?style=for-the-badge&logo=kalilinux" alt="Platform"></a>
    <img src="https://img.shields.io/badge/Python-3.8%2B-brightgreen?style=for-the-badge&logo=python" alt="Python">
    <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
    <img src="https://img.shields.io/badge/Interface-CLI%20%26%20Interactive%20TUI-purple?style=for-the-badge" alt="Interface">
    <img src="https://img.shields.io/badge/Version-v2.2.0-orange?style=for-the-badge" alt="Version">
    <img src="https://img.shields.io/badge/Architecture-Zero--Key%20Free-red?style=for-the-badge" alt="Architecture">
  </p>
</p>

```text
  ██████╗ ███████╗██╗███╗   ██╗████████╗ █████╗ ██╗     ██╗     
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔══██╗██║     ██║     
 ██║   ██║███████╗██║██╔██╗ ██║   ██║   ███████║██║     ██║     
 ██║   ██║╚════██║██║██║╚██╗██║   ██║   ██╔══██║██║     ██║     
 ╚██████╔╝███████║██║██║ ╚████║   ██║   ██║  ██║███████╗███████╗
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
```

---

## 📖 Overview

**OSINTALL** is an enterprise-grade, modular Open Source Intelligence (OSINT) and defensive reconnaissance framework designed specifically for security professionals, penetration testers, red teamers, digital forensic analysts, and bug bounty hunters on **Kali Linux** and Debian-based systems.

Built with a **zero-key philosophy**, OSINTALL executes high-fidelity passive intelligence collection without requiring paid subscriptions or mandatory API keys. It aggregates multi-source passive DNS, probes live hosts, identifies CNAME subdomain takeovers, audits IP geolocation and BGP ASNs, conducts zero-key open port & CVE vulnerability scans via Shodan InternetDB, fingerprints web technologies/CMS platforms, sweeps reverse IP co-hosting environments, enumerates multi-cloud storage buckets (`AWS S3`, `Google Cloud`, `Azure Blob`), scores cybercrime malware reputations using `Abuse.ch` feeds, mines sensitive endpoints and parameters from Wayback archives, parses camera EXIF/GPS telemetry into offline interactive Leaflet.js HTML maps, discovers social footprints across 40+ platforms with false-positive mitigation, checks infostealer breach telemetry, and exports reports into modern dark-mode HTML dashboards featuring an interactive **Vis.js Node Relationship Graph**, **Maltego-ready Entity CSVs**, and structured spreadsheets.

---

## ⚡ Integrated Capabilities Matrix

| Domain / Category | Primary Modules & Services | Operational Capabilities |
|---|---|---|
| **🌐 Domain & Network Recon** | `crt.sh`, `AlienVault OTX`, `HackerTarget`, `Shodan InternetDB`, `WHOIS/RDAP`, `IP-API`, `dnspython` | Multi-source passive subdomain enumeration, concurrent A-record host resolution, CNAME subdomain takeover vulnerability auditing (20+ cloud signatures), IP Geolocation, BGP ASN ownership, reverse IP co-hosting discovery, zero-key open port & CVE discovery, SSL/TLS certificate validity tracking, SPF/DMARC email spoofing audits, and HTTP security header inspections. |
| **☁️ Cloud Recon (CLOUDINT)** | `AWS S3`, `Google Cloud Storage (GCS)`, `Microsoft Azure Blob` | Targeted permutation engine discovering exposed cloud storage infrastructure. Categorizes buckets into public listings (`200 OK` severe leak risk), access-restricted existing accounts (`403 Forbidden`), and available names (`404 Not Found`). |
| **🛡️ Threat Intelligence & Reputation** | `Abuse.ch URLhaus`, `Abuse.ch ThreatFox`, `VirusTotal`, `AbuseIPDB` | Zero-key querying of global cybercrime intelligence feeds. Identifies active malware distribution URLs, payload hashes, and botnet Command & Control (C2) indicators (Cobalt Strike, Emotet, Qakbot, RedLine), computing a unified **Threat Severity Score (0 to 100)**. |
| **🔎 Search Dorking (DORKINT)** | `Google Search`, `GitHub Code Search`, `Shodan SSL Dorks` | Automated query generator creating clickable hunting links for confidential documents (`.pdf`, `.xlsx`), exposed environment files (`.env`, `.sql`, `.bak`, `.log`), administrative portals (`/admin`, `/swagger`, `/graphql`), and target-scoped API keys on GitHub. |
| **🛠️ Tech Stack Fingerprinting** | `Wappalyzer signatures`, `HTTP Headers`, `DOM Inspection` | Passive identification of Content Management Systems (WordPress, Drupal, Joomla, Shopify, Ghost), frontend frameworks (React, Vue, Next.js, Angular), backend servers (Nginx, Apache, LiteSpeed, IIS, PHP, Node.js), and CDN/WAF providers (Cloudflare, CloudFront, Akamai, Imperva). |
| **📱 Phone Recon (TELINT)** | `E.164 Engine`, `RFC 3966`, `Truecaller`, `Sync.me`, `WhatsApp`, `Telegram`, `Viber` | International phone number parsing, country dial-code mapping, carrier/line-type indicators (Mobile vs Fixed vs VoIP), and direct deep links for messaging applications and caller ID directories. |
| **👤 Identity & SOCMINT** | `Sherlock`, `Holehe`, `Maigret`, `WhatsMyName`, `Gravatar`, `Hunter.io`, `Epieos` | Concurrent cross-platform username scanning across 40+ sites with response-body and redirect false-positive mitigation, email format validation, MX record audits, and MD5 Gravatar avatar detection. |
| **🚨 Breach & Infostealer Intel** | `Hudson Rock Cavalier`, `Have I Been Pwned (HIBP)`, `DeHashed`, `Snusbase` | K-anonymity SHA-1 privacy password checks (no plaintext transmitted), and free Hudson Rock cybercrime intelligence correlating domain and email exposures against infostealer malware infections (RedLine, Vidar, Lumma). |
| **📸 GEOINT & File Metadata** | `ExifTool`, `Pillow`, `Leaflet.js`, `Google Lens`, `Yandex Images`, `TinEye`, `PimEyes` | Deep EXIF/IPTC metadata extraction (camera make, model, lens, editing software), GPS coordinate parsing, automatic generation of standalone offline interactive Leaflet.js HTML map files, and reverse image toolkits. |
| **💻 Code Secrets & Leaks** | `Native Regex Scanner`, `Gitleaks`, `TruffleHog`, `grep.app`, `Sourcegraph` | Built-in regex rule scanner for AWS keys (`AKIA...`), GitHub PATs (`ghp_...`), Google API keys, Slack tokens, Stripe keys, JWTs, and Private Key headers across strings, files, or local directory trees. |
| **🏛️ Dark Web & Web Archives** | `Wayback Machine (CDX)`, `Tor SOCKS5 Proxy`, `Ahmia`, `Torry`, `OnionSearch` | Historical snapshot mining with sensitive file extension filtering (`.env`, `.sql`, `.bak`, `.pdf`, `.xls`), automated sensitive endpoint & parameter discovery (`?url=`, `?file=`, `?id=`), and local Tor SOCKS proxy detection (`127.0.0.1:9050`). |
| **📊 Visual Graph & Multi-Export** | `Vis.js Network`, `Maltego Entity CSV`, `Flat CSV`, `Executive HTML Dashboard` | Interactive draggable node relationship graph in dark-mode HTML reports, Maltego Entity CSV generation for instant drag-and-drop import on Kali Linux, tabular flat CSV spreadsheets, and structured JSON output. |

---

## 🖥️ Interactive Terminal UI (TUI)

Launch the full-featured interactive Rich terminal console by running `osintall` without arguments:

```text
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option ┃ Module Category                        ┃ Capabilities                                                ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│   1    │ 🌐 Domain & Network Intelligence       │ WHOIS, DNS, Subdomains, IP Geo, InternetDB, SSL, Reverse IP │
│   2    │ 👤 Identity & SOCMINT                  │ Multi-platform Username Scanner (40+ sites), Email Recon    │
│   3    │ 📱 Phone Number Intelligence (TELINT)  │ Carrier & Telecom Lookup, E.164, WhatsApp/Telegram Footprint│
│   4    │ ☁️ Cloud Storage Recon (CLOUDINT)      │ Audit AWS S3, Google Cloud Storage, Azure Blob Leaks        │
│   5    │ 🛡️ Threat Intelligence & Reputation    │ Abuse.ch URLhaus & ThreatFox Telemetry, Threat Risk Scoring │
│   6    │ 🔎 Targeted Search Dorks (DORKINT)     │ Automated Google & GitHub Dorks for Confidential Documents  │
│   7    │ 🚨 Breach Intelligence & Leaks         │ HIBP k-anonymity Passwords, Hudson Rock Infostealer Malware │
│   8    │ 📸 GEOINT & File Metadata              │ EXIF/GPS, Device Info, Offline Leaflet.js HTML Map Pin      │
│   9    │ 🏛️ Dark Web & Historical Archives      │ Wayback Sensitive Endpoint Mining, Tor SOCKS Proxy Check    │
│   10   │ 💻 Code Repos & Secret Detection       │ Native Regex Scanner (AWS, PAT, Slack, Stripe, Keys)        │
│   11   │ 🕸️ Link Analysis Frameworks            │ Maltego, SpiderFoot, Recon-ng, OSINT Framework Launchers    │
│   12   │ ⚡ Full Automated Recon Suite          │ Full Domain, Cloud, Threat & Target Recon (HTML/CSV/Maltego)│
│   0    │ ❌ Exit                                │ Close OSINTALL                                              │
└━━━━━━━━┴━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┴━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┘
```

---

## 🚀 Installation & Update Guide

### 🐧 Fresh Installation on Kali Linux / Debian

```bash
# 1. Clone the repository
git clone https://github.com/AnonymousSOC/OSINTall.git

# 2. Navigate into the directory
cd OSINTall

# 3. Make installer executable & run as root
chmod +x install.sh
sudo ./install.sh
```

The installer automatically:
1. Updates package lists (`apt update`).
2. Installs required system binaries (`python3-venv`, `libimage-exiftool-perl`, `whois`, `dnsutils`, `curl`, `wget`, `jq`).
3. Installs integrated Kali tools (`subfinder`, `theharvester`, `sherlock`, `holehe`, `phoneinfoga`, `tor`).
4. Creates an isolated Python virtual environment (`.venv`) and installs all Python dependencies.
5. Symlinks `/usr/local/bin/osintall` so the tool is accessible globally from any shell.

---

### 🔄 Updating an Existing Clone on Kali Linux

If you already have OSINTall cloned on your machine, pull the latest release cleanly:

```bash
cd ~/OSINTall
git fetch origin
git reset --hard origin/main
chmod +x install.sh
sudo ./install.sh
```

---

## 💻 CLI Reference & One-Liners

### Full Flag Specification

| Flag | Long Argument | Value Required | Description |
|---|---|:---:|---|
| `-d` | `--domain` | `<domain>` | Target domain for Network, DNS, Subdomains, Ports, CVEs & Tech Recon |
| `-c` | `--cloud` | `<target>` | Target domain or keyword for Multi-Cloud storage bucket auditing |
| `--threat` | | `<target>` | Query Abuse.ch URLhaus & ThreatFox for malware reputation & threat scores |
| `--dorks` | | `<domain>` | Generate automated Google, GitHub, and Shodan search dorks |
| `-u` | `--user` | `<username>` | Target username for 40+ platform SOCMINT correlation |
| `-e` | `--email` | `<email>` | Target email for MX verification, Gravatar, and infostealer check |
| `-n` | `--phone` | `<number>` | Target phone number (E.164 format, e.g. `+14155552671`) for TELINT |
| `-f` | `--file` | `<path>` | Image/document path for EXIF metadata and offline HTML map generation |
| `-p` | `--password` | `<password>` | Safe k-anonymity SHA-1 password breach check via Have I Been Pwned |
| `-w` | `--wayback` | `<domain>` | Query Archive.org CDX snapshots for historical pages and endpoints |
| `--sensitive` | | *None* | Filter Wayback results for sensitive files (`.env`, `.sql`, `.bak`, `.pdf`) |
| `--darkweb` | | `<query>` | Query Tor search engines (Ahmia) and check local Tor SOCKS proxy |
| `-s` | `--secret-search`| `<string>` | Scan a token string or query code repositories for leaked secrets |
| `--scan-path` | | `<dir_path>` | Recursively scan local directory or git repo with native secret rules |
| `--frameworks`| | *None* | Display quick links and launchers for external OSINT frameworks |
| `-o` | `--output` | `json\|html\|csv\|maltego\|all` | Select specific report export formats (Default: `all`) |
| `--csv` | | *None* | Force export of Flat CSV and Maltego-compatible Entity CSV reports |
| `--proxy` | | `<proxy_url>`| Route outgoing requests through HTTP/HTTPS or SOCKS5 proxy |
| `-i` | `--interactive`| *None* | Launch the interactive Rich terminal console |

---

### Command Examples

```bash
# 1. Full Domain Reconnaissance with Shodan InternetDB, Subdomains, and Tech Stack
osintall -d example.com

# 2. Multi-Cloud Storage Bucket Enumeration (AWS S3, GCP, Azure Blob)
osintall -c example

# 3. Zero-Key Threat Intelligence & Abuse.ch Malware Reputation Scoring
osintall --threat example.com

# 4. Generate Automated Search Dorks for Confidential Documents and Backups
osintall --dorks example.com

# 5. Full Reconnaissance Exporting to HTML Dashboard, Flat CSV & Maltego Entity CSV
osintall -d example.com --csv

# 6. Telephone Intelligence (E.164, WhatsApp, Telegram, Carrier Indicators)
osintall -n "+14155552671"

# 7. Multi-Platform Username Search with False-Positive Filtering
osintall -u targetuser

# 8. Email Intelligence with MX Check and Free Hudson Rock Infostealer Lookup
osintall -e target@company.com

# 9. Extract Image EXIF Metadata and Generate Offline Interactive Leaflet Map
osintall -f evidence_photo.jpg

# 10. Query Historical Wayback Machine Snapshots for Sensitive Files
osintall -w example.com --sensitive

# 11. Native Regex Secret Scanner against a Local Project Directory
osintall --scan-path /path/to/source_code

# 12. Route All Outgoing Requests through Tor SOCKS5 or Burp Suite
osintall -d example.com --proxy "socks5://127.0.0.1:9050"
osintall -d example.com --proxy "http://127.0.0.1:8080"
```

---

## 📊 Comprehensive Reporting & Visualization Architecture

Whenever an analysis is performed, OSINTALL automatically generates cross-referenced intelligence assets in the `reports/` directory:

```text
reports/
├── osint_report_<target>_<timestamp>.html      # Executive Dark-Mode Dashboard with Vis.js
├── osint_report_<target>_<timestamp>.json      # Machine-Readable Structured Intelligence
├── osint_report_<target>_<timestamp>.csv       # Tabular Flat CSV Spreadsheet
├── maltego_entities_<target>_<timestamp>.csv   # Maltego Drag-and-Drop Import CSV
└── geoint_map_<target>_<timestamp>.html        # Standalone Leaflet.js GPS Coordinate Map
```

### 1. Executive HTML Dashboard with Vis.js Graph
- **Interactive Vis.js Node Graph**: Fully interactive, draggable, zoomable network topology diagram mapping:
  `Target Node` ➔ `Resolved IPs` ➔ `BGP ASNs` ➔ `Open Ports` ➔ `CVE Vulnerabilities` ➔ `Subdomains` ➔ `Cloud Buckets` ➔ `Threat IoCs` ➔ `Identities`.
- **Cloud Storage Audit Card**: Color-coded exposure badges (`🚨 PUBLIC LEAK (200)` vs `🔒 PROTECTED (403)`).
- **Threat Reputation Card**: Real-time Threat Severity meter (0-100), active malware URLs, and ThreatFox IoC signatures.
- **Automated Search Dorks Card**: Clickable, one-click execution buttons for Google, GitHub, and Shodan queries.
- **Technical Telemetry**: Shodan InternetDB open ports, software CPEs, CVE tags, SPF/DMARC status, and HTTP security headers.

### 2. Maltego Entity CSV (`maltego_entities_*.csv`)
Formatted specifically for **Maltego on Kali Linux**:
- Entities mapped: `maltego.Domain`, `maltego.IPv4Address`, `maltego.DNSName`, `maltego.NSRecord`, `maltego.MXRecord`, `maltego.URL`, `maltego.PhoneNumber`.
- Import directly via: **Maltego ➔ Import ➔ Import Graph from CSV**.

### 3. Standalone Leaflet.js GPS Mapping (`geoint_map_*.html`)
When GPS coordinates are identified within image EXIF metadata, an offline interactive HTML map is rendered featuring street/satellite layers and a pin drop with exact latitude, longitude, and altitude details.

---

## 📁 Repository Structure

```text
OSINTall/
├── config/
│   └── config.json               # Configurable timeouts, user-agents, and optional API keys
├── modules/
│   ├── __init__.py               # Package initialization
│   ├── banner.py                 # ANSI/Rich banners, terminal formatting, proxy handler
│   ├── breach_intel.py           # HIBP k-anonymity checks & Hudson Rock infostealer intel
│   ├── cloud_recon.py            # Multi-cloud storage scanner (AWS S3, GCP, Azure Blob)
│   ├── code_secrets.py           # Native regex secret detection & code search engines
│   ├── darkweb_archives.py       # Wayback CDX mining & Tor daemon verification
│   ├── domain_recon.py           # DNS, Subdomains, InternetDB, Tech Stack, Dorks, Reverse IP
│   ├── geoint_meta.py            # EXIF parser & standalone Leaflet.js HTML map generator
│   ├── phone_recon.py            # TELINT parser, E.164 formatting & messaging footprints
│   ├── report_generator.py       # HTML Vis.js dashboard, Flat CSV & Maltego CSV exporters
│   └── socmint.py                # 40+ site username correlation & email intelligence
├── reports/                      # Output directory for HTML, JSON, and CSV reports
├── .gitignore                    # Git ignore rules for reports, pycache, and virtualenvs
├── .gitattributes                # Enforces Unix LF line endings for shell scripts
├── install.sh                    # Automated installer for Kali Linux & Debian
├── osintall.py                   # Main CLI entry point & Interactive TUI engine
├── requirements.txt              # Python dependency requirements
├── setup.py                      # Pip package build configuration
└── README.md                     # Documentation & usage guide
```

---

## ⚙️ Configuration & Optional API Keys

OSINTALL operates fully with **zero API keys required**. To unlock optional authenticated lookups for enterprise APIs, populate your keys in `config/config.json`:

```json
{
  "settings": {
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0 OSINTALL/2.2",
    "request_timeout_seconds": 8,
    "max_threads": 25,
    "save_reports_by_default": true,
    "reports_directory": "reports"
  },
  "api_keys": {
    "shodan": "YOUR_SHODAN_KEY",
    "censys_api_id": "YOUR_CENSYS_API_ID",
    "censys_api_secret": "YOUR_CENSYS_SECRET",
    "haveibeenpwned": "YOUR_HIBP_API_KEY",
    "hunter_io": "YOUR_HUNTER_KEY",
    "urlscan_io": "YOUR_URLSCAN_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_KEY"
  }
}
```

---

## ⚠️ Legal & Ethical Disclaimer

> [!CAUTION]
> **OSINTALL is developed strictly for authorized security auditing, defensive threat research, digital forensics, bug bounties, and educational intelligence analysis.**
> Always obtain explicit, written authorization before conducting active reconnaissance against systems, domains, or organizations you do not own. The authors and contributors assume no liability for misuse or damages resulting from this framework.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
