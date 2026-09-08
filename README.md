<p align="center">
  <h1 align="center">🕵️ OSINTALL v2.1</h1>
  <p align="center">
    <strong>Universal Open Source Intelligence (OSINT) Reconnaissance Framework for Kali Linux</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Debian%20%7C%20Linux-blue?style=for-the-badge&logo=kalilinux" alt="Platform">
    <img src="https://img.shields.io/badge/Python-3.8%2B-brightgreen?style=for-the-badge&logo=python" alt="Python">
    <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
    <img src="https://img.shields.io/badge/Interface-CLI%20%26%20Interactive%20TUI-purple?style=for-the-badge" alt="Interface">
    <img src="https://img.shields.io/badge/Version-v2.1.0-orange?style=for-the-badge" alt="Version">
  </p>
</p>

---

## 📖 Overview

**OSINTALL** is a modular, high-performance Open Source Intelligence (OSINT) framework built specifically for security professionals, penetration testers, red teamers, and OSINT investigators on **Kali Linux** and Debian-based systems.

It combines multi-source passive DNS/network intelligence, live host probing, CNAME subdomain takeover auditing, IP/ASN geolocation, Shodan InternetDB zero-key open port & CVE discovery, web technology/CMS fingerprinting, 40+ platform username correlation with false-positive mitigation, international telephone intelligence (`TELINT`), free cybercrime infostealer malware breach detection, native token/secret pattern scanning, offline interactive Leaflet.js GPS mapping, historical sensitive endpoint mining, and an interactive **Maltego-style Vis.js relationship graph** inside an executive dark-mode HTML dashboard.

---

## ⚡ Integrated Capabilities Matrix

| Domain / Category | Tools & Services Covered | Description |
|---|---|---|
| **Domain & Network Intelligence** | `crt.sh`, `AlienVault OTX`, `HackerTarget`, `Shodan InternetDB`, `Censys`, `WHOIS/RDAP`, `IP-API`, `DNS` | Multi-source subdomain discovery, active A-record host resolution, CNAME subdomain takeover vulnerability auditing, IP Geolocation & ASN discovery, zero-key open port & CVE discovery (InternetDB), SSL/TLS certificate validity checks, SPF/DMARC domain spoofing audits, and HTTP security header analysis. |
| **Web Technologies & CMS** | `Wappalyzer signatures`, `HTTP headers`, `DOM inspection` | Passive fingerprinting of Content Management Systems (WordPress, Drupal, Joomla, Shopify, Ghost), web frameworks (React, Vue, Next.js, Angular, Django, Laravel, Express), web servers (Nginx, Apache, LiteSpeed, IIS), and CDNs (Cloudflare, CloudFront, Akamai). |
| **Phone Recon (TELINT)** | `E.164 Engine`, `Truecaller`, `Sync.me`, `WhatsApp`, `Telegram`, `Viber`, `PhoneInfoga` | International phone number parsing, country dial-code mapping, carrier/line-type indicators (Mobile vs Landline vs Toll-Free), and direct links for messaging app footprints and caller ID directories. |
| **Identity & SOCMINT** | `Sherlock`, `Holehe`, `Maigret`, `WhatsMyName`, `Gravatar`, `Hunter.io`, `Epieos`, `SocialBlade` | Concurrent username search across 40+ platforms with redirect and soft-404 false-positive mitigation, email format & MX verification, Gravatar MD5 profile detection, and infostealer malware infection correlation. |
| **Breach & Threat Intelligence** | `Have I Been Pwned (HIBP)`, `Hudson Rock Cavalier`, `DeHashed`, `LeakCheck`, `Snusbase` | K-anonymity SHA-1 privacy password checks (no raw passwords transmitted), and free, real-time infostealer malware compromise intelligence (RedLine, Vidar, Lumma). |
| **GEOINT & IMINT** | `ExifTool`, `Leaflet.js`, `Google Lens`, `Yandex Images`, `TinEye`, `PimEyes`, `FaceCheck.ID`, `SunCalc` | Image EXIF metadata parsing (camera model, lens, software tampering), GPS latitude/longitude extraction, automatic generation of local interactive Leaflet.js HTML map pins, and reverse image search toolkits. |
| **Code & Secret Leaks** | `Native Regex Scanner`, `Gitleaks`, `TruffleHog`, `grep.app`, `Sourcegraph`, `PublicWWW` | Native pattern scanner for AWS keys, GitHub PATs, Google API keys, Slack tokens, Stripe keys, and Private Keys on local files/directories, plus code search engine queries. |
| **Dark Web & Web Archives** | `Wayback Machine (CDX)`, `Tor SOCKS5`, `Ahmia`, `Torry`, `OnionSearch`, `DuckDuckGo Onion` | Historical snapshot extraction with sensitive file extension filtering (`.env`, `.sql`, `.bak`, `.pdf`, `.xls`), automated sensitive endpoint & high-risk query parameter mining, local Tor proxy status detection, and .onion search engines. |
| **Visual Frameworks & Graphs** | `Vis.js Network`, `Maltego`, `SpiderFoot`, `Recon-ng`, `OSINT Framework` | Built-in interactive draggable node relationship graph embedded in HTML reports, plus launchers and deep links for top graph frameworks. |

---

## 🚀 Installation on Kali Linux

Clone the repository and run the automated installer. The installer updates package lists, installs all dependencies (`exiftool`, `whois`, `subfinder`, `theharvester`, `sherlock`, `holehe`, `phoneinfoga`, `tor`), configures an isolated Python virtual environment, and creates a global `/usr/local/bin/osintall` command.

```bash
# 1. Clone the repository
git clone https://github.com/AnonymousSOC/OSINTall.git

# 2. Navigate to the project directory
cd OSINTall

# 3. Make installer executable & run as root
chmod +x install.sh
sudo ./install.sh
```

Once installed, you can launch `osintall` from any directory in your terminal!

---

## 🖥️ Usage Guide

### 1. Interactive Terminal UI (TUI)
Simply run without arguments:
```bash
osintall
```

### 2. Direct CLI One-Liners

```bash
# Full Domain Recon (DNS, Subdomains, IP Geolocation, Shodan InternetDB Ports/CVEs, Tech Stack, SSL, Headers)
osintall -d example.com

# Phone Number Intelligence: Carrier, E.164, WhatsApp & Telegram Footprints
osintall -n "+14155552671"

# SOCMINT: Multi-platform Username Scan (40+ Platforms with False-Positive Filtering)
osintall -u targetuser

# Email Intelligence, Gravatar, MX, and Free Infostealer Compromise Check
osintall -e target@company.com

# Image EXIF Metadata & Standalone Offline Leaflet.js HTML Map Pin Generation
osintall -f evidence_photo.jpg

# Safe HIBP Password Leak Check (k-anonymity SHA-1 hash)
osintall -p "TargetPassword123"

# Query Historical Wayback Machine Snapshots for Sensitive Files (.env, .sql, .bak, .pdf)
osintall -w example.com --sensitive

# Native Regex Secret Scanner against Local Files, Directories, or Token Strings
osintall -s "AKIAIOSFODNN7EXAMPLE"
osintall --scan-path /path/to/project

# Route All Network Queries Through Proxy (Burp Suite or Tor SOCKS5)
osintall -d example.com --proxy "http://127.0.0.1:8080"
osintall -d example.com --proxy "socks5://127.0.0.1:9050"

# Dark Web / .onion Search Query & Tor Service Verification
osintall --darkweb "target organization"

# Display OSINT Frameworks & Graph Tools
osintall --frameworks
```

---

## 📊 Executive HTML Dashboard & Visual Graph Reporting

OSINTALL automatically compiles findings into:
- **Interactive Dark-Mode HTML Dashboard**: `reports/osint_report_<target>_<timestamp>.html`
  - **Embedded Vis.js Node Relationship Graph**: Draggable, zoomable topology connecting target, IPs, ASNs, open ports, CVEs, subdomains, technologies, and compromised credentials.
  - **Shodan InternetDB Telemetry**: Open ports, software CPEs, and CVE tags.
  - **Detected Web Technologies**: CMS, web frameworks, and CDN infrastructure.
  - **TELINT Intelligence Card**: Formatted telephony numbers, carrier indicators, and messaging app profile links.
  - **Security Badges & Tables**: SPF, DMARC, SSL validity, and live host indicators.
- **Structured JSON**: `reports/osint_report_<target>_<timestamp>.json`
- **Interactive Leaflet Map**: `reports/geoint_map_<target>_<timestamp>.html` (generated whenever GPS metadata is detected).

---

## ⚙️ Configuration & API Keys

OSINTALL works out-of-the-box with **zero API keys required** using passive intelligence engines and free endpoints (including Shodan InternetDB and Hudson Rock Cavalier). To enable optional authenticated features, edit `config/config.json`:

```json
{
  "api_keys": {
    "shodan": "YOUR_SHODAN_API_KEY",
    "censys_api_id": "YOUR_CENSYS_API_ID",
    "censys_api_secret": "YOUR_CENSYS_SECRET",
    "haveibeenpwned": "YOUR_HIBP_API_KEY",
    "hunter_io": "YOUR_HUNTER_KEY",
    "urlscan_io": "YOUR_URLSCAN_KEY"
  }
}
```

---

## ⚠️ Legal & Ethical Disclaimer

> [!CAUTION]
> This tool is developed strictly for authorized security assessments, digital forensics, defensive research, bug bounties, and educational purposes. Always obtain proper authorization before conducting reconnaissance against systems and organizations you do not own.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
