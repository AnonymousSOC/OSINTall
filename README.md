<p align="center">
  <h1 align="center">🕵️ OSINTALL</h1>
  <p align="center">
    <strong>Universal Open Source Intelligence (OSINT) Reconnaissance Framework for Kali Linux</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Debian%20%7C%20Linux-blue?style=for-the-badge&logo=kalilinux" alt="Platform">
    <img src="https://img.shields.io/badge/Python-3.8%2B-brightgreen?style=for-the-badge&logo=python" alt="Python">
    <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
    <img src="https://img.shields.io/badge/Interface-CLI%20%26%20Interactive%20TUI-purple?style=for-the-badge" alt="Interface">
  </p>
</p>

---

## 📖 Overview

**OSINTALL** is a modular, high-performance Open Source Intelligence (OSINT) framework built specifically for security professionals, penetration testers, and OSINT researchers on **Kali Linux** and Debian-based systems.

It combines deep DNS/network intelligence, multi-platform username correlation, email verification, breach discovery, EXIF/GPS extraction, dark web indexing, and secret scanning into a unified, lightning-fast command-line and interactive Terminal UI.

---

## ⚡ Integrated Tool Matrix & Capabilities

| Domain / Category | Tools & Services Covered | Description |
|---|---|---|
| **Domain & Network Intelligence** | `Shodan`, `Censys`, `FOFA`, `Amass`, `theHarvester`, `Subfinder`, `crt.sh`, `DNSDumpster`, `SecurityTrails`, `WhoisXML`, `ViewDNS`, `urlscan.io`, `Lookyloo`, `WiGLE` | Full DNS lookup, RDAP/WHOIS extraction, Certificate Transparency subdomains, HTTP security headers, BSSID/SSID lookups, and Shodan/Censys queries. |
| **Identity & SOCMINT** | `Sherlock`, `Blackbird`, `Maigret`, `WhatsMyName`, `Hunter.io`, `Clearbit`, `Anymail Finder`, `Holehe`, `SocialBlade`, `TweetDeck` | High-speed multi-threaded username search across 30+ platforms, email pattern discovery, domain MX checks, and registered service lookups. |
| **Breach Intelligence** | `Have I Been Pwned (HIBP)`, `DeHashed`, `LeakCheck`, `Intelligence X`, `Snusbase`, `BreachDirectory` | K-anonymity SHA-1 privacy password checks (no raw password sent) and query engines for compromised credential databases. |
| **GEOINT & IMINT** | `ExifTool`, `FOCA`, `Google Lens`, `Yandex Images`, `TinEye`, `PimEyes`, `FaceCheck.ID`, `Google Earth Pro`, `Sentinel Hub`, `DualMaps`, `SunCalc` | Image EXIF metadata parsing, GPS latitude/longitude extraction, instant Google Maps / OpenStreetMap pin generation, facial recognition links, and shadow solar calculators. |
| **Dark Web & Web Archives** | `Ahmia`, `OnionSearch`, `Torry`, `Wayback Machine (Archive.org)`, `Archive.today` | Real-time CDX API querying for historical snapshots and .onion dark web search engines. |
| **Code & Secret Leaks** | `grep.app`, `Sourcegraph`, `PublicWWW`, `Gitleaks`, `TruffleHog` | Public code footprint searches, API key discovery engines, and local repository secret scanning. |
| **Visual Frameworks** | `Maltego`, `SpiderFoot`, `Recon-ng`, `OSINT Framework` | Launchers and deep links for top graph and automation frameworks. |

---

## 🚀 Installation on Kali Linux

Clone the repository and run the automated installer. The installer updates package lists, installs all dependencies (`exiftool`, `whois`, `subfinder`, `theharvester`, `sherlock`, python dependencies), and creates a global `/usr/local/bin/osintall` command.

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
# Domain & Network Reconnaissance (DNS, WHOIS, crt.sh Subdomains, Headers)
osintall -d example.com

# SOCMINT: Multi-platform Username Scan
osintall -u targetuser

# Email Intelligence & Breach Lookups
osintall -e target@company.com

# Image EXIF Metadata & Embedded GPS Coordinates Extraction
osintall -f evidence_photo.jpg

# Safe HIBP Password Leak Check (k-anonymity SHA-1 hash)
osintall -p "TargetPassword123"

# Query Historical Wayback Machine Snapshots
osintall -w targetsite.com

# Dark Web / .onion Search Query
osintall --darkweb "target organization name"

# Search Code Footprints (grep.app, Sourcegraph)
osintall -s "AKIAIOSFODNN7EXAMPLE"

# Display OSINT Frameworks & Graph Tools
osintall --frameworks
```

---

## ⚙️ Configuration & API Keys

OSINTALL works out-of-the-box for passive and unauthenticated OSINT. To enable advanced API querying (Shodan, Censys, Hunter.io, urlscan.io), edit `config/config.json`:

```json
{
  "api_keys": {
    "shodan": "YOUR_SHODAN_API_KEY",
    "censys_api_id": "YOUR_CENSYS_API_ID",
    "censys_api_secret": "YOUR_CENSYS_SECRET",
    "hunter_io": "YOUR_HUNTER_KEY",
    "urlscan_io": "YOUR_URLSCAN_KEY"
  }
}
```

---

## 📤 How to Push to Your GitHub Account

To upload this tool to your own GitHub profile:

1. Create a new repository named `OSINTall` on [GitHub](https://github.com/new).
2. Run the following commands in the `osintall` folder:

```bash
cd osintall
git init
git add .
git commit -m "Initial release of OSINTall framework"
git branch -M main
git remote add origin https://github.com/AnonymousSOC/OSINTall.git
git push -u origin main
```

---

## 📊 Report Generation

OSINTALL automatically exports structured intelligence results to:
- **JSON**: `reports/osint_report_<target>_<timestamp>.json`
- **Dark-Mode HTML**: `reports/osint_report_<target>_<timestamp>.html`

---

## ⚠️ Legal & Ethical Disclaimer

> [!CAUTION]
> This tool is developed strictly for authorized security assessments, digital forensics, defensive research, and educational purposes. Always obtain proper authorization before conducting reconnaissance against systems and organizations you do not own.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
