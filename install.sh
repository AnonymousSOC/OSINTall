#!/usr/bin/env bash
# ==============================================================================
# OSINTALL Installer for Kali Linux & Debian-based Distributions (v2.1)
# GitHub: https://github.com/AnonymousSOC/OSINTall
# ==============================================================================

set -e

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Print Banner
clear
echo -e "${CYAN}${BOLD}"
cat << "EOF"
  ██████╗ ███████╗██╗███╗   ██╗████████╗ █████╗ ██╗     ██╗     
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔══██╗██║     ██║     
 ██║   ██║███████╗██║██╔██╗ ██║   ██║   ███████║██║     ██║     
 ██║   ██║╚════██║██║██║╚██╗██║   ██║   ██╔══██║██║     ██║     
 ╚██████╔╝███████║██║██║ ╚████║   ██║   ██║  ██║███████╗███████╗
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
EOF
echo -e "${PURPLE}  [!] Automated Installer for Kali Linux & Security Distributions (v2.1)${NC}"
echo -e "${BLUE}  ================================================================${NC}"
echo ""

# 1. Check Root Privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run the installer with root privileges: sudo ./install.sh${NC}"
    exit 1
fi

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="/usr/local/bin/osintall"

echo -e "${BLUE}[*] Target Installation Directory:${NC} ${INSTALL_DIR}"

# 2. Update System Package Lists
echo -e "\n${YELLOW}[+] Step 1/5: Updating system package index (apt update)...${NC}"
apt-get update -y || {
    echo -e "${RED}[!] Warning: apt update had warnings, continuing with installation...${NC}"
}

# 3. Install Required System Dependencies
echo -e "\n${YELLOW}[+] Step 2/5: Installing system packages & OSINT binary tools...${NC}"
APT_PACKAGES=(
    "python3"
    "python3-pip"
    "python3-venv"
    "python3-dev"
    "git"
    "curl"
    "wget"
    "jq"
    "whois"
    "dnsutils"
    "libimage-exiftool-perl"
)

for pkg in "${APT_PACKAGES[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "  ${GREEN}[✓] System package already installed:${NC} $pkg"
    else
        echo -e "  ${CYAN}[+] Installing:${NC} $pkg..."
        apt-get install -y "$pkg" || echo -e "${RED}[!] Could not install $pkg via apt.${NC}"
    fi
done

# 4. Optional Kali Linux OSINT Tool Suite
echo -e "\n${YELLOW}[+] Step 3/5: Checking optional Kali OSINT tool packages...${NC}"
OPTIONAL_KALI_TOOLS=(
    "subfinder"
    "theharvester"
    "sherlock"
    "holehe"
    "phoneinfoga"
    "amass"
    "spiderfoot"
    "gitleaks"
    "tor"
)

for tool in "${OPTIONAL_KALI_TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "  ${GREEN}[✓] Integrated CLI tool found:${NC} $tool"
    else
        echo -e "  ${PURPLE}[i] Attempting to install optional tool:${NC} $tool..."
        apt-get install -y "$tool" 2>/dev/null || echo -e "  ${YELLOW}[-] $tool not found in apt repo (OSINTALL built-in native engine will be used).${NC}"
    fi
done

# 5. Setup Python Virtual Environment (Fixes Debian/Kali PEP 668 externally-managed-environment)
echo -e "\n${YELLOW}[+] Step 4/5: Configuring Python environment and installing dependencies...${NC}"
VENV_DIR="${INSTALL_DIR}/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo -e "  ${CYAN}[+] Creating isolated Python virtual environment in .venv...${NC}"
    python3 -m venv "$VENV_DIR"
fi

# Activate Virtual Environment & Install Requirements
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel
echo -e "  ${CYAN}[+] Installing Python dependencies from requirements.txt...${NC}"
"$VENV_DIR/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

# Ensure reports directory exists with write permissions for regular users
mkdir -p "${INSTALL_DIR}/reports"
chmod 777 "${INSTALL_DIR}/reports"

# Grant global read/execute on venv so non-root users can execute
chmod -R a+rX "$VENV_DIR"
chmod +x "${INSTALL_DIR}/osintall.py"

# 6. Create Global Wrapper in /usr/local/bin/osintall
echo -e "\n${YELLOW}[+] Step 5/5: Creating global system command '/usr/local/bin/osintall'...${NC}"
cat << EOF > "$BIN_PATH"
#!/usr/bin/env bash
# Global launcher for OSINTALL v2.0
"${VENV_DIR}/bin/python3" "${INSTALL_DIR}/osintall.py" "\$@"
EOF

chmod +x "$BIN_PATH"

echo -e "\n${GREEN}${BOLD}[✔] SUCCESS: OSINTALL v2.0 installation complete!${NC}"
echo -e "${CYAN}----------------------------------------------------------------${NC}"
echo -e "You can now run OSINTALL from anywhere by typing: ${BOLD}${GREEN}osintall${NC}"
echo -e ""
echo -e "Quick Usage Examples:"
echo -e "  ${BOLD}osintall${NC}                                 # Interactive Terminal UI"
echo -e "  ${BOLD}osintall -d example.com${NC}                  # Full Domain Recon (DNS, Subdomains, IP Geo, Headers)"
echo -e "  ${BOLD}osintall -u targetuser${NC}                   # SOCMINT (40+ Platforms)"
echo -e "  ${BOLD}osintall -e target@domain.com${NC}            # Email, MX, Gravatar & Infostealer checks"
echo -e "  ${BOLD}osintall -f photo.jpg${NC}                    # EXIF & Offline Leaflet Map Pin"
echo -e "  ${BOLD}osintall -s 'AKIAIOSFODNN7EXAMPLE'${NC}       # Native Regex Secret Scanner"
echo -e "  ${BOLD}osintall -w example.com --sensitive${NC}        # Historical Sensitive File Discovery"
echo -e "  ${BOLD}osintall --help${NC}                          # View all options"
echo -e "${CYAN}----------------------------------------------------------------${NC}"
