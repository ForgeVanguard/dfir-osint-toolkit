#!/usr/bin/env bash
#
# install-kali-dfir-osint.sh
# Installs a DFIR + OSINT + recon toolset on Kali Linux (bare metal, VM or WSL2).
#
# Usage:
#   chmod +x install-kali-dfir-osint.sh
#   sudo ./install-kali-dfir-osint.sh
#
# What it does:
#   - apt: base build/CLI tools, forensics tools, Kali-packaged OSINT tools
#   - pipx (as the invoking user): Python OSINT tools and Volatility 3
#   - go install (as the invoking user): ProjectDiscovery / tomnomnom recon tools
#   - Creates ~/DFIR/{Tools,Cases,Scripts,Logs} and ~/OSINT for the invoking user
#   - Writes ~/DFIR/Scripts/update-all-tools.sh
#   - Safe to re-run: installed packages are skipped
#
# Pairs with windows/Install-DFIRTools.ps1 (run Linux tools against /mnt/c evidence in WSL).
#
# Author: Steven Drew
# License: MIT

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()     { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)."
    exit 1
fi

# Under sudo, $HOME is root's. Install user-level tools for the real user.
TARGET_USER="${SUDO_USER:-root}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
if [[ -z "$TARGET_HOME" || ! -d "$TARGET_HOME" ]]; then
    error "Could not resolve home directory for $TARGET_USER."
    exit 1
fi

as_user() {
    if [[ "$TARGET_USER" == "root" ]]; then
        "$@"
    else
        sudo -u "$TARGET_USER" -H env PATH="$TARGET_HOME/.local/bin:$TARGET_HOME/go/bin:$PATH" "$@"
    fi
}

is_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

apt_install_list() {
    local pkg
    for pkg in "$@"; do
        if is_installed "$pkg"; then
            log "$pkg already installed."
        else
            log "Installing $pkg..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" \
                || warn "Could not install $pkg (check the package name for your release)"
        fi
    done
}

BASE_DIR="$TARGET_HOME/DFIR"
OSINT_DIR="$TARGET_HOME/OSINT"
SCRIPTS_DIR="$BASE_DIR/Scripts"

mkdir -p "$BASE_DIR"/{Tools,Cases,Scripts,Logs} "$OSINT_DIR"
chown -R "$TARGET_USER":"$TARGET_USER" "$BASE_DIR" "$OSINT_DIR"

log "Installing for user: $TARGET_USER ($TARGET_HOME)"

# =============================================================================
# 1. System update and base tools
# =============================================================================
log "=== Section 1: System update and base tools ==="

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -qq

apt_install_list \
    build-essential git curl wget unzip zip jq yq ripgrep fzf bat fd-find \
    tmux zsh python3 python3-pip python3-venv pipx golang-go ca-certificates

success "Base tools installed."

# =============================================================================
# 2. DFIR / forensics
# =============================================================================
log "=== Section 2: DFIR / forensics tools ==="

apt_install_list \
    sleuthkit yara binwalk foremost libimage-exiftool-perl bulk-extractor \
    plaso hashcat john tshark wireshark tcpdump nmap whois dnsutils \
    strace ltrace file xxd hexedit

success "DFIR tools installed."

# =============================================================================
# 3. OSINT (Kali-packaged)
# =============================================================================
log "=== Section 3: OSINT tools (apt) ==="

# Kali packages these; apt versions track Kali's Python and are easier to maintain.
apt_install_list theharvester recon-ng sherlock

success "Kali-packaged OSINT tools installed."

# =============================================================================
# 4. OSINT (Python, isolated with pipx)
# =============================================================================
log "=== Section 4: OSINT tools (pipx, as $TARGET_USER) ==="

as_user pipx ensurepath >/dev/null 2>&1 || true

PIPX_TOOLS=(volatility3 maigret holehe)
for tool in "${PIPX_TOOLS[@]}"; do
    if as_user pipx list --short 2>/dev/null | grep -q "^$tool "; then
        log "$tool already installed (pipx)."
    else
        log "Installing $tool via pipx..."
        as_user pipx install "$tool" >/dev/null || warn "pipx install of $tool failed"
    fi
done

success "pipx tools installed."

# =============================================================================
# 5. Recon tools (Go, as the invoking user)
# =============================================================================
log "=== Section 5: Recon tools (go install, as $TARGET_USER) ==="

GO_TOOLS=(
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    tool_name="$(basename "${tool%@*}")"
    [[ "$tool_name" == "..." ]] && tool_name="amass"
    if [[ -x "$TARGET_HOME/go/bin/$tool_name" ]] || command -v "$tool_name" >/dev/null 2>&1; then
        log "$tool_name already installed."
    else
        log "Installing $tool_name via go install..."
        as_user go install "$tool" || warn "go install of $tool_name failed"
    fi
done

# PhoneInfoga ships as a release binary, not a Python package.
if ! command -v phoneinfoga >/dev/null 2>&1; then
    warn "phoneinfoga not installed. Get the release binary from github.com/sundowndev/phoneinfoga/releases if you need it."
fi

success "Go-based recon tools installed."

# =============================================================================
# 6. Extra CLI tools
# =============================================================================
log "=== Section 6: Extra CLI tools ==="

apt_install_list httpie zoxide eza git-delta lazygit neovim

# =============================================================================
# 7. Update helper
# =============================================================================
log "=== Section 7: Update helper ==="

cat > "$SCRIPTS_DIR/update-all-tools.sh" << 'UPDATER'
#!/usr/bin/env bash
# Updates apt, pipx and Go-installed DFIR/OSINT tools.
set -euo pipefail
echo "Updating apt packages..."
sudo apt-get update && sudo apt-get full-upgrade -y
echo "Updating pipx tools..."
pipx upgrade-all
echo "Updating Go tools..."
for t in \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    github.com/tomnomnom/assetfinder@latest \
    github.com/tomnomnom/waybackurls@latest \
    github.com/lc/gau/v2/cmd/gau@latest; do
    go install "$t"
done
echo "Update complete."
UPDATER
chmod +x "$SCRIPTS_DIR/update-all-tools.sh"
chown "$TARGET_USER":"$TARGET_USER" "$SCRIPTS_DIR/update-all-tools.sh"

success "Installation complete."

cat << SUMMARY

==============================================================================
                     KALI DFIR + OSINT SETUP COMPLETE
==============================================================================

Directories (owned by $TARGET_USER):
  ~/DFIR/Tools  ~/DFIR/Cases  ~/DFIR/Scripts  ~/DFIR/Logs  ~/OSINT

DFIR:  volatility3 (vol), sleuthkit (fls, icat, ...), yara, binwalk, plaso
       (log2timeline.py), bulk_extractor, exiftool, foremost, hashcat, john, tshark
OSINT: theHarvester, recon-ng, sherlock, maigret, holehe,
       amass, subfinder, assetfinder, waybackurls, gau, httpx, nuclei

Next steps:
  1. Open a new shell (or 'source ~/.bashrc') so ~/.local/bin and ~/go/bin are on PATH.
  2. WSL only: Windows evidence is under /mnt/c, for example:
       cd /mnt/c/Users/<USERNAME>/
       cd /mnt/c/DFIR/Cases/
     Optional PATH additions for Windows tools from Kali:
       export PATH="\$PATH:/mnt/c/DFIR/Tools/EZTools"
  3. Update everything later with: ~/DFIR/Scripts/update-all-tools.sh
  4. OSINT OPSEC: use a dedicated VM or browser profile and route through a VPN or
     proxychains/Tor. Do not run heavy recon from a daily-driver profile.

SUMMARY
