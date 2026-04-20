#!/usr/bin/env bash
################################################################################
# Paintester — Installer
# Installs tools and prepares ~/.recon.conf on Debian/Ubuntu/Kali/macOS
# Usage: ./install.sh [--no-sudo] [--skip-seclists]
################################################################################

set -uo pipefail

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'
log()   { echo -e "${B}[$(date +%H:%M:%S)]${N} ${G}$*${N}"; }
warn()  { echo -e "${Y}[!] $*${N}"; }
err()   { echo -e "${R}[X] $*${N}" >&2; }
info()  { echo -e "${C}[i] $*${N}"; }

USE_SUDO=1
SKIP_SECLISTS=0
for arg in "$@"; do
    case "$arg" in
        --no-sudo) USE_SUDO=0 ;;
        --skip-seclists) SKIP_SECLISTS=1 ;;
        -h|--help)
            cat <<EOF
Usage: $0 [options]
  --no-sudo         Don't use sudo (install to \$HOME only)
  --skip-seclists   Skip SecLists clone (huge, ~1GB)
  -h, --help        Show this help
EOF
            exit 0
            ;;
    esac
done

SUDO=""
[ "$USE_SUDO" -eq 1 ] && SUDO="sudo"

OS="unknown"
if [ -f /etc/debian_version ]; then
    OS="debian"
elif [ "$(uname)" = "Darwin" ]; then
    OS="mac"
elif [ -f /etc/arch-release ]; then
    OS="arch"
fi
log "Detected OS: $OS"

cat <<'EOF'

 ╔════════════════════════════════════════════════╗
 ║   Paintester — Installer v1                    ║
 ╚════════════════════════════════════════════════╝

EOF

have() { command -v "$1" &>/dev/null; }

install_pkg() {
    case "$OS" in
        debian)  $SUDO apt-get install -y "$@" ;;
        mac)     brew install "$@" ;;
        arch)    $SUDO pacman -S --noconfirm "$@" ;;
        *)       warn "Unsupported OS for pkg: $*"; return 1 ;;
    esac
}

go_install() {
    local pkg="$1"
    local bin
    bin=$(basename "$(echo "$pkg" | sed 's|@.*||')")
    if have "$bin"; then
        info "✓ $bin already installed"
        return 0
    fi
    log "Installing $bin via go install..."
    go install "$pkg" 2>&1 | tail -5 || warn "Failed: $pkg"
}

pip_install() {
    local pkg="$1"
    python3 -m pip install --user --upgrade "$pkg" 2>&1 | tail -3 || warn "pip failed: $pkg"
}

ensure_user_bin_path() {
    local user_bin="$HOME/.local/bin"
    case ":$PATH:" in
        *":${user_bin}:"*) ;;
        *) export PATH="$user_bin:$PATH" ;;
    esac

    for rc in ~/.bashrc ~/.zshrc; do
        [ -f "$rc" ] || continue
        grep -q 'HOME/.local/bin' "$rc" || \
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
    done
}

install_system_deps() {
    log "▶ Installing system dependencies"
    case "$OS" in
        debian)
            $SUDO apt-get update -qq
            install_pkg git curl wget jq whois dnsutils nmap python3 python3-pip \
                        unzip build-essential libpcap-dev chromium
            ;;
        mac)
            if ! have brew; then
                err "Homebrew not found. Install from https://brew.sh first."
                exit 1
            fi
            install_pkg git curl wget jq whois nmap python3 libpcap coreutils
            ;;
        arch)
            $SUDO pacman -Sy --noconfirm
            install_pkg git curl wget jq whois bind nmap python python-pip \
                        unzip base-devel libpcap
            ;;
        *)
            warn "Unknown OS — please install: git curl wget jq whois nmap python3 manually"
            ;;
    esac
}

install_go() {
    if have go; then
        info "✓ Go already installed ($(go version | awk '{print \$3}'))"
        return 0
    fi

    log "▶ Installing Go 1.22"
    local GO_VERSION="1.22.5"
    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) err "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    local OS_NAME
    OS_NAME=$([ "$OS" = "mac" ] && echo "darwin" || echo "linux")

    local url="https://go.dev/dl/go${GO_VERSION}.${OS_NAME}-${ARCH}.tar.gz"
    log "Downloading: $url"
    cd /tmp
    wget -q "$url" -O go.tar.gz
    if [ "$USE_SUDO" -eq 1 ]; then
        $SUDO rm -rf /usr/local/go
        $SUDO tar -C /usr/local -xzf go.tar.gz
    else
        rm -rf "$HOME/.local/go"
        mkdir -p "$HOME/.local"
        tar -C "$HOME/.local" -xzf go.tar.gz
        for rc in ~/.bashrc ~/.zshrc; do
            [ -f "$rc" ] || continue
            grep -q 'HOME/.local/go/bin' "$rc" || \
                echo 'export PATH="$HOME/.local/go/bin:$PATH"' >> "$rc"
        done
        export PATH="$HOME/.local/go/bin:$PATH"
    fi
    rm go.tar.gz

    if [ "$USE_SUDO" -eq 1 ]; then
        for rc in ~/.bashrc ~/.zshrc; do
            [ -f "$rc" ] || continue
            grep -q '/usr/local/go/bin' "$rc" || \
                echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$rc"
        done
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    else
        export PATH=$PATH:$HOME/go/bin
    fi

    have go && info "✓ Go installed: $(go version)"
}

install_go_tools() {
    log "▶ Installing Go-based tools"

    go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go_install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go_install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go_install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go_install github.com/projectdiscovery/katana/cmd/katana@latest
    go_install github.com/projectdiscovery/notify/cmd/notify@latest

    go_install github.com/tomnomnom/assetfinder@latest
    go_install github.com/tomnomnom/waybackurls@latest
    go_install github.com/tomnomnom/gf@latest
    go_install github.com/tomnomnom/unfurl@latest
    go_install github.com/tomnomnom/anew@latest
    go_install github.com/tomnomnom/qsreplace@latest

    go_install github.com/lc/gau/v2/cmd/gau@latest
    go_install github.com/ffuf/ffuf/v2@latest
    go_install github.com/hakluke/hakrawler@latest
    go_install github.com/lc/subjs@latest
    go_install github.com/hahwul/dalfox/v2@latest
    go_install github.com/haccer/subjack@latest
    go_install github.com/Josue87/gotator@latest
    go_install github.com/sensepost/gowitness@latest
    go_install github.com/BishopFox/jsluice/cmd/jsluice@latest
    go_install github.com/owasp-amass/amass/v4/...@master

    # v6 additions (optional — phases degrade gracefully if missing)
    go_install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
    go_install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
    go_install github.com/j3ssie/metabigor@latest
    go_install github.com/damit5/gitdorks_go@latest

    if have nuclei; then
        log "Updating nuclei templates"
        nuclei -update-templates -silent 2>/dev/null || true
    fi

    if have gf; then
        log "Installing gf patterns"
        mkdir -p ~/.gf
        if [ ! -f ~/.gf/.keep ]; then
            git clone --depth 1 https://github.com/tomnomnom/gf.git /tmp/gf-src 2>/dev/null
            cp /tmp/gf-src/examples/*.json ~/.gf/ 2>/dev/null
            rm -rf /tmp/gf-src
            git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null
            cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null
            rm -rf /tmp/gf-patterns
            touch ~/.gf/.keep
            info "✓ gf patterns installed to ~/.gf/"
        fi
    fi
}

install_python_tools() {
    log "▶ Installing Python-based tools"
    ensure_user_bin_path
    pip_install arjun
    pip_install uro
    pip_install wafw00f
    pip_install graphql-cop
    pip_install s3scanner
    # cloud_enum: optional, large deps
    pip_install cloud-enum 2>/dev/null || warn "cloud_enum optional — skip if failed"
    ensure_user_bin_path
}

install_jwt_tool() {
    have jwt_tool && { info "✓ jwt_tool already installed"; return 0; }
    log "Installing jwt_tool"
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /tmp/jwt_tool 2>/dev/null || return 0
    $SUDO mkdir -p /opt/jwt_tool
    $SUDO cp -r /tmp/jwt_tool/* /opt/jwt_tool/ 2>/dev/null || true
    $SUDO bash -c 'cat > /usr/local/bin/jwt_tool' <<'WRAP'
#!/usr/bin/env bash
exec python3 /opt/jwt_tool/jwt_tool.py "$@"
WRAP
    $SUDO chmod +x /usr/local/bin/jwt_tool
    python3 -m pip install --user -r /opt/jwt_tool/requirements.txt 2>/dev/null || true
    rm -rf /tmp/jwt_tool
}

install_sqlmap() {
    have sqlmap && { info "✓ sqlmap already installed"; return 0; }
    log "Installing sqlmap (for opt-in SQLMAP_RISK handoff)"
    case "$OS" in
        debian) $SUDO apt-get install -y sqlmap 2>/dev/null || true ;;
        mac)    brew install sqlmap 2>/dev/null || true ;;
        arch)   $SUDO pacman -S --noconfirm sqlmap 2>/dev/null || true ;;
    esac
}

install_other_tools() {
    log "▶ Installing other tools"

    if ! have trufflehog; then
        log "Installing trufflehog"
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
            | $SUDO sh -s -- -b /usr/local/bin 2>/dev/null || warn "trufflehog install failed"
    fi

    if ! have gitleaks; then
        log "Installing gitleaks"
        case "$OS" in
            debian|arch)
                local latest
                latest=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
                    | jq -r '.tag_name' | sed 's/v//')
                local arch_name
                arch_name=$(uname -m | sed 's/x86_64/x64/; s/aarch64/arm64/')
                wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${latest}/gitleaks_${latest}_linux_${arch_name}.tar.gz" \
                    -O /tmp/gitleaks.tar.gz
                tar -xzf /tmp/gitleaks.tar.gz -C /tmp
                $SUDO mv /tmp/gitleaks /usr/local/bin/
                rm -f /tmp/gitleaks.tar.gz
                ;;
            mac) brew install gitleaks ;;
        esac
    fi

    if ! have findomain; then
        log "Installing findomain"
        case "$OS" in
            debian|arch)
                wget -q https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
                    -O /tmp/findomain.zip
                unzip -q -o /tmp/findomain.zip -d /tmp
                chmod +x /tmp/findomain
                $SUDO mv /tmp/findomain /usr/local/bin/
                rm /tmp/findomain.zip
                ;;
            mac) brew install findomain ;;
        esac
    fi

    if ! have testssl.sh; then
        log "Installing testssl.sh"
        $SUDO git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh 2>/dev/null
        $SUDO ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
    fi
}

install_seclists() {
    [ "$SKIP_SECLISTS" -eq 1 ] && { info "Skipping SecLists (--skip-seclists)"; return 0; }

    if [ -d /usr/share/seclists ]; then
        info "✓ SecLists already installed"
        return 0
    fi

    log "▶ Installing SecLists (~1GB, this takes a while)"
    $SUDO git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
    info "✓ SecLists installed to /usr/share/seclists"
}

ensure_config_key() {
    local conf="$1"
    local key="$2"
    local value="$3"
    local comment="$4"

    if grep -q "^${key}=" "$conf"; then
        return 0
    fi

    printf '%s=%s                  # %s\n' "$key" "$value" "$comment" >> "$conf"
}

setup_config() {
    log "▶ Preparing ~/.recon.conf"

    local conf="$HOME/.recon.conf"
    if [ ! -f "$conf" ]; then
        if [ -f "recon.conf.example" ]; then
            cp recon.conf.example "$conf"
            info "✓ Created $conf from recon.conf.example"
        else
            cat > "$conf" <<'EOF'
# Paintest Recon Framework configuration
BOUNTY_HANDLE="anon"
CALLBACK_DOMAIN="oob.attacker-callback.invalid"
WEBHOOK_URL=""
AUTH_HEADER=""
AUTH_COOKIE=""
THREADS=25
RATE=30
DEEP_THREADS=50
DEEP_RATE=100
MAX_JS_FILES=300
HTTP_TIMEOUT=15
API_TIMEOUT=30
WEBHOOK_CONNECT_TIMEOUT=20
WEBHOOK_TIMEOUT=30
WEBHOOK_RETRIES=3
AI_PROVIDER="openai"
AI_API_TOKEN=""
AI_MODEL=""
AI_MAX_OUTPUT_TOKENS=2000
AI_ACTIVE_MAX_TESTS=50
SECLISTS="/usr/share/seclists"
EOF
            info "✓ Created $conf"
        fi
    else
        info "✓ $conf already exists; preserving current values"
    fi

    ensure_config_key "$conf" "WEBHOOK_CONNECT_TIMEOUT" "20" "max seconds to establish webhook connection"
    ensure_config_key "$conf" "WEBHOOK_TIMEOUT" "30" "max seconds per webhook delivery attempt"
    ensure_config_key "$conf" "WEBHOOK_RETRIES" "3" "webhook delivery attempts before warning"
    ensure_config_key "$conf" "DEEP_THREADS" "50" "deep mode concurrency"
    ensure_config_key "$conf" "DEEP_RATE" "100" "deep mode request rate"
    ensure_config_key "$conf" "AI_PROVIDER" "\"openai\"" "AI provider: openai or anthropic"
    ensure_config_key "$conf" "AI_API_TOKEN" "\"\"" "optional AI token; prefer env vars for secrets"
    ensure_config_key "$conf" "AI_MODEL" "\"\"" "optional AI model override"
    ensure_config_key "$conf" "AI_MAX_OUTPUT_TOKENS" "2000" "AI triage output token cap"
    ensure_config_key "$conf" "AI_ACTIVE_MAX_TESTS" "50" "max AI active validation candidates"
    if grep -q '^AGGRESSIVE_THREADS=' "$conf" && ! grep -q '^DEEP_THREADS=' "$conf"; then
        sed -i 's/^AGGRESSIVE_THREADS=/DEEP_THREADS=/' "$conf"
    fi
    if grep -q '^AGGRESSIVE_RATE=' "$conf" && ! grep -q '^DEEP_RATE=' "$conf"; then
        sed -i 's/^AGGRESSIVE_RATE=/DEEP_RATE=/' "$conf"
    fi
    chmod 600 "$conf"
    info "✓ Secured $conf permissions (600)"
}

verify_install() {
    log "▶ Verifying installation"
    local tools=(
        subfinder assetfinder amass httpx nuclei naabu dnsx katana gau
        waybackurls ffuf nmap dalfox gf wafw00f testssl.sh
        trufflehog gitleaks arjun unfurl anew qsreplace gotator
        gowitness subjs jsluice uro jq findomain
    )
    local missing=()
    local installed=()
    for t in "${tools[@]}"; do
        if have "$t"; then
            installed+=("$t")
        else
            missing+=("$t")
        fi
    done

    echo
    echo -e "${G}✅ Installed (${#installed[@]}/${#tools[@]}):${N}"
    printf '   %s\n' "${installed[@]}"

    if [ ${#missing[@]} -gt 0 ]; then
        echo
        echo -e "${Y}⚠️  Missing (${#missing[@]}):${N}"
        printf '   %s\n' "${missing[@]}"
        echo -e "${Y}The script will still run, but these features will be skipped.${N}"
    fi
}

post_install() {
    cat <<EOF

${G}═══════════════════════════════════════════════════════════════${N}
${G}  ✅ Installation complete!${N}
${G}═══════════════════════════════════════════════════════════════${N}

${C}Next steps:${N}

  1. ${Y}Reload your shell:${N}
       ${B}source ~/.bashrc${N}

  2. ${Y}Edit your config:${N}
       ${B}nano ~/.recon.conf${N}

  3. ${Y}Run your first scan:${N}
       ${B}./paintest.sh -sd example.com${N}

  4. ${Y}Optional AI triage:${N}
       ${B}OPENAI_API_KEY=sk-... ./paintest.sh -ai example.com${N}

${C}Documentation:${N} ${B}./README.md${N}

${G}Happy hunting! 🎯${N}

EOF
}

main() {
    install_system_deps
    install_go
    install_go_tools
    install_python_tools
    install_other_tools
    install_jwt_tool
    install_sqlmap
    install_seclists
    setup_config
    verify_install
    post_install
}

main
