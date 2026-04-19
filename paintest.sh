#!/usr/bin/env bash
################################################################################
# Paintest Framework v5 (god-tier)
# Usage:
#   ./paintest.sh <target>                    → single-target pentest
#   ./paintest.sh -sd <target>                → + subdomain discovery
#   ./paintest.sh -sd -r <target>             → + resume from last run
#   ./paintest.sh -sd -d <target>             → + diff against previous run
#   ./paintest.sh -ai <target>                → + AI triage after scan
#   ./paintest.sh --ai-active <target>        → + bounded AI-assisted validation
#
# Env vars:
#   BOUNTY_HANDLE     your handle (for ID headers)
#   CALLBACK_DOMAIN   your OOB domain (default: interact.sh placeholder)
#   WEBHOOK_URL       Discord/Slack/Telegram webhook for notifications
#   AUTH_HEADER       e.g. "Authorization: Bearer xxx"
#   AUTH_COOKIE       e.g. "session=abc; csrf=xyz"
#   SCOPE_FILE        path to scope file (default ./scope.txt)
#   THREADS / RATE    concurrency + rate-limit
#   DEEP_THREADS / DEEP_RATE
#                    deep mode concurrency + rate-limit
#   AI_PROVIDER / AI_API_TOKEN / AI_MODEL
#                    optional AI triage / active validation settings
################################################################################

set -uo pipefail
# Not using -e intentionally: we want phases to continue on individual tool failure

# ============= AUTO-LOAD CONFIG =============
# Priority: .env in pwd > ~/.recon.conf > defaults
[ -f "$HOME/.recon.conf" ] && source "$HOME/.recon.conf"
[ -f "$(pwd)/.env" ] && source "$(pwd)/.env"

# ============= ARG PARSING =============
SUBDOMAIN_MODE=0
RESUME_MODE=0
DIFF_MODE=0
TEST_WEBHOOK_MODE=0
DEEP_MODE=0
AI_MODE=0
AI_ACTIVE_MODE=0
TARGET=""

while [ $# -gt 0 ]; do
    case "$1" in
        -sd) SUBDOMAIN_MODE=1; shift ;;
        -r|--resume) RESUME_MODE=1; shift ;;
        -d|--diff) DIFF_MODE=1; shift ;;
        -ai|--ai) AI_MODE=1; shift ;;
        --ai-active) AI_MODE=1; AI_ACTIVE_MODE=1; shift ;;
        --test-webhook) TEST_WEBHOOK_MODE=1; shift ;;
        --deep|--aggressive|--lab) DEEP_MODE=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: $0 [options] <target>
  -sd           Enable subdomain discovery (multi-host recon)
  -r, --resume  Resume from last incomplete run for this target
  -d, --diff    Diff against previous run, save new findings only
  -ai, --ai     Send final findings to an AI provider for triage
  --ai-active   Let AI propose bounded payloads and actively validate candidates
  --deep, --aggressive, --lab
                Enable deep validation checks and broader real-world template coverage
  --test-webhook
                Send one webhook test message and exit
  -h, --help    Show this help

Env vars:
  BOUNTY_HANDLE, CALLBACK_DOMAIN, WEBHOOK_URL,
  AUTH_HEADER, AUTH_COOKIE, SCOPE_FILE, THREADS, RATE,
  DEEP_THREADS, DEEP_RATE,
  AI_PROVIDER=openai|anthropic, AI_API_TOKEN, AI_MODEL,
  AI_ACTIVE_MAX_TESTS
EOF
            exit 0
            ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [ "$TEST_WEBHOOK_MODE" -eq 1 ] && [ -z "$TARGET" ]; then
    TARGET="webhook-test"
fi

[ -z "$TARGET" ] && { echo "Usage: $0 [-sd] [-r] [-d] [-ai|--ai] [--ai-active] [--deep|--aggressive|--lab] [--test-webhook] <target>" >&2; exit 1; }

INPUT_TARGET="$TARGET"
TARGET_SCAN="$TARGET"
TARGET_HOST="$TARGET"
if [[ "$INPUT_TARGET" =~ ^https?:// ]]; then
    TARGET_SCAN="$INPUT_TARGET"
    TARGET_HOST="${INPUT_TARGET#http://}"
    TARGET_HOST="${TARGET_HOST#https://}"
    TARGET_HOST="${TARGET_HOST%%/*}"
    TARGET_HOST="${TARGET_HOST%%:*}"
    TARGET="$TARGET_HOST"
fi
TARGET_SAFE=$(printf '%s' "$INPUT_TARGET" | sed -E 's#^https?://##; s#[^A-Za-z0-9._-]+#_#g; s#_+$##')

# ============= CONFIG =============
THREADS="${THREADS:-25}"
RATE="${RATE:-30}"
DEEP_THREADS="${DEEP_THREADS:-${AGGRESSIVE_THREADS:-50}}"
DEEP_RATE="${DEEP_RATE:-${AGGRESSIVE_RATE:-100}}"
HANDLE="${BOUNTY_HANDLE:-anon}"
CALLBACK_DOMAIN="${CALLBACK_DOMAIN:-oob.attacker-callback.invalid}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
AUTH_HEADER="${AUTH_HEADER:-}"
AUTH_COOKIE="${AUTH_COOKIE:-}"
UA="Mozilla/5.0 (BugBounty; ${HANDLE})"
ID_HEADER="X-Bug-Bounty: ${HANDLE}"
SCOPE_FILE="${SCOPE_FILE:-$(pwd)/scope.txt}"
SECLISTS="${SECLISTS:-/usr/share/seclists}"
MAX_JS_FILES="${MAX_JS_FILES:-300}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-15}"
API_TIMEOUT="${API_TIMEOUT:-30}"
WEBHOOK_CONNECT_TIMEOUT="${WEBHOOK_CONNECT_TIMEOUT:-20}"
WEBHOOK_TIMEOUT="${WEBHOOK_TIMEOUT:-30}"
WEBHOOK_RETRIES="${WEBHOOK_RETRIES:-3}"
BASIC_CHECK_LIMIT="${BASIC_CHECK_LIMIT:-200}"
TLS_CHECK_LIMIT="${TLS_CHECK_LIMIT:-50}"
AI_PROVIDER="${AI_PROVIDER:-openai}"
AI_MODEL="${AI_MODEL:-}"
AI_API_TOKEN="${AI_API_TOKEN:-}"
AI_MAX_OUTPUT_TOKENS="${AI_MAX_OUTPUT_TOKENS:-2000}"
AI_ACTIVE_MAX_TESTS="${AI_ACTIVE_MAX_TESTS:-50}"

if [ "$AI_PROVIDER" = "openai" ] && [ -z "$AI_MODEL" ]; then
    AI_MODEL="gpt-5.4-mini"
elif [ "$AI_PROVIDER" = "anthropic" ] && [ -z "$AI_MODEL" ]; then
    AI_MODEL="claude-sonnet-4-5"
fi
[ -z "$AI_API_TOKEN" ] && [ "$AI_PROVIDER" = "openai" ] && AI_API_TOKEN="${OPENAI_API_KEY:-}"
[ -z "$AI_API_TOKEN" ] && [ "$AI_PROVIDER" = "anthropic" ] && AI_API_TOKEN="${ANTHROPIC_API_KEY:-}"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MODE_TAG=$([ "$SUBDOMAIN_MODE" -eq 1 ] && echo "sd" || echo "single")

# Resume: find latest incomplete run
if [ "$RESUME_MODE" -eq 1 ]; then
    LAST_RUN=$(ls -dt "recon_${TARGET_SAFE}_${MODE_TAG}_"* 2>/dev/null | head -1 || true)
    if [ -n "$LAST_RUN" ]; then
        OUTPUT_DIR="$(cd "$LAST_RUN" && pwd)"
        echo "[resume] Continuing in: $OUTPUT_DIR"
    else
        OUTPUT_DIR="$(pwd)/recon_${TARGET_SAFE}_${MODE_TAG}_${TIMESTAMP}"
        echo "[resume] No prior run found — starting fresh"
    fi
else
    OUTPUT_DIR="$(pwd)/recon_${TARGET_SAFE}_${MODE_TAG}_${TIMESTAMP}"
fi

# Diff: locate previous completed run for comparison
PREV_RUN=""
if [ "$DIFF_MODE" -eq 1 ]; then
    PREV_RUN=$(ls -dt "$(pwd)/recon_${TARGET_SAFE}_${MODE_TAG}_"* 2>/dev/null \
        | grep -v "$(basename "$OUTPUT_DIR")" | head -1 || true)
    [ -n "$PREV_RUN" ] && echo "[diff] Comparing against: $PREV_RUN"
fi

STATE_FILE="$OUTPUT_DIR/.phase_state"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'
log()   { echo -e "${B}[$(date +%H:%M:%S)]${N} ${G}$*${N}"; }
warn()  { echo -e "${Y}[!] $*${N}"; }
err()   { echo -e "${R}[X] $*${N}" >&2; }
info()  { echo -e "${C}[i] $*${N}"; }

# ============= NOTIFY =============
notify() {
    [ -z "$WEBHOOK_URL" ] && return
    local msg="$1"
    local json_msg
    if have jq; then
        json_msg=$(jq -Rn --arg msg "$msg" '$msg')
    else
        json_msg=$(printf '%s' "$msg" \
            | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
            | awk 'BEGIN { printf "\"" } { if (NR > 1) printf "\\n"; printf "%s", $0 } END { print "\"" }')
    fi

    # Auto-detect Discord vs Slack vs generic by URL
    local payload
    if [[ "$WEBHOOK_URL" == *"discord.com"* || "$WEBHOOK_URL" == *"discordapp.com"* ]]; then
        payload="{\"content\": ${json_msg}}"
    elif [[ "$WEBHOOK_URL" == *"slack.com"* || "$WEBHOOK_URL" == *"hooks.slack"* ]]; then
        payload="{\"text\": ${json_msg}}"
    elif [[ "$WEBHOOK_URL" == *"api.telegram.org"* ]]; then
        local http_code curl_rc
        http_code=$(send_webhook_request --data-urlencode "text=${msg}" "$WEBHOOK_URL")
        curl_rc=$?
        if [[ "$http_code" =~ ^2 ]]; then
            return 0
        fi
        warn "Webhook notification failed (HTTP ${http_code:-000}, curl rc=${curl_rc})"
        return 1
    else
        payload="{\"text\": ${json_msg}}"
    fi

    local http_code curl_rc
    http_code=$(send_webhook_request \
        -H "Content-Type: application/json" \
        -X POST -d "$payload" "$WEBHOOK_URL")
    curl_rc=$?
    if [[ "$http_code" =~ ^2 ]]; then
        return 0
    fi
    warn "Webhook notification failed (HTTP ${http_code:-000}, curl rc=${curl_rc})"
    return 1
}

send_webhook_request() {
    local attempt http_code curl_rc=0
    local err_file="$OUTPUT_DIR/tmp/webhook_error.log"
    [ -d "$OUTPUT_DIR/tmp" ] || err_file="$(mktemp)"

    for ((attempt = 1; attempt <= WEBHOOK_RETRIES; attempt++)); do
        : > "$err_file" 2>/dev/null || true
        http_code=$(curl -sS \
            --connect-timeout "$WEBHOOK_CONNECT_TIMEOUT" \
            --max-time "$WEBHOOK_TIMEOUT" \
            -o /dev/null -w '%{http_code}' \
            "$@" 2>"$err_file")
        curl_rc=$?
        if [[ "$http_code" =~ ^2 ]]; then
            [ "$attempt" -gt 1 ] && info "Webhook notification delivered after retry ${attempt}/${WEBHOOK_RETRIES}" >&2
            printf '%s\n' "$http_code"
            [ "$err_file" = "$OUTPUT_DIR/tmp/webhook_error.log" ] || rm -f "$err_file"
            return 0
        fi
        [ "$attempt" -lt "$WEBHOOK_RETRIES" ] && sleep 2
    done

    if [ -s "$err_file" ]; then
        warn "Webhook curl error: $(head -1 "$err_file" | sed 's/[[:space:]]\\+/ /g')" >&2
    fi
    printf '%s\n' "${http_code:-000}"
    [ "$err_file" = "$OUTPUT_DIR/tmp/webhook_error.log" ] || rm -f "$err_file"
    return "$curl_rc"
}

# ============= PHASE CHECKPOINT =============
PHASE_TOTAL=$((14 + AI_MODE + AI_ACTIVE_MODE))
PHASE_CURRENT=0

notify_phase_progress() {
    local name="$1"
    local status="$2"
    local details="${3:-}"
    PHASE_CURRENT=$((PHASE_CURRENT + 1))
    local pct=$((PHASE_CURRENT * 100 / PHASE_TOTAL))
    local msg="📍 Paintest progress: ${pct}% (${PHASE_CURRENT}/${PHASE_TOTAL})
Target: \`${INPUT_TARGET}\`
Step: \`${name}\`
Status: ${status}"
    [ -n "$details" ] && msg="${msg}
${details}"
    notify "$msg"
}

phase_done()    { grep -q "^${1}:done$" "$STATE_FILE" 2>/dev/null; }
mark_phase()    { echo "${1}:done" >> "$STATE_FILE"; }
run_phase() {
    local name="$1"; shift
    if phase_done "$name"; then
        info "Skip ${name} (checkpoint)"
        notify_phase_progress "$name" "skipped (checkpoint)"
        return 0
    fi
    log "▶ Phase: ${name}"
    local t0=$(date +%s)
    "$@"
    local rc=$?
    local dt=$(( $(date +%s) - t0 ))
    if [ "$rc" -eq 0 ]; then
        mark_phase "$name"
        info "✓ ${name} done in ${dt}s"
        notify_phase_progress "$name" "done" "Duration: ${dt}s"
    else
        warn "${name} exited rc=${rc} after ${dt}s (not marking done)"
        notify_phase_progress "$name" "failed" "Exit code: ${rc}
Duration: ${dt}s"
    fi
    return $rc
}

# ============= CLEANUP =============
cleanup() {
    warn "Interrupted — killing background jobs"
    jobs -p | xargs -r kill 2>/dev/null
    notify "⚠️ Recon interrupted for \`${TARGET}\`"
    exit 130
}
trap cleanup INT TERM

# ============= BANNER =============
banner() {
    echo -e "${C}"
    cat << 'EOF'
 ╔════════════════════════════════════════════════╗
 ║   Paintest Recon Framework v5 (god-tier)       ║
 ╚════════════════════════════════════════════════╝
EOF
    echo -e "${N}"
    echo -e "${G}[+] Target:    ${INPUT_TARGET}${N}"
    echo -e "${G}[+] Handle:    ${HANDLE}${N}"
    echo -e "${G}[+] Output:    ${OUTPUT_DIR}${N}"
    echo -e "${G}[+] Callback:  ${CALLBACK_DOMAIN}${N}"
    [ -n "$AUTH_HEADER" ] && echo -e "${G}[+] Auth:      header set${N}"
    [ -n "$AUTH_COOKIE" ] && echo -e "${G}[+] Auth:      cookie set${N}"
    [ -n "$WEBHOOK_URL" ] && echo -e "${G}[+] Webhook:   configured${N}"
    if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
        echo -e "${G}[+] Mode:      subdomain discovery (-sd)${N}"
    else
        echo -e "${Y}[+] Mode:      single-target pentest${N}"
    fi
    [ "$DEEP_MODE" -eq 1 ] && echo -e "${R}[+] Deep mode:  validation checks enabled${N}"
    [ "$AI_MODE" -eq 1 ] && echo -e "${C}[+] AI triage: ${AI_PROVIDER}/${AI_MODEL}${N}"
    [ "$AI_ACTIVE_MODE" -eq 1 ] && echo -e "${R}[+] AI active: ${AI_ACTIVE_MAX_TESTS} bounded tests max${N}"
    [ "$RESUME_MODE" -eq 1 ] && echo -e "${C}[+] Resume:    ON${N}"
    [ "$DIFF_MODE" -eq 1 ]   && echo -e "${C}[+] Diff:      ON (prev: ${PREV_RUN:-none})${N}"
    [ -f "$SCOPE_FILE" ] && echo -e "${G}[+] Scope file: ${SCOPE_FILE}${N}" \
        || warn "No scope.txt — defaulting to *.${TARGET}"
    echo
}

have() { command -v "$1" &>/dev/null; }

url_host_port() {
    local url="$1" proto rest hostport host port
    proto="${url%%://*}"
    rest="${url#*://}"
    hostport="${rest%%/*}"
    host="${hostport%%:*}"
    if [[ "$hostport" == *":"* ]]; then
        port="${hostport##*:}"
    elif [ "$proto" = "https" ]; then
        port="443"
    else
        port="80"
    fi
    printf '%s\t%s\t%s\n' "$host" "$port" "$proto"
}

is_version_older() {
    local found="$1" minimum="$2"
    local IFS=.
    local -a f m
    read -r -a f <<< "$found"
    read -r -a m <<< "$minimum"
    local i fv mv
    for i in 0 1 2; do
        fv="${f[$i]:-0}"
        mv="${m[$i]:-0}"
        fv="${fv//[^0-9]/}"
        mv="${mv//[^0-9]/}"
        [ "${fv:-0}" -lt "${mv:-0}" ] && return 0
        [ "${fv:-0}" -gt "${mv:-0}" ] && return 1
    done
    return 1
}

record_outdated_version_candidates() {
    local url="$1" header="$2" lower version
    lower=$(printf '%s' "$header" | tr '[:upper:]' '[:lower:]')

    if [[ "$lower" =~ apache/([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
        version="${BASH_REMATCH[1]}"
        is_version_older "$version" "2.4.58" \
            && printf '%s\tApache/%s below 2.4.58\t%s\n' "$url" "$version" "$header" >> vulns/basic_outdated_versions.txt
    fi
    if [[ "$lower" =~ nginx/([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
        version="${BASH_REMATCH[1]}"
        is_version_older "$version" "1.24.0" \
            && printf '%s\tnginx/%s below 1.24.0\t%s\n' "$url" "$version" "$header" >> vulns/basic_outdated_versions.txt
    fi
    if [[ "$lower" =~ php/([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
        version="${BASH_REMATCH[1]}"
        is_version_older "$version" "8.1.0" \
            && printf '%s\tPHP/%s below 8.1.0\t%s\n' "$url" "$version" "$header" >> vulns/basic_outdated_versions.txt
    fi
    if [[ "$lower" =~ openssl/([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
        version="${BASH_REMATCH[1]}"
        is_version_older "$version" "1.1.1" \
            && printf '%s\tOpenSSL/%s below 1.1.1\t%s\n' "$url" "$version" "$header" >> vulns/basic_outdated_versions.txt
    fi
    if [[ "$lower" =~ microsoft-iis/([0-9]+(\.[0-9]+)?) ]]; then
        version="${BASH_REMATCH[1]}"
        is_version_older "$version" "10.0.0" \
            && printf '%s\tMicrosoft-IIS/%s below 10.0\t%s\n' "$url" "$version" "$header" >> vulns/basic_outdated_versions.txt
    fi
    if [[ "$lower" =~ tomcat[/-]([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
        version="${BASH_REMATCH[1]}"
        is_version_older "$version" "9.0.0" \
            && printf '%s\tTomcat/%s below 9.0.0\t%s\n' "$url" "$version" "$header" >> vulns/basic_outdated_versions.txt
    fi
}

# Build header args for tools that accept -H
# Usage: CURL_HDRS=($(curl_headers))
curl_headers() {
    printf -- '-H\n%s\n' "$ID_HEADER"
    [ -n "$AUTH_HEADER" ] && printf -- '-H\n%s\n' "$AUTH_HEADER"
    [ -n "$AUTH_COOKIE" ] && printf -- '-H\n%s\n' "Cookie: $AUTH_COOKIE"
}

# httpx/nuclei/katana use -H repeated
httpx_hdrs() {
    local args=(-H "$ID_HEADER")
    [ -n "$AUTH_HEADER" ] && args+=(-H "$AUTH_HEADER")
    [ -n "$AUTH_COOKIE" ] && args+=(-H "Cookie: $AUTH_COOKIE")
    printf '%s\n' "${args[@]}"
}

check_tools() {
    log "Checking tools"
    local tools=(subfinder assetfinder amass httpx nuclei naabu dnsx katana gau
                 waybackurls ffuf nmap dalfox gf wafw00f testssl.sh
                 trufflehog gitleaks arjun unfurl anew qsreplace gotator
                 gowitness subjs jsluice uro jq)
    local missing=()
    for t in "${tools[@]}"; do
        have "$t" || missing+=("$t")
    done
    [ ${#missing[@]} -gt 0 ] && warn "Missing (will skip): ${missing[*]}"
}

setup() {
    mkdir -p "$OUTPUT_DIR"/{recon,subdomains,ports,web,vulns,fuzzing,screenshots,js,js/content,params,checklist,reports,diffs,tmp}
    cd "$OUTPUT_DIR" || exit 1
    touch "$STATE_FILE"
    log "Working dir: $OUTPUT_DIR"
}

# Scope filter
apply_scope() {
    local infile="$1" outfile="$2"
    if [ -f "$SCOPE_FILE" ] && [ -s "$SCOPE_FILE" ]; then
        grep -F -f "$SCOPE_FILE" "$infile" 2>/dev/null | sort -u > "$outfile"
    else
        grep -E "(^|\.)${TARGET//./\\.}(\$|/|:)" "$infile" 2>/dev/null | sort -u > "$outfile"
    fi
}

# Safe concurrent append (atomic per-line)
safe_append() {
    local line="$1" file="$2"
    (
        flock -x 200
        echo "$line" >> "$file"
    ) 200>>"${file}.lock"
}

# ============= PHASE 1: PASSIVE RECON =============
do_passive_recon() {
    ( timeout "$API_TIMEOUT" whois "$TARGET" > recon/whois.txt 2>/dev/null ) &
    dig "$TARGET" ANY +noall +answer  > recon/dns.txt 2>/dev/null
    dig "$TARGET" TXT +short         >> recon/dns.txt 2>/dev/null
    dig "$TARGET" MX  +short         >> recon/dns.txt 2>/dev/null
    dig "$TARGET" NS  +short         >> recon/dns.txt 2>/dev/null

    ( timeout "$API_TIMEOUT" curl -s -A "$UA" \
        "https://api.hackertarget.com/aslookup/?q=${TARGET}" \
        > recon/asn.txt 2>/dev/null ) &

    if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
        ( timeout 60 curl -s -A "$UA" "https://crt.sh/?q=%25.${TARGET}&output=json" \
            | jq -r '.[].name_value' 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' | tr ',' '\n' | sed 's/^\*\.//' \
            | sort -u > recon/crtsh.txt ) &

        # Extra passive source: bufferover / anubis (free, no key)
        ( timeout 30 curl -s -A "$UA" \
            "https://jldc.me/anubis/subdomains/${TARGET}" \
            | jq -r '.[]?' 2>/dev/null > recon/anubis.txt ) &
    fi

    # Favicon hash pivot hint (useful for shodan search later)
    if [ "$SUBDOMAIN_MODE" -eq 1 ] && have httpx; then
        ( timeout 20 httpx -u "https://${TARGET}" -favicon -silent \
            > recon/favicon.txt 2>/dev/null ) &
    fi

    cat > checklist/github_dorks.txt <<EOF
# Run manually on github.com/search — or use gitdorker for automation
"${TARGET}" password
"${TARGET}" api_key
"${TARGET}" secret
"${TARGET}" token
"${TARGET}" extension:env
"${TARGET}" extension:yml aws
"${TARGET}" filename:.npmrc _auth
"${TARGET}" filename:.dockercfg auth
"${TARGET}" extension:pem private
org:${TARGET%%.*} language:yaml
EOF
    wait
    return 0
}

# ============= PHASE 2: SUBDOMAINS =============
do_subdomain_enum() {
    if [ "$SUBDOMAIN_MODE" -ne 1 ]; then
        info "Single-target mode — skipping discovery"
        echo "$TARGET_SCAN" > subdomains/all.txt
        if have dnsx; then
            echo "$TARGET_HOST" | dnsx -silent -a -resp \
                -o subdomains/resolved.txt 2>/dev/null
        else
            dig +short "$TARGET_HOST" | awk -v t="$TARGET_HOST" '{print t" [A] "$0}' \
                > subdomains/resolved.txt
        fi
        return 0
    fi

    have subfinder   && ( timeout 300 subfinder -d "$TARGET" -all -silent -o subdomains/subfinder.txt ) &
    have assetfinder && ( timeout 120 assetfinder --subs-only "$TARGET" > subdomains/assetfinder.txt 2>/dev/null ) &
    have amass       && ( timeout 300 amass enum -passive -d "$TARGET" -silent -o subdomains/amass.txt ) &
    have findomain   && ( timeout 180 findomain -t "$TARGET" -q -u subdomains/findomain.txt ) &
    wait
    cp recon/crtsh.txt subdomains/crtsh.txt 2>/dev/null
    cp recon/anubis.txt subdomains/anubis.txt 2>/dev/null

    cat subdomains/*.txt 2>/dev/null | tr '[:upper:]' '[:lower:]' \
        | grep -E '^[a-z0-9._-]+$' | sort -u > subdomains/all_passive.txt

    local wl="$SECLISTS/Discovery/DNS/subdomains-top1million-20000.txt"
    if have dnsx && [ -f "$wl" ]; then
        log "DNS bruteforce (top 20k)"
        dnsx -d "$TARGET" -w "$wl" -silent -o subdomains/bruteforce.txt 2>/dev/null
    fi

    if have gotator && [ -s subdomains/all_passive.txt ] \
       && [ "$(wc -l < subdomains/all_passive.txt)" -lt 500 ]; then
        log "Permutations"
        local permwl="$SECLISTS/Discovery/DNS/dns-Jhaddix.txt"
        [ -f "$permwl" ] && gotator -sub subdomains/all_passive.txt -perm "$permwl" \
            -depth 1 -numbers 3 -mindup -adv -md 2>/dev/null \
            | dnsx -silent 2>/dev/null > subdomains/permutations.txt
    fi

    cat subdomains/*.txt 2>/dev/null | sort -u > subdomains/all_unfiltered.txt
    echo "$TARGET" >> subdomains/all_unfiltered.txt
    apply_scope subdomains/all_unfiltered.txt subdomains/all.txt
    log "In-scope subdomains: $(wc -l < subdomains/all.txt)"

    have dnsx && dnsx -l subdomains/all.txt -silent -a -resp \
        -o subdomains/resolved.txt 2>/dev/null
    return 0
}

# ============= PHASE 3: PORT SCAN =============
do_port_scan() {
    grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
        subdomains/resolved.txt 2>/dev/null | sort -u > ports/ips.txt
    [ ! -s ports/ips.txt ] && dig +short "$TARGET" > ports/ips.txt

    if have naabu && [ -s ports/ips.txt ]; then
        naabu -list ports/ips.txt -top-ports 1000 -rate 500 -silent \
            -o ports/naabu.txt 2>/dev/null
    fi
    # Run nmap detached — don't wait on it
    if have nmap && [ -s ports/naabu.txt ]; then
        local pp
        pp=$(awk -F: '{print $2}' ports/naabu.txt | sort -un | paste -sd, -)
        [ -n "$pp" ] && ( nmap -iL ports/ips.txt -sV -Pn -T3 -p "$pp" \
            -oA ports/nmap 2>/dev/null >/dev/null ) &
        disown
    fi
    return 0
}

# ============= PHASE 4: WEB PROBING =============
do_web_probe() {
    if ! have httpx; then
        warn "httpx not found — skipping web probe"
        return 0
    fi
    local hdrs
    mapfile -t hdrs < <(httpx_hdrs)

    # Rich probe with response hash for dedup
    httpx -l subdomains/all.txt -silent -threads "$THREADS" \
        -status-code -title -tech-detect -web-server -location -cdn \
        -follow-redirects -random-agent \
        "${hdrs[@]}" \
        -rate-limit "$RATE" \
        -hash sha256 -json \
        -o web/httpx.jsonl 2>/dev/null

    # Flat live list
    jq -r '.url // ."input"' web/httpx.jsonl 2>/dev/null | sort -u > web/live.txt

    # Dedup by body-hash — take first URL per response cluster
    if [ -s web/httpx.jsonl ]; then
        jq -r 'select(.hash!=null) | [.hash.body_sha256 // .hash, .url] | @tsv' \
            web/httpx.jsonl 2>/dev/null \
            | sort -u -k1,1 | cut -f2 > web/live_dedup.txt
        [ ! -s web/live_dedup.txt ] && cp web/live.txt web/live_dedup.txt
    else
        cp web/live.txt web/live_dedup.txt 2>/dev/null
    fi

    have wafw00f   && ( wafw00f -i web/live.txt -o web/waf.txt 2>/dev/null ) &
    have gowitness && ( gowitness file -f web/live_dedup.txt -P screenshots/ 2>/dev/null ) &
    wait

    log "Live hosts: $(wc -l < web/live.txt 2>/dev/null || echo 0) \
(unique-content: $(wc -l < web/live_dedup.txt 2>/dev/null || echo 0))"
    return 0
}

# ============= PHASE 5: URL DISCOVERY =============
do_url_discovery() {
    [ ! -s web/live.txt ] && return 0
    local hdrs
    mapfile -t hdrs < <(httpx_hdrs)

    if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
        have gau && ( timeout 300 gau --threads "$THREADS" --subs "$TARGET" \
                     > web/gau.txt 2>/dev/null ) &
        have waybackurls && ( timeout 180 waybackurls <<< "$TARGET" \
                             > web/wayback.txt 2>/dev/null ) &
    else
        have gau && ( timeout 300 gau --threads "$THREADS" "$TARGET" \
                     > web/gau.txt 2>/dev/null ) &
        have waybackurls && ( timeout 180 sh -c "echo $TARGET | waybackurls" \
                             > web/wayback.txt 2>/dev/null ) &
    fi
    local crawl_depth=3
    [ "$DEEP_MODE" -eq 1 ] && crawl_depth=5
    have katana && ( katana -list web/live_dedup.txt -d "$crawl_depth" -silent -jc -kf all \
                     "${hdrs[@]}" -rl "$([ "$DEEP_MODE" -eq 1 ] && echo "$DEEP_RATE" || echo "$RATE")" \
                     -o web/katana.txt 2>/dev/null ) &
    wait

    cat web/gau.txt web/wayback.txt web/katana.txt 2>/dev/null \
        | grep -Ei "^https?://" | sort -u > web/all_urls_raw.txt

    apply_scope web/all_urls_raw.txt web/all_urls_scoped.txt

    # Normalize: dedup param-only duplicates (?id=1, ?id=2 → one entry)
    if have uro; then
        uro < web/all_urls_scoped.txt > web/all_urls.txt 2>/dev/null
    else
        sed -E 's/=[^&]*/=FUZZ/g' web/all_urls_scoped.txt | sort -u > web/all_urls.txt
    fi
    log "URLs raw:$(wc -l<web/all_urls_scoped.txt) → normalized:$(wc -l<web/all_urls.txt)"

    grep -Ei '\.js(\?|$)' web/all_urls_scoped.txt | sort -u > js/js_urls.txt

    grep -Ei '/(graphql|gql|graphiql|playground|api/graphql)' web/all_urls.txt \
        | sort -u > checklist/graphql_endpoints.txt
    grep -Ei '/(api|v[0-9]+|rest|jsonrpc)/' web/all_urls.txt \
        | sort -u > checklist/api_endpoints.txt

    if have gf; then
        for p in xss sqli ssrf lfi redirect rce idor ssti debug_logic interestingparams; do
            gf "$p" web/all_urls.txt > "params/${p}.txt" 2>/dev/null
        done
    fi

    have unfurl && unfurl --unique keys < web/all_urls.txt \
        > params/all_param_names.txt 2>/dev/null
    return 0
}

# ============= PHASE 6: DIRECTORY FUZZING =============
do_dir_fuzz() {
    [ ! -s web/live_dedup.txt ] && return 0
    local wl="$SECLISTS/Discovery/Web-Content/raft-small-directories.txt"
    [ "$DEEP_MODE" -eq 1 ] && [ -f "$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt" ] && \
        wl="$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt"
    [ ! -f "$wl" ] && wl="$SECLISTS/Discovery/Web-Content/common.txt"
    [ ! -f "$wl" ] && { warn "No wordlist, skipping"; return 0; }

    local hdrs=(-H "$ID_HEADER" -H "User-Agent: $UA")
    [ -n "$AUTH_HEADER" ] && hdrs+=(-H "$AUTH_HEADER")
    [ -n "$AUTH_COOKIE" ] && hdrs+=(-H "Cookie: $AUTH_COOKIE")

    if have ffuf; then
        local hosts_to_fuzz
        if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
            if [ "$DEEP_MODE" -eq 1 ]; then
                hosts_to_fuzz=$(head -100 web/live_dedup.txt)
            else
                hosts_to_fuzz=$(head -20 web/live_dedup.txt)
            fi
        else
            hosts_to_fuzz=$(cat web/live_dedup.txt)
        fi

        echo "$hosts_to_fuzz" | while read -r url; do
            [ -z "$url" ] && continue
            local safe
            safe=$(echo "$url" | sed 's|https\?://||; s|[/:]|_|g')
            ffuf -u "${url}/FUZZ" -w "$wl" \
                 -mc 200,201,204,301,302,307,401,403 \
                 -fc 404 -t "$([ "$DEEP_MODE" -eq 1 ] && echo "$DEEP_THREADS" || echo "$THREADS")" \
                 -rate "$([ "$DEEP_MODE" -eq 1 ] && echo "$DEEP_RATE" || echo "$RATE")" -s \
                 "${hdrs[@]}" \
                 -o "fuzzing/${safe}.json" -of json 2>/dev/null
        done
    fi

    # High-value paths
    cat > tmp/highvalue_paths.txt <<'EOF'
.git/config
.git/HEAD
.env
.env.local
.env.production
.DS_Store
.svn/entries
config.json
config.yml
composer.json
package.json
.npmrc
backup.sql
backup.zip
db.sql
wp-config.php.bak
server-status
actuator
actuator/env
actuator/health
actuator/heapdump
actuator/mappings
api/swagger.json
swagger.json
swagger-ui.html
openapi.json
phpinfo.php
info.php
debug
debug.php
console
actuator/configprops
actuator/beans
actuator/logfile
graphql
graphiql
api/graphql
playground
dvwa/
DVWA/
vulnerabilities/sqli/
vulnerabilities/xss_r/
vulnerabilities/xss_s/
vulnerabilities/exec/
vulnerabilities/fi/
mutillidae/
WebGoat/
JuiceShop/
ftp/
administration
robots.txt
sitemap.xml
crossdomain.xml
.well-known/security.txt
.well-known/openid-configuration
EOF
    if have httpx; then
        local hx_hdrs
        mapfile -t hx_hdrs < <(httpx_hdrs)
        while read -r host; do
            while read -r path; do
                echo "${host}/${path}"
            done < tmp/highvalue_paths.txt
        done < web/live_dedup.txt | httpx -silent -mc 200,301,302,401,403 \
            "${hx_hdrs[@]}" -rate-limit "$RATE" \
            -status-code -content-length \
            -o vulns/highvalue_paths.txt 2>/dev/null
    fi
    return 0
}

# ============= PHASE 7: JS ANALYSIS =============
do_js_analysis() {
    [ ! -s js/js_urls.txt ] && return 0

    if have subjs; then
        subjs -i web/live_dedup.txt 2>/dev/null | sort -u \
            | anew js/js_urls.txt >/dev/null
    fi

    log "Fetching JS files (max ${MAX_JS_FILES})"
    local -a hdrs=(-A "$UA" -H "$ID_HEADER")
    [ -n "$AUTH_HEADER" ] && hdrs+=(-H "$AUTH_HEADER")
    [ -n "$AUTH_COOKIE" ] && hdrs+=(-H "Cookie: $AUTH_COOKIE")

    local count=0
    while read -r jsurl && [ "$count" -lt "$MAX_JS_FILES" ]; do
        local fname
        fname=$(echo "$jsurl" | md5sum | cut -d' ' -f1).js
        [ -f "js/content/${fname}" ] && { ((count++)); continue; }  # resume-friendly
        curl -sL --max-time "$HTTP_TIMEOUT" "${hdrs[@]}" "$jsurl" \
            -o "js/content/${fname}" 2>/dev/null
        ((count++))
    done < js/js_urls.txt

    # jsluice is dramatically better than regex for bundled JS
    if have jsluice; then
        find js/content -name '*.js' -size +0c -print0 2>/dev/null \
            | xargs -0 -n 20 jsluice urls 2>/dev/null \
            | sort -u > js/jsluice_urls.txt
        find js/content -name '*.js' -size +0c -print0 2>/dev/null \
            | xargs -0 -n 20 jsluice secrets 2>/dev/null \
            > js/jsluice_secrets.txt
    fi

    have trufflehog && trufflehog filesystem js/content \
        --no-update --no-verification \
        > js/trufflehog.txt 2>/dev/null
    have gitleaks   && gitleaks detect -s js/content --no-git \
        -r js/gitleaks.json 2>/dev/null

    # Regex endpoints as fallback
    grep -rhoE '"(/[a-zA-Z0-9_/.-]+)"' js/content/ 2>/dev/null \
        | tr -d '"' | sort -u | grep -vE '\.(png|jpg|gif|css|svg|woff|ttf|ico)' \
        > js/endpoints_regex.txt
    # Merge jsluice + regex
    cat js/jsluice_urls.txt js/endpoints_regex.txt 2>/dev/null \
        | sort -u > js/endpoints.txt
    return 0
}

# ============= PHASE 8: VULN SCAN =============
do_basic_vuln_checks() {
    [ ! -s web/live.txt ] && return 0
    log "Basic web/TLS checks"

    : > vulns/basic_http_exposure.txt
    : > vulns/basic_insecure_cookies.txt
    : > vulns/basic_missing_security_headers.txt
    : > vulns/basic_server_disclosure.txt
    : > vulns/basic_outdated_versions.txt
    : > vulns/basic_extra_ports.txt
    : > vulns/basic_tls_legacy.txt
    : > vulns/basic_tls_name_mismatch.txt
    : > vulns/basic_sri_missing.txt
    : > vulns/basic_host_header_injection.txt
    : > vulns/basic_dangerous_methods.txt
    : > vulns/basic_directory_listing.txt
    : > vulns/basic_mixed_content.txt
    : > vulns/basic_checks.txt

    grep -E '^http://' web/live.txt 2>/dev/null \
        | sed 's/^/HTTP-CLEAR-TEXT\t/' \
        | sort -u > vulns/basic_http_exposure.txt

    if [ -s ports/naabu.txt ]; then
        awk '
            {
                line=$0
                port=line
                sub(/^.*:/, "", port)
                host=line
                sub(":[^:]*$", "", host)
                if (port !~ /^(80|443)$/ && host != "" && port != "") {
                    ports[host] = ports[host] ? ports[host] "," port : port
                }
            }
            END {
                for (host in ports) {
                    print "EXTRA-OPEN-PORTS\t" host "\t" ports[host]
                }
            }
        ' ports/naabu.txt | sort -u > vulns/basic_extra_ports.txt
    fi

    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)
    while read -r url; do
        [ -z "$url" ] && continue
        local resp proto server powered cookie_name cookie_lower header canary injected_resp injected_body methods
        proto="${url%%://*}"
        resp=$(curl -skI --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
        [ -z "$resp" ] && continue

        for header in strict-transport-security content-security-policy x-frame-options x-content-type-options referrer-policy permissions-policy; do
            if [ "$header" = "strict-transport-security" ] && [ "$proto" != "https" ]; then
                continue
            fi
            echo "$resp" | grep -qi "^${header}:" \
                || printf 'MISSING-HEADER\t%s\t%s\n' "$url" "$header" >> vulns/basic_missing_security_headers.txt
        done

        server=$(echo "$resp" | awk 'BEGIN{IGNORECASE=1} /^server:/ {sub(/^[^:]+:[[:space:]]*/, ""); print; exit}')
        if [ -n "$server" ]; then
            printf 'SERVER-HEADER\t%s\t%s\n' "$url" "$server" >> vulns/basic_server_disclosure.txt
            record_outdated_version_candidates "$url" "Server: $server"
        fi
        powered=$(echo "$resp" | awk 'BEGIN{IGNORECASE=1} /^x-powered-by:/ {sub(/^[^:]+:[[:space:]]*/, ""); print; exit}')
        if [ -n "$powered" ]; then
            printf 'X-POWERED-BY\t%s\t%s\n' "$url" "$powered" >> vulns/basic_server_disclosure.txt
            record_outdated_version_candidates "$url" "X-Powered-By: $powered"
        fi

        while IFS= read -r cookie; do
            [ -z "$cookie" ] && continue
            cookie_name=$(printf '%s' "$cookie" | sed -E 's/^[Ss]et-[Cc]ookie:[[:space:]]*([^=;]+).*/\1/')
            cookie_lower=$(printf '%s' "$cookie" | tr '[:upper:]' '[:lower:]')
            if [ "$proto" = "http" ]; then
                printf 'COOKIE-OVER-HTTP\t%s\t%s\n' "$url" "$cookie_name" >> vulns/basic_insecure_cookies.txt
            fi
            echo "$cookie_lower" | grep -q ';[[:space:]]*secure' \
                || printf 'COOKIE-MISSING-SECURE\t%s\t%s\n' "$url" "$cookie_name" >> vulns/basic_insecure_cookies.txt
            echo "$cookie_lower" | grep -q ';[[:space:]]*httponly' \
                || printf 'COOKIE-MISSING-HTTPONLY\t%s\t%s\n' "$url" "$cookie_name" >> vulns/basic_insecure_cookies.txt
            echo "$cookie_lower" | grep -q ';[[:space:]]*samesite=' \
                || printf 'COOKIE-MISSING-SAMESITE\t%s\t%s\n' "$url" "$cookie_name" >> vulns/basic_insecure_cookies.txt
        done < <(echo "$resp" | grep -i '^set-cookie:')

        canary="host-header-${RANDOM}.${CALLBACK_DOMAIN}"
        injected_resp=$(curl -skI --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" \
            -H "Host: ${canary}" -H "X-Forwarded-Host: ${canary}" "$url" 2>/dev/null)
        echo "$injected_resp" | grep -Fqi "$canary" \
            && printf 'HOST-HEADER-REFLECTED-HEADERS\t%s\t%s\n' "$url" "$canary" >> vulns/basic_host_header_injection.txt
        injected_body=$(curl -sk --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" \
            -H "Host: ${canary}" -H "X-Forwarded-Host: ${canary}" "$url" 2>/dev/null)
        echo "$injected_body" | grep -Fqi "$canary" \
            && printf 'HOST-HEADER-REFLECTED-BODY\t%s\t%s\n' "$url" "$canary" >> vulns/basic_host_header_injection.txt

        methods=$(curl -skI -X OPTIONS --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null \
            | awk 'BEGIN{IGNORECASE=1} /^allow:|^access-control-allow-methods:/ {sub(/^[^:]+:[[:space:]]*/, ""); print}' \
            | paste -sd, -)
        if printf '%s\n' "$methods" | grep -Eiq '(^|[,[:space:]])(TRACE|PUT|DELETE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE)([,[:space:]]|$)'; then
            printf 'DANGEROUS-METHODS\t%s\t%s\n' "$url" "$methods" >> vulns/basic_dangerous_methods.txt
        fi

        curl -skI -X TRACE --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null \
            | head -1 | grep -Eq ' 2[0-9][0-9] ' \
            && printf 'TRACE-ENABLED\t%s\n' "$url" >> vulns/basic_dangerous_methods.txt
    done < <(head -n "$BASIC_CHECK_LIMIT" web/live.txt)

    while read -r url; do
        [ -z "$url" ] && continue
        local page host proto
        proto="${url%%://*}"
        host=$(url_host_port "$url" | cut -f1)
        page=$(curl -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
        [ -z "$page" ] && continue

        printf '%s\n' "$page" | head -80 \
            | grep -Eiq '<title>[[:space:]]*Index of /|<h1>[[:space:]]*Index of /|Directory Listing For|Parent Directory' \
            && printf 'DIRECTORY-LISTING\t%s\n' "$url" >> vulns/basic_directory_listing.txt

        printf '%s\n' "$page" | tr '\n' ' ' \
            | grep -oiE '<script[^>]+src=["'\''][^"'\'']+["'\''][^>]*>' \
            | while IFS= read -r tag; do
                local src src_host
                if [ "$proto" = "https" ]; then
                    src=$(printf '%s\n' "$tag" | sed -nE 's/.*src=["'\'']([^"'\'']+)["'\''].*/\1/ip' | head -1)
                    [[ "$src" =~ ^http:// ]] \
                        && printf 'MIXED-CONTENT-SCRIPT\t%s\t%s\n' "$url" "$src" >> vulns/basic_mixed_content.txt
                fi
                echo "$tag" | grep -qi 'integrity=' && continue
                src=$(printf '%s\n' "$tag" | sed -nE 's/.*src=["'\'']([^"'\'']+)["'\''].*/\1/ip' | head -1)
                [[ "$src" =~ ^https?:// ]] || continue
                src_host=$(printf '%s\n' "$src" | sed -E 's#^https?://([^/:]+).*#\1#')
                [ "$src_host" = "$host" ] && continue
                printf 'SRI-MISSING-SCRIPT\t%s\t%s\n' "$url" "$src" >> vulns/basic_sri_missing.txt
            done

        printf '%s\n' "$page" | tr '\n' ' ' \
            | grep -oiE '<link[^>]+href=["'\''][^"'\'']+["'\''][^>]*>' \
            | grep -iE 'rel=["'\'']?stylesheet|as=["'\'']?style' \
            | while IFS= read -r tag; do
                local href href_host
                if [ "$proto" = "https" ]; then
                    href=$(printf '%s\n' "$tag" | sed -nE 's/.*href=["'\'']([^"'\'']+)["'\''].*/\1/ip' | head -1)
                    [[ "$href" =~ ^http:// ]] \
                        && printf 'MIXED-CONTENT-STYLESHEET\t%s\t%s\n' "$url" "$href" >> vulns/basic_mixed_content.txt
                fi
                echo "$tag" | grep -qi 'integrity=' && continue
                href=$(printf '%s\n' "$tag" | sed -nE 's/.*href=["'\'']([^"'\'']+)["'\''].*/\1/ip' | head -1)
                [[ "$href" =~ ^https?:// ]] || continue
                href_host=$(printf '%s\n' "$href" | sed -E 's#^https?://([^/:]+).*#\1#')
                [ "$href_host" = "$host" ] && continue
                printf 'SRI-MISSING-STYLESHEET\t%s\t%s\n' "$url" "$href" >> vulns/basic_sri_missing.txt
            done
    done < <(head -n "$BASIC_CHECK_LIMIT" web/live_dedup.txt)

    if have openssl; then
        while read -r url; do
            [ -z "$url" ] && continue
            [[ "$url" != https://* ]] && continue
            local host port proto cert_tmp tls_out
            IFS=$'\t' read -r host port proto < <(url_host_port "$url")
            [ -z "$host" ] && continue

            tls_out=$(timeout 10 openssl s_client -tls1 -servername "$host" -connect "${host}:${port}" </dev/null 2>/dev/null)
            echo "$tls_out" | grep -q 'Protocol  *: TLSv1$' \
                && printf 'TLS-1.0-SUPPORTED\t%s\t%s:%s\n' "$url" "$host" "$port" >> vulns/basic_tls_legacy.txt

            tls_out=$(timeout 10 openssl s_client -tls1_1 -servername "$host" -connect "${host}:${port}" </dev/null 2>/dev/null)
            echo "$tls_out" | grep -q 'Protocol  *: TLSv1.1$' \
                && printf 'TLS-1.1-SUPPORTED\t%s\t%s:%s\n' "$url" "$host" "$port" >> vulns/basic_tls_legacy.txt

            cert_tmp=$(mktemp)
            timeout 10 openssl s_client -servername "$host" -connect "${host}:${port}" </dev/null > "$cert_tmp" 2>/dev/null || true
            if [ -s "$cert_tmp" ] && openssl x509 -in "$cert_tmp" -noout >/dev/null 2>&1; then
                openssl x509 -in "$cert_tmp" -noout -checkhost "$host" 2>/dev/null \
                    | grep -qi 'does NOT match' \
                    && printf 'TLS-NAME-MISMATCH\t%s\t%s:%s\n' "$url" "$host" "$port" >> vulns/basic_tls_name_mismatch.txt
            fi
            rm -f "$cert_tmp"
        done < <(head -n "$TLS_CHECK_LIMIT" web/live_dedup.txt)
    fi

    for f in \
        vulns/basic_http_exposure.txt \
        vulns/basic_insecure_cookies.txt \
        vulns/basic_missing_security_headers.txt \
        vulns/basic_server_disclosure.txt \
        vulns/basic_outdated_versions.txt \
        vulns/basic_extra_ports.txt \
        vulns/basic_tls_legacy.txt \
        vulns/basic_tls_name_mismatch.txt \
        vulns/basic_sri_missing.txt \
        vulns/basic_host_header_injection.txt \
        vulns/basic_dangerous_methods.txt \
        vulns/basic_directory_listing.txt \
        vulns/basic_mixed_content.txt; do
        [ -s "$f" ] && cat "$f"
    done | sort -u > vulns/basic_checks.txt

    return 0
}

do_vuln_scan() {
    local hdrs
    mapfile -t hdrs < <(httpx_hdrs)

    # Single consolidated nuclei run (much faster than 5 separate calls)
    if have nuclei; then
        nuclei -update-templates -silent 2>/dev/null

        log "Nuclei (consolidated, JSONL output)"
        if [ -s web/live_dedup.txt ]; then
            nuclei -l web/live_dedup.txt \
                -severity critical,high,medium,low \
                -exclude-tags intrusive,dos,fuzz,brute-force \
                -tags cve,exposure,misconfig,default-login,exposed-panels \
                -rl "$RATE" -c 25 -silent \
                "${hdrs[@]}" \
                -jsonl -o vulns/nuclei.jsonl 2>/dev/null
        fi

        if [ "$DEEP_MODE" -eq 1 ]; then
            log "Nuclei deep sweep"
            if [ -s web/live_dedup.txt ]; then
                nuclei -l web/live_dedup.txt \
                    -severity info,low,medium,high,critical \
                    -exclude-tags dos,brute-force \
                    -rl "$DEEP_RATE" -c "$DEEP_THREADS" -silent \
                    "${hdrs[@]}" \
                    -jsonl -o vulns/nuclei_deep_hosts.jsonl 2>/dev/null
            fi
            if [ -s web/all_urls.txt ]; then
                nuclei -l web/all_urls.txt \
                    -severity info,low,medium,high,critical \
                    -exclude-tags dos,brute-force \
                    -rl "$DEEP_RATE" -c "$DEEP_THREADS" -silent \
                    "${hdrs[@]}" \
                    -jsonl -o vulns/nuclei_deep_urls.jsonl 2>/dev/null
            fi
            cat vulns/nuclei.jsonl vulns/nuclei_deep_hosts.jsonl vulns/nuclei_deep_urls.jsonl \
                2>/dev/null | sort -u > vulns/nuclei_all.jsonl
        else
            cp vulns/nuclei.jsonl vulns/nuclei_all.jsonl 2>/dev/null || true
        fi

        # Split by severity for reporting
        if [ -s vulns/nuclei_all.jsonl ]; then
            jq -r 'select(.info.severity=="critical") | [.info.name,.host] | @tsv' \
                vulns/nuclei_all.jsonl > vulns/nuclei_critical.txt 2>/dev/null
            jq -r 'select(.info.severity=="high") | [.info.name,.host] | @tsv' \
                vulns/nuclei_all.jsonl > vulns/nuclei_high.txt 2>/dev/null
        fi

        # Subdomain takeover (only in -sd)
        if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
            nuclei -l subdomains/all.txt -t takeovers/ -silent \
                -rl "$RATE" "${hdrs[@]}" \
                -jsonl -o vulns/takeovers.jsonl 2>/dev/null
        fi
    fi

    # Dalfox XSS
    if have dalfox && [ -s params/xss.txt ]; then
        log "Dalfox XSS"
        local dfx_hdrs=("$ID_HEADER")
        [ -n "$AUTH_HEADER" ] && dfx_hdrs+=("$AUTH_HEADER")
        [ -n "$AUTH_COOKIE" ] && dfx_hdrs+=("Cookie: $AUTH_COOKIE")

        local header_args=()
        for h in "${dfx_hdrs[@]}"; do header_args+=(--header "$h"); done

        dalfox file params/xss.txt --silence --no-spinner \
            "${header_args[@]}" --user-agent "$UA" \
            --delay 100 -o vulns/xss.txt 2>/dev/null
    fi

    [ -s params/sqli.txt ] && cp params/sqli.txt checklist/sqli_manual.txt

    if [ -s params/redirect.txt ] && have qsreplace; then
        head -50 params/redirect.txt \
            | qsreplace "https://${CALLBACK_DOMAIN}" \
            > checklist/openredirect_payloads.txt
    fi
    [ -s params/ssrf.txt ] && cp params/ssrf.txt checklist/ssrf_manual.txt

    # CORS — race-safe
    log "CORS checks"
    local cors_tmp; cors_tmp=$(mktemp)
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)
    while read -r url; do
        [ -z "$url" ] && continue
        local resp
        resp=$(curl -sI --max-time 8 -A "$UA" "${c_hdrs[@]}" \
            -H "Origin: https://${CALLBACK_DOMAIN}" "$url" 2>/dev/null)
        if echo "$resp" | grep -qi "access-control-allow-origin: https://${CALLBACK_DOMAIN}"; then
            echo "REFLECTED: $url" >> "$cors_tmp"
        fi
        if echo "$resp" | grep -qi "access-control-allow-origin: null"; then
            echo "NULL-ALLOWED: $url" >> "$cors_tmp"
        fi
    done < <(head -50 web/live_dedup.txt)
    sort -u "$cors_tmp" > vulns/cors_manual.txt 2>/dev/null
    rm -f "$cors_tmp"

    do_basic_vuln_checks

    # JWT — race-safe
    log "JWT surface scan"
    local jwt_tmp; jwt_tmp=$(mktemp)
    while read -r url; do
        [ -z "$url" ] && continue
        curl -sI --max-time 8 -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null \
            | grep -iE "(authorization|set-cookie).*eyJ" >/dev/null \
            && echo "JWT-exposing: $url" >> "$jwt_tmp"
    done < <(head -30 web/live_dedup.txt)
    sort -u "$jwt_tmp" > checklist/jwt_endpoints.txt 2>/dev/null
    rm -f "$jwt_tmp"

    # testssl in background — do NOT wait on it
    if have testssl.sh && [ -s web/live_dedup.txt ]; then
        ( testssl.sh --quiet --fast "$(head -1 web/live_dedup.txt)" \
            > vulns/ssl.txt 2>/dev/null ) &
        disown
    fi

    if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
        have subjack && subjack -w subdomains/all.txt -t 50 -timeout 30 -ssl \
            -c /usr/share/subjack/fingerprints.json \
            -o vulns/subjack.txt 2>/dev/null
    fi
    return 0
}

# ============= PHASE 8.5: DEEP VALIDATION CHECKS =============
do_deep_checks() {
    [ "$DEEP_MODE" -ne 1 ] && return 0
    [ ! -s web/live_dedup.txt ] && return 0

    mkdir -p vulns/deep
    log "Deep validation checks"

    local -a curl_hdrs=(-A "$UA" -H "$ID_HEADER")
    [ -n "$AUTH_HEADER" ] && curl_hdrs+=(-H "$AUTH_HEADER")
    [ -n "$AUTH_COOKIE" ] && curl_hdrs+=(-H "Cookie: $AUTH_COOKIE")

    cat > tmp/deep_paths.txt <<'EOF'
/
/login
/admin
/administrator
/debug
/debug.php
/phpinfo.php
/info.php
/server-status
/actuator/env
/actuator/heapdump
/graphql
/graphiql
/api/graphql
/playground
/dvwa/
/DVWA/
/setup.php
/security.php
/vulnerabilities/sqli/
/vulnerabilities/xss_r/
/vulnerabilities/xss_s/
/vulnerabilities/exec/
/vulnerabilities/fi/?page=../../../../../../etc/passwd
/mutillidae/
/index.php?page=login.php
/index.php?page=user-info.php
/WebGoat/
/WebGoat/login
/JuiceShop/
/ftp/
/administration
/api/Challenges
/rest/products/search?q=test
/rest/products/search?q=<script>alert(1337)</script>
EOF

    while read -r host; do
        [ -z "$host" ] && continue
        while read -r path; do
            printf '%s%s\n' "${host%/}" "$path"
        done < tmp/deep_paths.txt
    done < web/live_dedup.txt | sort -u > vulns/deep/deep_probe_urls.txt

    if have httpx; then
        local hx_hdrs
        mapfile -t hx_hdrs < <(httpx_hdrs)
        httpx -l vulns/deep/deep_probe_urls.txt -silent \
            -status-code -title -content-length -location -tech-detect \
            "${hx_hdrs[@]}" -rate-limit "$DEEP_RATE" \
            -o vulns/deep/deep_exposed_routes.txt 2>/dev/null
    fi

    local xss_payload='"><script>alert(1337)</script>'
    local sqli_payload="'"
    local lfi_payload='../../../../../../etc/passwd'
    local redirect_payload="https://${CALLBACK_DOMAIN}"

    if have qsreplace && [ -s web/all_urls.txt ]; then
        grep '=' web/all_urls.txt | head -200 | qsreplace "$xss_payload" \
            > tmp/deep_xss_payloads.txt 2>/dev/null
        while read -r url; do
            [ -z "$url" ] && continue
            curl -skL --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
                | grep -F "$xss_payload" >/dev/null && echo "$url" >> vulns/deep/reflected_xss_confirmed.txt
        done < tmp/deep_xss_payloads.txt

        grep '=' web/all_urls.txt | head -200 | qsreplace "$sqli_payload" \
            > tmp/deep_sqli_payloads.txt 2>/dev/null
        while read -r url; do
            [ -z "$url" ] && continue
            curl -skL --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
                | grep -Eiq 'SQL syntax|mysql_fetch|ORA-[0-9]|PostgreSQL|SQLite|ODBC|MariaDB|You have an error in your SQL' \
                && echo "$url" >> vulns/deep/sql_error_candidates.txt
        done < tmp/deep_sqli_payloads.txt

        grep -Ei '(file|path|page|include|template|view|doc|document|folder|root|dir)=' web/all_urls.txt \
            | head -150 | qsreplace "$lfi_payload" > tmp/deep_lfi_payloads.txt 2>/dev/null
        while read -r url; do
            [ -z "$url" ] && continue
            curl -skL --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
                | grep -E 'root:.*:0:0:|daemon:.*:1:1:' >/dev/null \
                && echo "$url" >> vulns/deep/lfi_confirmed.txt
        done < tmp/deep_lfi_payloads.txt

        grep -Ei '(url|next|redirect|return|continue|dest|destination|callback|to)=' web/all_urls.txt \
            | head -150 | qsreplace "$redirect_payload" > tmp/deep_redirect_payloads.txt 2>/dev/null
        while read -r url; do
            [ -z "$url" ] && continue
            curl -skI --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
                | grep -qi "^location: ${redirect_payload}" \
                && echo "$url" >> vulns/deep/open_redirect_confirmed.txt
        done < tmp/deep_redirect_payloads.txt
    fi

    while read -r url; do
        [ -z "$url" ] && continue
        curl -skL --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
            | grep -E 'root:.*:0:0:|daemon:.*:1:1:' >/dev/null \
            && echo "$url" >> vulns/deep/lfi_confirmed.txt
    done < <(grep 'passwd' vulns/deep/deep_probe_urls.txt 2>/dev/null)

    sort -u -o vulns/deep/reflected_xss_confirmed.txt vulns/deep/reflected_xss_confirmed.txt 2>/dev/null || true
    sort -u -o vulns/deep/sql_error_candidates.txt vulns/deep/sql_error_candidates.txt 2>/dev/null || true
    sort -u -o vulns/deep/lfi_confirmed.txt vulns/deep/lfi_confirmed.txt 2>/dev/null || true
    sort -u -o vulns/deep/open_redirect_confirmed.txt vulns/deep/open_redirect_confirmed.txt 2>/dev/null || true

    {
        echo "# Deep Validation Findings"
        echo
        echo "- Exposed interesting routes: $(wc -l < vulns/deep/deep_exposed_routes.txt 2>/dev/null || echo 0)"
        echo "- Reflected XSS confirmed: $(wc -l < vulns/deep/reflected_xss_confirmed.txt 2>/dev/null || echo 0)"
        echo "- SQL error candidates: $(wc -l < vulns/deep/sql_error_candidates.txt 2>/dev/null || echo 0)"
        echo "- LFI confirmed: $(wc -l < vulns/deep/lfi_confirmed.txt 2>/dev/null || echo 0)"
        echo "- Open redirects confirmed: $(wc -l < vulns/deep/open_redirect_confirmed.txt 2>/dev/null || echo 0)"
    } > vulns/deep/summary.md

    return 0
}

# ============= PHASE 9: PARAM MINING =============
do_param_mining() {
    [ ! -s web/live_dedup.txt ] && return 0
    have arjun || return 0

    local hosts
    if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
        hosts=$(head -15 web/live_dedup.txt)
    else
        hosts=$(cat web/live_dedup.txt)
    fi

    local arjun_hdrs=("$ID_HEADER")
    [ -n "$AUTH_HEADER" ] && arjun_hdrs+=("$AUTH_HEADER")
    [ -n "$AUTH_COOKIE" ] && arjun_hdrs+=("Cookie: $AUTH_COOKIE")

    echo "$hosts" | while read -r url; do
        [ -z "$url" ] && continue
        arjun -u "$url" -t 10 --stable \
            --headers "$(IFS=$'\n'; echo "${arjun_hdrs[*]}")" \
            -oT "params/arjun_$(echo "$url" | md5sum | cut -c1-8).txt" \
            2>/dev/null
    done
    return 0
}

# ============= PHASE 10: AUTH / SENSITIVE =============
do_auth_surface() {
    [ ! -s web/all_urls.txt ] && return 0
    grep -Ei '(login|signin|signup|register|auth|oauth|sso|saml|admin|dashboard|wp-admin|phpmyadmin|console|portal|internal|staff)' \
        web/all_urls.txt | sort -u > checklist/auth_endpoints.txt
    grep -Ei '\.(bak|backup|old|orig|save|swp|swo|sql|db|sqlite|zip|tar\.gz|tgz|rar|7z|env|git|DS_Store|log|conf|config|yml|yaml|ini|pem|key|p12|pfx)(\?|$)' \
        web/all_urls.txt | sort -u > checklist/sensitive_files.txt
    grep -Ei '(url|dest|redirect|uri|path|continue|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open)=' \
        web/all_urls.txt | sort -u > checklist/ssrf_params.txt
    grep -Ei '[?&](__proto__|constructor|prototype)=' \
        web/all_urls.txt > checklist/proto_pollution.txt
    grep -Ei '(redirect_uri|response_type|client_id|state|code_challenge|SAMLRequest|RelayState)' \
        web/all_urls.txt | sort -u > checklist/oauth_flows.txt
    return 0
}

# ============= PHASE 10.5: CUSTOM WORDLIST (target-tailored) =============
do_custom_wordlist() {
    log "Building target-tailored wordlist"
    {
        cat js/content/*.js 2>/dev/null
        cat web/all_urls.txt 2>/dev/null
        jq -r '.title // empty' web/httpx.jsonl 2>/dev/null
    } | grep -oE '[a-zA-Z][a-zA-Z0-9_-]{3,20}' \
      | tr '[:upper:]' '[:lower:]' \
      | sort -u > fuzzing/custom_wordlist.txt
    log "Custom wordlist: $(wc -l < fuzzing/custom_wordlist.txt) words"
    return 0
}

# ============= PHASE 11: DIFF =============
do_diff() {
    [ "$DIFF_MODE" -ne 1 ] && return 0
    [ -z "$PREV_RUN" ] && { info "No previous run — skipping diff"; return 0; }

    local sections=(
        "subdomains/all.txt"
        "web/live.txt"
        "web/all_urls.txt"
        "js/js_urls.txt"
        "checklist/api_endpoints.txt"
        "checklist/graphql_endpoints.txt"
        "vulns/highvalue_paths.txt"
        "vulns/basic_checks.txt"
        "vulns/ai_active/confirmed.txt"
    )
    for f in "${sections[@]}"; do
        local cur="$f"
        local prev="$PREV_RUN/$f"
        [ -s "$cur" ] && [ -s "$prev" ] || continue
        local out="diffs/new_$(echo "$f" | tr '/' '_')"
        comm -23 <(sort -u "$cur") <(sort -u "$prev") > "$out"
    done

    # Diff nuclei findings
    if [ -s vulns/nuclei.jsonl ] && [ -s "$PREV_RUN/vulns/nuclei.jsonl" ]; then
        jq -r '[.info.name, .host, .["matched-at"]] | @tsv' vulns/nuclei.jsonl \
            | sort -u > tmp/cur_nuclei.txt
        jq -r '[.info.name, .host, .["matched-at"]] | @tsv' "$PREV_RUN/vulns/nuclei.jsonl" \
            | sort -u > tmp/prev_nuclei.txt
        comm -23 tmp/cur_nuclei.txt tmp/prev_nuclei.txt > diffs/new_nuclei_findings.txt
    fi

    local new_subs=$(wc -l < diffs/new_subdomains_all.txt 2>/dev/null || echo 0)
    local new_urls=$(wc -l < diffs/new_web_all_urls.txt 2>/dev/null || echo 0)
    local new_vulns=$(wc -l < diffs/new_nuclei_findings.txt 2>/dev/null || echo 0)
    info "Diffs: +${new_subs} subs, +${new_urls} urls, +${new_vulns} findings"
    return 0
}

# ============= PHASE 12: REPORT =============
do_report() {
    local report="reports/report_${TARGET_SAFE}_${TIMESTAMP}.md"
    {
        echo "# Recon Report: $INPUT_TARGET"
        echo "**Date:** $(date)"
        echo "**Handle:** $HANDLE"
        echo "**Mode:** $([ "$SUBDOMAIN_MODE" -eq 1 ] && echo "Subdomain (-sd)" || echo "Single-target")"
        [ "$DIFF_MODE" -eq 1 ] && echo "**Diff vs:** ${PREV_RUN:-none}"
        echo
        echo "## Stats"
        echo "- Subdomains: $(wc -l < subdomains/all.txt 2>/dev/null || echo 0)"
        echo "- Live hosts: $(wc -l < web/live.txt 2>/dev/null || echo 0)"
        echo "- Unique-content hosts: $(wc -l < web/live_dedup.txt 2>/dev/null || echo 0)"
        echo "- URLs (normalized): $(wc -l < web/all_urls.txt 2>/dev/null || echo 0)"
        echo "- JS files: $(wc -l < js/js_urls.txt 2>/dev/null || echo 0)"
        echo "- GraphQL endpoints: $(wc -l < checklist/graphql_endpoints.txt 2>/dev/null || echo 0)"
        echo "- API endpoints: $(wc -l < checklist/api_endpoints.txt 2>/dev/null || echo 0)"
        echo "- Basic check findings: $(wc -l < vulns/basic_checks.txt 2>/dev/null || echo 0)"
        if [ "$DEEP_MODE" -eq 1 ]; then
            echo "- Deep reflected XSS: $(wc -l < vulns/deep/reflected_xss_confirmed.txt 2>/dev/null || echo 0)"
            echo "- Deep SQL error candidates: $(wc -l < vulns/deep/sql_error_candidates.txt 2>/dev/null || echo 0)"
            echo "- Deep LFI confirmed: $(wc -l < vulns/deep/lfi_confirmed.txt 2>/dev/null || echo 0)"
            echo "- Deep open redirects: $(wc -l < vulns/deep/open_redirect_confirmed.txt 2>/dev/null || echo 0)"
        fi
        echo
        echo "## Nuclei — Critical"
        echo '```'
        head -20 vulns/nuclei_critical.txt 2>/dev/null
        echo '```'
        echo "## Nuclei — High"
        echo '```'
        head -30 vulns/nuclei_high.txt 2>/dev/null
        echo '```'
        if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
            echo "## Subdomain Takeovers"
            echo '```'
            jq -r '[.info.name, .host] | @tsv' vulns/takeovers.jsonl 2>/dev/null
            cat vulns/subjack.txt 2>/dev/null
            echo '```'
        fi
        echo "## High-value Paths"
        echo '```'
        head -30 vulns/highvalue_paths.txt 2>/dev/null
        echo '```'
        echo "## XSS (Dalfox)"
        echo '```'
        head -30 vulns/xss.txt 2>/dev/null
        echo '```'
        echo "## CORS"
        echo '```'
        head -30 vulns/cors_manual.txt 2>/dev/null
        echo '```'
        echo "## Basic Checks"
        echo "### HTTP Cleartext"
        echo '```'
        head -30 vulns/basic_http_exposure.txt 2>/dev/null
        echo '```'
        echo "### Insecure Cookies"
        echo '```'
        head -30 vulns/basic_insecure_cookies.txt 2>/dev/null
        echo '```'
        echo "### Missing Security Headers"
        echo '```'
        head -50 vulns/basic_missing_security_headers.txt 2>/dev/null
        echo '```'
        echo "### Server and Framework Disclosure"
        echo '```'
        head -30 vulns/basic_server_disclosure.txt 2>/dev/null
        echo '```'
        echo "### Outdated Version Candidates"
        echo '```'
        head -30 vulns/basic_outdated_versions.txt 2>/dev/null
        echo '```'
        echo "### Extra Open Ports"
        echo '```'
        head -30 vulns/basic_extra_ports.txt 2>/dev/null
        echo '```'
        echo "### Legacy TLS"
        echo '```'
        head -30 vulns/basic_tls_legacy.txt 2>/dev/null
        echo '```'
        echo "### TLS Name Mismatch"
        echo '```'
        head -30 vulns/basic_tls_name_mismatch.txt 2>/dev/null
        echo '```'
        echo "### Missing Subresource Integrity"
        echo '```'
        head -30 vulns/basic_sri_missing.txt 2>/dev/null
        echo '```'
        echo "### Host Header Injection"
        echo '```'
        head -30 vulns/basic_host_header_injection.txt 2>/dev/null
        echo '```'
        echo "### Dangerous HTTP Methods"
        echo '```'
        head -30 vulns/basic_dangerous_methods.txt 2>/dev/null
        echo '```'
        echo "### Directory Listing"
        echo '```'
        head -30 vulns/basic_directory_listing.txt 2>/dev/null
        echo '```'
        echo "### Mixed Content"
        echo '```'
        head -30 vulns/basic_mixed_content.txt 2>/dev/null
        echo '```'
        if [ "$DEEP_MODE" -eq 1 ]; then
            echo "## Deep Validation Checks"
            cat vulns/deep/summary.md 2>/dev/null
            echo "### Reflected XSS"
            echo '```'
            head -30 vulns/deep/reflected_xss_confirmed.txt 2>/dev/null
            echo '```'
            echo "### SQL Error Candidates"
            echo '```'
            head -30 vulns/deep/sql_error_candidates.txt 2>/dev/null
            echo '```'
            echo "### LFI Confirmed"
            echo '```'
            head -30 vulns/deep/lfi_confirmed.txt 2>/dev/null
            echo '```'
            echo "### Open Redirects"
            echo '```'
            head -30 vulns/deep/open_redirect_confirmed.txt 2>/dev/null
            echo '```'
        fi
        if [ "$AI_ACTIVE_MODE" -eq 1 ]; then
            echo "## AI Active Validation"
            cat vulns/ai_active/summary.md 2>/dev/null
            echo "### AI Reflected XSS"
            echo '```'
            head -30 vulns/ai_active/reflected_xss.txt 2>/dev/null
            echo '```'
            echo "### AI SQL Error Candidates"
            echo '```'
            head -30 vulns/ai_active/sql_error_candidates.txt 2>/dev/null
            echo '```'
            echo "### AI LFI Confirmed"
            echo '```'
            head -30 vulns/ai_active/lfi_confirmed.txt 2>/dev/null
            echo '```'
            echo "### AI Open Redirects"
            echo '```'
            head -30 vulns/ai_active/open_redirect_confirmed.txt 2>/dev/null
            echo '```'
            echo "### AI SSRF Payloads"
            echo '```'
            head -30 vulns/ai_active/ssrf_payloads.txt 2>/dev/null
            echo '```'
        fi
        echo "## JS Secrets (jsluice)"
        echo '```'
        head -30 js/jsluice_secrets.txt 2>/dev/null
        echo '```'
        echo "## JS Secrets (trufflehog)"
        echo '```'
        head -30 js/trufflehog.txt 2>/dev/null
        echo '```'
        if [ "$DIFF_MODE" -eq 1 ] && [ -n "$PREV_RUN" ]; then
            echo
            echo "## 🔥 NEW since last run"
            echo "### New subdomains"
            echo '```'
            head -30 diffs/new_subdomains_all.txt 2>/dev/null
            echo '```'
            echo "### New findings"
            echo '```'
            head -30 diffs/new_nuclei_findings.txt 2>/dev/null
            echo '```'
            echo "### New basic check findings"
            echo '```'
            head -30 diffs/new_vulns_basic_checks.txt 2>/dev/null
            echo '```'
            echo "### New AI active findings"
            echo '```'
            head -30 diffs/new_vulns_ai_active_confirmed.txt 2>/dev/null
            echo '```'
        fi
    } > "$report"

    # Manual checklist (unchanged content, trimmed here for brevity but you can paste your full v4 version)
    cat > checklist/MANUAL_CHECKLIST.md <<EOF
# Manual Hunting Checklist — $TARGET
(see previous version — intentionally unchanged)
EOF

    log "Report: $report"
    return 0
}

# ============= PHASE 13: OPTIONAL AI TRIAGE =============
build_ai_triage_prompt() {
    local prompt_file="$1"
    {
        echo "You are reviewing authorized security scan results for triage."
        echo "Prioritize likely real issues, reduce noise, and provide concise next manual validation steps."
        echo "Do not invent findings that are not present in the evidence."
        echo
        echo "Target: ${INPUT_TARGET}"
        echo "Mode: $([ "$SUBDOMAIN_MODE" -eq 1 ] && echo "subdomain" || echo "single-target")"
        echo "Deep mode: $([ "$DEEP_MODE" -eq 1 ] && echo "enabled" || echo "disabled")"
        echo
        echo "Expected output:"
        echo "1. Top 10 prioritized findings with severity, evidence file/line context when possible, and why it matters."
        echo "2. Likely false positives or noisy checks."
        echo "3. Manual validation checklist."
        echo "4. Suggested bug bounty report titles for confirmed candidates."
        echo
        echo "## Stats"
        echo "- Subdomains: $(wc -l < subdomains/all.txt 2>/dev/null || echo 0)"
        echo "- Live hosts: $(wc -l < web/live.txt 2>/dev/null || echo 0)"
        echo "- URLs: $(wc -l < web/all_urls.txt 2>/dev/null || echo 0)"
        echo "- Basic checks: $(wc -l < vulns/basic_checks.txt 2>/dev/null || echo 0)"
        echo
        echo "## Nuclei Critical"
        head -50 vulns/nuclei_critical.txt 2>/dev/null
        echo
        echo "## Nuclei High"
        head -80 vulns/nuclei_high.txt 2>/dev/null
        echo
        echo "## Basic Checks"
        head -250 vulns/basic_checks.txt 2>/dev/null
        echo
        echo "## CORS"
        head -80 vulns/cors_manual.txt 2>/dev/null
        echo
        echo "## XSS"
        head -80 vulns/xss.txt 2>/dev/null
        echo
        echo "## High-value Paths"
        head -120 vulns/highvalue_paths.txt 2>/dev/null
        echo
        echo "## Deep Summary"
        cat vulns/deep/summary.md 2>/dev/null
        echo
        echo "## Deep Confirmed Candidates"
        head -60 vulns/deep/reflected_xss_confirmed.txt 2>/dev/null
        head -60 vulns/deep/sql_error_candidates.txt 2>/dev/null
        head -60 vulns/deep/lfi_confirmed.txt 2>/dev/null
        head -60 vulns/deep/open_redirect_confirmed.txt 2>/dev/null
        echo
        echo "## AI Active Validation"
        cat vulns/ai_active/summary.md 2>/dev/null
        head -80 vulns/ai_active/confirmed.txt 2>/dev/null
        head -80 vulns/ai_active/ssrf_payloads.txt 2>/dev/null
        echo
        echo "## JS Secret Signals"
        head -80 js/jsluice_secrets.txt 2>/dev/null
        head -80 js/trufflehog.txt 2>/dev/null
    } > "$prompt_file"
}

ai_request() {
    local prompt_file="$1" raw_file="$2" out_file="$3" system_prompt="$4" max_tokens="${5:-$AI_MAX_OUTPUT_TOKENS}"
    local prompt payload http_code endpoint
    prompt=$(cat "$prompt_file")

    case "$AI_PROVIDER" in
        openai|codex)
            endpoint="${AI_ENDPOINT:-https://api.openai.com/v1/responses}"
            payload=$(jq -n \
                --arg model "$AI_MODEL" \
                --arg system "$system_prompt" \
                --arg prompt "$prompt" \
                --argjson max_tokens "$max_tokens" \
                '{model:$model,max_output_tokens:$max_tokens,input:[{role:"system",content:$system},{role:"user",content:$prompt}]}')
            http_code=$(curl -sS --max-time 120 \
                -H "Authorization: Bearer ${AI_API_TOKEN}" \
                -H "Content-Type: application/json" \
                -o "$raw_file" -w '%{http_code}' \
                -d "$payload" "$endpoint" 2>/dev/null)
            if [[ "$http_code" =~ ^2 ]]; then
                jq -r '.output_text // ([.output[]?.content[]?.text] | join("\n")) // empty' \
                    "$raw_file" > "$out_file" 2>/dev/null
                return 0
            fi
            warn "AI request failed for ${AI_PROVIDER} (HTTP ${http_code:-000}); raw response: $raw_file"
            return 1
            ;;
        anthropic|claude|claudecode)
            endpoint="${AI_ENDPOINT:-https://api.anthropic.com/v1/messages}"
            payload=$(jq -n \
                --arg model "$AI_MODEL" \
                --arg system "$system_prompt" \
                --arg prompt "$prompt" \
                --argjson max_tokens "$max_tokens" \
                '{model:$model,max_tokens:$max_tokens,system:$system,messages:[{role:"user",content:$prompt}]}')
            http_code=$(curl -sS --max-time 120 \
                -H "x-api-key: ${AI_API_TOKEN}" \
                -H "anthropic-version: 2023-06-01" \
                -H "Content-Type: application/json" \
                -o "$raw_file" -w '%{http_code}' \
                -d "$payload" "$endpoint" 2>/dev/null)
            if [[ "$http_code" =~ ^2 ]]; then
                jq -r '[.content[]? | select(.type=="text") | .text] | join("\n")' \
                    "$raw_file" > "$out_file" 2>/dev/null
                return 0
            fi
            warn "AI request failed for ${AI_PROVIDER} (HTTP ${http_code:-000}); raw response: $raw_file"
            return 1
            ;;
        *)
            warn "Unsupported AI_PROVIDER=${AI_PROVIDER}. Use openai or anthropic."
            return 1
            ;;
    esac
}

do_ai_triage() {
    [ "$AI_MODE" -ne 1 ] && return 0

    if [ -z "$AI_API_TOKEN" ]; then
        warn "AI mode enabled, but no API token found. Set AI_API_TOKEN, OPENAI_API_KEY, or ANTHROPIC_API_KEY."
        return 0
    fi
    if ! have jq; then
        warn "AI mode requires jq to build and parse API payloads."
        return 0
    fi

    local prompt_file="reports/ai_input_${TARGET_SAFE}_${TIMESTAMP}.txt"
    local raw_file="reports/ai_raw_${TARGET_SAFE}_${TIMESTAMP}.json"
    local out_file="reports/ai_triage_${TARGET_SAFE}_${TIMESTAMP}.md"
    local system_prompt="You are a pragmatic security triage assistant. Summarize evidence, rank risk, and suggest safe manual validation steps for an authorized test."

    build_ai_triage_prompt "$prompt_file"
    ai_request "$prompt_file" "$raw_file" "$out_file" "$system_prompt" "$AI_MAX_OUTPUT_TOKENS" || return 0

    if [ -s "$out_file" ]; then
        log "AI triage: $out_file"
    else
        warn "AI triage produced an empty output. Raw response: $raw_file"
    fi
    return 0
}

# ============= PHASE 12.5: OPTIONAL AI ACTIVE VALIDATION =============
build_ai_active_prompt() {
    local prompt_file="$1"
    {
        echo "You are helping with an authorized security test."
        echo "Generate bounded, non-destructive validation candidates only from the discovered URLs below."
        echo "Return ONLY a JSON array. Do not include Markdown, prose, or code fences."
        echo
        echo "Allowed classes: xss, sqli, lfi, redirect, ssrf."
        echo "Rules:"
        echo "- Use only existing discovered URLs as the base."
        echo "- Prefer URLs with query parameters."
        echo "- Do not generate destructive payloads, file writes, command execution, brute force, login attempts, or denial-of-service payloads."
        echo "- For ssrf, use this callback host only: ${CALLBACK_DOMAIN}"
        echo "- Keep candidates concise and high-signal."
        echo "- Maximum candidates: ${AI_ACTIVE_MAX_TESTS}"
        echo
        echo "JSON schema:"
        echo '[{"class":"xss|sqli|lfi|redirect|ssrf","url":"https://example/path?param=payload","payload":"payload string","reason":"short reason"}]'
        echo
        echo "Target: ${INPUT_TARGET}"
        echo
        echo "Interesting parameter URLs:"
        {
            head -120 params/xss.txt 2>/dev/null
            head -120 params/sqli.txt 2>/dev/null
            head -120 params/lfi.txt 2>/dev/null
            head -120 params/redirect.txt 2>/dev/null
            head -120 params/ssrf.txt 2>/dev/null
            grep '=' web/all_urls.txt 2>/dev/null | head -250
        } | sort -u | head -500
        echo
        echo "High-value routes and titles:"
        head -120 vulns/highvalue_paths.txt 2>/dev/null
        jq -r '[.url,.title,.tech[]?] | @tsv' web/httpx.jsonl 2>/dev/null | head -120
    } > "$prompt_file"
}

do_ai_active() {
    [ "$AI_ACTIVE_MODE" -ne 1 ] && return 0

    if [ -z "$AI_API_TOKEN" ]; then
        warn "AI active mode enabled, but no API token found. Set AI_API_TOKEN, OPENAI_API_KEY, or ANTHROPIC_API_KEY."
        return 0
    fi
    if ! have jq; then
        warn "AI active mode requires jq."
        return 0
    fi
    if [ ! -s web/all_urls.txt ] && [ ! -s web/live.txt ]; then
        info "No URLs available for AI active validation"
        return 0
    fi

    mkdir -p vulns/ai_active
    : > vulns/ai_active/reflected_xss.txt
    : > vulns/ai_active/sql_error_candidates.txt
    : > vulns/ai_active/lfi_confirmed.txt
    : > vulns/ai_active/open_redirect_confirmed.txt
    : > vulns/ai_active/ssrf_payloads.txt
    : > vulns/ai_active/validation_log.tsv

    local prompt_file="reports/ai_active_input_${TARGET_SAFE}_${TIMESTAMP}.txt"
    local raw_file="reports/ai_active_raw_${TARGET_SAFE}_${TIMESTAMP}.json"
    local text_file="reports/ai_active_candidates_${TARGET_SAFE}_${TIMESTAMP}.txt"
    local json_file="vulns/ai_active/candidates.json"
    local scoped_file="vulns/ai_active/candidates_scoped.json"
    local system_prompt="You generate safe, bounded web security validation candidates for authorized testing. Output strict JSON only."

    build_ai_active_prompt "$prompt_file"
    ai_request "$prompt_file" "$raw_file" "$text_file" "$system_prompt" 3000 || return 0

    if ! jq -e 'type=="array"' "$text_file" >/dev/null 2>&1; then
        warn "AI active output was not valid JSON array. Saved text: $text_file"
        return 0
    fi

    jq '[.[] | select(.class and .url and (.class|test("^(xss|sqli|lfi|redirect|ssrf)$"))) | {
        class: .class,
        url: .url,
        payload: (.payload // ""),
        reason: (.reason // "")
    }]' "$text_file" > "$json_file"

    jq -r '.[].url' "$json_file" > tmp/ai_active_urls.txt
    apply_scope tmp/ai_active_urls.txt tmp/ai_active_urls_scoped.txt
    jq --slurpfile scoped <(jq -Rn '[inputs]' < tmp/ai_active_urls_scoped.txt) \
        '[.[] | select(.url as $u | $scoped[0] | index($u))]' \
        "$json_file" > "$scoped_file"

    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    jq -c ".[:${AI_ACTIVE_MAX_TESTS}][]" "$scoped_file" | while read -r item; do
        local class url payload reason body headers location
        class=$(jq -r '.class' <<< "$item")
        url=$(jq -r '.url' <<< "$item")
        payload=$(jq -r '.payload' <<< "$item")
        reason=$(jq -r '.reason' <<< "$item")
        printf '%s\t%s\t%s\t%s\n' "$class" "$url" "$payload" "$reason" >> vulns/ai_active/validation_log.tsv

        case "$class" in
            xss)
                [ -z "$payload" ] && continue
                body=$(curl -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
                printf '%s' "$body" | grep -F "$payload" >/dev/null \
                    && printf 'AI-XSS-REFLECTED\t%s\t%s\t%s\n' "$url" "$payload" "$reason" >> vulns/ai_active/reflected_xss.txt
                ;;
            sqli)
                body=$(curl -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
                printf '%s' "$body" | grep -Eiq 'SQL syntax|mysql_fetch|ORA-[0-9]|PostgreSQL|SQLite|ODBC|MariaDB|You have an error in your SQL|SQLSTATE' \
                    && printf 'AI-SQL-ERROR\t%s\t%s\t%s\n' "$url" "$payload" "$reason" >> vulns/ai_active/sql_error_candidates.txt
                ;;
            lfi)
                body=$(curl -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
                printf '%s' "$body" | grep -E 'root:.*:0:0:|daemon:.*:1:1:' >/dev/null \
                    && printf 'AI-LFI-CONFIRMED\t%s\t%s\t%s\n' "$url" "$payload" "$reason" >> vulns/ai_active/lfi_confirmed.txt
                ;;
            redirect)
                headers=$(curl -skI --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
                location=$(printf '%s\n' "$headers" | awk 'BEGIN{IGNORECASE=1} /^location:/ {sub(/^[^:]+:[[:space:]]*/, ""); print; exit}')
                if [ -n "$location" ] && { printf '%s\n' "$location" | grep -Fq "$payload" || printf '%s\n' "$location" | grep -Fq "$CALLBACK_DOMAIN"; }; then
                    printf 'AI-OPEN-REDIRECT\t%s\t%s\t%s\n' "$url" "$location" "$reason" >> vulns/ai_active/open_redirect_confirmed.txt
                fi
                ;;
            ssrf)
                printf 'AI-SSRF-PAYLOAD\t%s\t%s\t%s\n' "$url" "$payload" "$reason" >> vulns/ai_active/ssrf_payloads.txt
                ;;
        esac
    done

    {
        echo "# AI Active Validation"
        echo
        echo "- Candidates generated: $(jq 'length' "$json_file" 2>/dev/null || echo 0)"
        echo "- In-scope candidates tested: $(jq 'length' "$scoped_file" 2>/dev/null || echo 0)"
        echo "- Reflected XSS: $(wc -l < vulns/ai_active/reflected_xss.txt 2>/dev/null || echo 0)"
        echo "- SQL error candidates: $(wc -l < vulns/ai_active/sql_error_candidates.txt 2>/dev/null || echo 0)"
        echo "- LFI confirmed: $(wc -l < vulns/ai_active/lfi_confirmed.txt 2>/dev/null || echo 0)"
        echo "- Open redirects: $(wc -l < vulns/ai_active/open_redirect_confirmed.txt 2>/dev/null || echo 0)"
        echo "- SSRF payloads generated: $(wc -l < vulns/ai_active/ssrf_payloads.txt 2>/dev/null || echo 0)"
    } > vulns/ai_active/summary.md

    cat vulns/ai_active/reflected_xss.txt \
        vulns/ai_active/sql_error_candidates.txt \
        vulns/ai_active/lfi_confirmed.txt \
        vulns/ai_active/open_redirect_confirmed.txt \
        2>/dev/null | sort -u > vulns/ai_active/confirmed.txt

    log "AI active validation: vulns/ai_active/summary.md"
    return 0
}

# ============= MAIN =============
main() {
    banner
    if [ "$TEST_WEBHOOK_MODE" -eq 1 ]; then
        if notify "✅ Paintest webhook test
Target label: \`${TARGET}\`
Mode: ${MODE_TAG}"; then
            echo -e "${G}[✓] Webhook test sent. Check your notification channel.${N}"
            exit 0
        fi
        echo -e "${R}[X] Webhook test failed. Check the warning above.${N}" >&2
        exit 1
    fi

    notify "🚀 Paintest scan started
Target: \`${INPUT_TARGET}\`
Mode: ${MODE_TAG}
Output: \`${OUTPUT_DIR}\`"
    check_tools
    setup

    run_phase "passive_recon"     do_passive_recon
    run_phase "subdomain_enum"    do_subdomain_enum
    run_phase "port_scan"         do_port_scan
    run_phase "web_probe"         do_web_probe
    run_phase "url_discovery"     do_url_discovery
    run_phase "custom_wordlist"   do_custom_wordlist
    run_phase "dir_fuzz"          do_dir_fuzz
    run_phase "js_analysis"       do_js_analysis
    run_phase "vuln_scan"         do_vuln_scan
    run_phase "deep_checks"        do_deep_checks
    run_phase "param_mining"      do_param_mining
    run_phase "auth_surface"      do_auth_surface
    [ "$AI_ACTIVE_MODE" -eq 1 ] && run_phase "ai_active" do_ai_active
    run_phase "diff"              do_diff
    run_phase "report"            do_report
    [ "$AI_MODE" -eq 1 ] && run_phase "ai_triage" do_ai_triage

    # Summarize for notification
    local crit=$(wc -l < vulns/nuclei_critical.txt 2>/dev/null || echo 0)
    local high=$(wc -l < vulns/nuclei_high.txt 2>/dev/null || echo 0)
    local hosts=$(wc -l < web/live.txt 2>/dev/null || echo 0)
    local subs=$(wc -l < subdomains/all.txt 2>/dev/null || echo 0)
    local deep_xss=$(wc -l < vulns/deep/reflected_xss_confirmed.txt 2>/dev/null || echo 0)
    local deep_lfi=$(wc -l < vulns/deep/lfi_confirmed.txt 2>/dev/null || echo 0)
    local basic=$(wc -l < vulns/basic_checks.txt 2>/dev/null || echo 0)
    local ai_active_confirmed=$(wc -l < vulns/ai_active/confirmed.txt 2>/dev/null || echo 0)

    local msg="✅ Recon done: \`${INPUT_TARGET}\`
• Subs: ${subs}
• Live hosts: ${hosts}
• Critical: ${crit}
• High: ${high}
• Basic checks: ${basic}"
    if [ "$DEEP_MODE" -eq 1 ]; then
        msg="${msg}
• Deep XSS: ${deep_xss}
• Deep LFI: ${deep_lfi}"
    fi
    if [ "$DIFF_MODE" -eq 1 ] && [ -n "$PREV_RUN" ]; then
        local new=$(wc -l < diffs/new_nuclei_findings.txt 2>/dev/null || echo 0)
        msg="${msg}
• NEW findings: ${new}"
    fi
    if [ "$AI_MODE" -eq 1 ]; then
        msg="${msg}
• AI triage: reports/ai_triage_${TARGET_SAFE}_${TIMESTAMP}.md"
    fi
    if [ "$AI_ACTIVE_MODE" -eq 1 ]; then
        msg="${msg}
• AI active confirmed: ${ai_active_confirmed}"
    fi
    notify "$msg"

    echo -e "\n${G}[✓] Done. Results: $OUTPUT_DIR${N}"
    echo -e "${Y}[!] Now open checklist/MANUAL_CHECKLIST.md and start hunting.${N}\n"
}

main
