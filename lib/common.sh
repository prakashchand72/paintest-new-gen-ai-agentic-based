# shellcheck shell=bash
# Paintest — common helpers. Sourced by paintest.sh.
# Depends on globals set by paintest.sh before sourcing:
#   OUTPUT_DIR, STATE_FILE, INPUT_TARGET, TARGET, TARGET_HOST, TARGET_SCAN,
#   HANDLE, ID_HEADER, UA, AUTH_HEADER, AUTH_COOKIE, SCOPE_FILE,
#   WEBHOOK_URL, WEBHOOK_CONNECT_TIMEOUT, WEBHOOK_TIMEOUT, WEBHOOK_RETRIES,
#   HTTP_TIMEOUT, API_TIMEOUT, THREADS, RATE, DEEP_THREADS, DEEP_RATE,
#   HTTP_PROXY (optional), PAINTEST_ADAPTIVE (optional).

# ============ Colors / logging ============
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'
log()   { echo -e "${B}[$(date +%H:%M:%S)]${N} ${G}$*${N}"; }
warn()  { echo -e "${Y}[!] $*${N}"; }
err()   { echo -e "${R}[X] $*${N}" >&2; }
info()  { echo -e "${C}[i] $*${N}"; }

have() { command -v "$1" &>/dev/null; }

# ============ Webhook notifications ============
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

notify() {
    [ -z "${WEBHOOK_URL:-}" ] && return
    local msg="$1"
    local json_msg
    if have jq; then
        json_msg=$(jq -Rn --arg msg "$msg" '$msg')
    else
        json_msg=$(printf '%s' "$msg" \
            | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
            | awk 'BEGIN { printf "\"" } { if (NR > 1) printf "\\n"; printf "%s", $0 } END { print "\"" }')
    fi

    local payload
    if [[ "$WEBHOOK_URL" == *"discord.com"* || "$WEBHOOK_URL" == *"discordapp.com"* ]]; then
        payload="{\"content\": ${json_msg}}"
    elif [[ "$WEBHOOK_URL" == *"slack.com"* || "$WEBHOOK_URL" == *"hooks.slack"* ]]; then
        payload="{\"text\": ${json_msg}}"
    elif [[ "$WEBHOOK_URL" == *"api.telegram.org"* ]]; then
        local http_code curl_rc
        http_code=$(send_webhook_request --data-urlencode "text=${msg}" "$WEBHOOK_URL")
        curl_rc=$?
        [[ "$http_code" =~ ^2 ]] && return 0
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
    [[ "$http_code" =~ ^2 ]] && return 0
    warn "Webhook notification failed (HTTP ${http_code:-000}, curl rc=${curl_rc})"
    return 1
}

# ============ URL / version helpers ============
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

# ============ Header builders ============
curl_headers() {
    printf -- '-H\n%s\n' "$ID_HEADER"
    [ -n "${AUTH_HEADER:-}" ] && printf -- '-H\n%s\n' "$AUTH_HEADER"
    [ -n "${AUTH_COOKIE:-}" ] && printf -- '-H\n%s\n' "Cookie: $AUTH_COOKIE"
}

httpx_hdrs() {
    local args=(-H "$ID_HEADER")
    [ -n "${AUTH_HEADER:-}" ] && args+=(-H "$AUTH_HEADER")
    [ -n "${AUTH_COOKIE:-}" ] && args+=(-H "Cookie: $AUTH_COOKIE")
    printf '%s\n' "${args[@]}"
}

# ============ Scope filter ============
apply_scope() {
    local infile="$1" outfile="$2"
    if [ -f "$SCOPE_FILE" ] && [ -s "$SCOPE_FILE" ]; then
        grep -F -f "$SCOPE_FILE" "$infile" 2>/dev/null | sort -u > "$outfile"
    else
        grep -E "(^|\.)${TARGET//./\\.}(\$|/|:)" "$infile" 2>/dev/null | sort -u > "$outfile"
    fi
}

safe_append() {
    local line="$1" file="$2"
    (
        flock -x 200
        echo "$line" >> "$file"
    ) 200>>"${file}.lock"
}

# ============ Phase checkpointing ============
phase_done() { grep -q "^${1}:done$" "$STATE_FILE" 2>/dev/null; }
mark_phase() { echo "${1}:done" >> "$STATE_FILE"; }

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

run_phase() {
    local name="$1"; shift
    if phase_done "$name"; then
        info "Skip ${name} (checkpoint)"
        notify_phase_progress "$name" "skipped (checkpoint)"
        return 0
    fi
    log "▶ Phase: ${name}"
    local t0; t0=$(date +%s)
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
    return "$rc"
}
