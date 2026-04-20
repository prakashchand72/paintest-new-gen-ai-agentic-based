# shellcheck shell=bash
# Paintest — engine: adaptive rate limiting, proxy passthrough, URL dedup/norm,
# lightweight parallel runner. Sourced after lib/common.sh.

# ============ Proxy passthrough ============
# If $HTTP_PROXY is set, all curl/httpx/nuclei/ffuf wrappers prepend proxy flags.
# Callers use the curl_p / httpx_p / nuclei_p / ffuf_p wrappers to get the
# proxy treatment automatically.
PAINTEST_PROXY="${HTTP_PROXY:-${PAINTEST_PROXY:-}}"
[ -n "$PAINTEST_PROXY" ] && info "Proxy active: $PAINTEST_PROXY"

curl_p() {
    if [ -n "$PAINTEST_PROXY" ]; then
        curl --proxy "$PAINTEST_PROXY" -k "$@"
    else
        curl "$@"
    fi
}

httpx_p() {
    have httpx || return 1
    if [ -n "$PAINTEST_PROXY" ]; then
        httpx -http-proxy "$PAINTEST_PROXY" "$@"
    else
        httpx "$@"
    fi
}

nuclei_p() {
    have nuclei || return 1
    if [ -n "$PAINTEST_PROXY" ]; then
        nuclei -proxy "$PAINTEST_PROXY" "$@"
    else
        nuclei "$@"
    fi
}

ffuf_p() {
    have ffuf || return 1
    if [ -n "$PAINTEST_PROXY" ]; then
        ffuf -x "$PAINTEST_PROXY" "$@"
    else
        ffuf "$@"
    fi
}

# ============ Adaptive rate limiting ============
# Adapts RATE/THREADS down when the target returns too many 429/5xx.
# Probes a single URL and trims RATE/THREADS for the remaining phases.
adaptive_probe() {
    local url="$1"
    [ -z "$url" ] && return 0
    [ "${PAINTEST_ADAPTIVE:-1}" != "1" ] && return 0

    local hits=0 total=5 code
    for _ in $(seq 1 $total); do
        code=$(curl_p -skL --max-time 8 -o /dev/null -w '%{http_code}' \
            -A "$UA" -H "$ID_HEADER" "$url" 2>/dev/null)
        [[ "$code" =~ ^(429|5[0-9][0-9])$ ]] && hits=$((hits+1))
        sleep 0.2
    done
    if [ "$hits" -ge 2 ]; then
        local old_rate="$RATE" old_threads="$THREADS"
        RATE=$(( RATE / 2 ))
        THREADS=$(( THREADS / 2 ))
        [ "$RATE" -lt 3 ] && RATE=3
        [ "$THREADS" -lt 3 ] && THREADS=3
        DEEP_RATE=$(( DEEP_RATE / 2 ))
        DEEP_THREADS=$(( DEEP_THREADS / 2 ))
        [ "$DEEP_RATE" -lt 5 ] && DEEP_RATE=5
        [ "$DEEP_THREADS" -lt 5 ] && DEEP_THREADS=5
        warn "Adaptive backoff: target returned ${hits}/${total} rate/err responses. \
RATE ${old_rate}→${RATE}, THREADS ${old_threads}→${THREADS}"
    fi
    return 0
}

# ============ URL normalization + dedup ============
# Normalizes a URL to a canonical form for dedup:
# - lowercase host
# - strip default ports
# - strip fragment
# - sort & dedup query keys (values replaced with FUZZ token)
normalize_url() {
    python3 - "$@" 2>/dev/null <<'PY' || true
import sys
from urllib.parse import urlsplit, parse_qsl, urlunsplit, urlencode
for raw in sys.argv[1:]:
    try:
        s = urlsplit(raw.strip())
        host = s.hostname.lower() if s.hostname else ""
        port = s.port
        if (s.scheme == "http" and port == 80) or (s.scheme == "https" and port == 443):
            port = None
        netloc = host + (f":{port}" if port else "")
        if s.username:
            netloc = f"{s.username}{':'+s.password if s.password else ''}@" + netloc
        q = sorted(set(k for k, _ in parse_qsl(s.query, keep_blank_values=True)))
        query = urlencode([(k, "FUZZ") for k in q])
        print(urlunsplit((s.scheme, netloc, s.path or "/", query, "")))
    except Exception:
        print(raw)
PY
}

# Dedup URLs in a file by (normalized-key + body-hash when available).
# Usage: dedup_urls <input-file> <output-file>
dedup_urls() {
    local infile="$1" outfile="$2"
    [ ! -s "$infile" ] && { : > "$outfile"; return 0; }
    if have python3; then
        python3 - "$infile" "$outfile" <<'PY'
import sys
from urllib.parse import urlsplit, parse_qsl, urlunsplit, urlencode
inp, out = sys.argv[1], sys.argv[2]
seen = set()
with open(inp) as fh, open(out, 'w') as w:
    for raw in fh:
        raw = raw.strip()
        if not raw:
            continue
        try:
            s = urlsplit(raw)
            host = s.hostname.lower() if s.hostname else ""
            port = s.port
            if (s.scheme == "http" and port == 80) or (s.scheme == "https" and port == 443):
                port = None
            netloc = host + (f":{port}" if port else "")
            q = sorted(set(k for k, _ in parse_qsl(s.query, keep_blank_values=True)))
            key = urlunsplit((s.scheme, netloc, s.path or "/", urlencode([(k,"") for k in q]), ""))
        except Exception:
            key = raw
        if key in seen:
            continue
        seen.add(key)
        w.write(raw + "\n")
PY
    else
        sort -u "$infile" > "$outfile"
    fi
}

# ============ Parallel runner ============
# Fan out a list of inputs over a function using xargs -P.
# Usage: parallel_map <N> <fn_name> < list
parallel_map() {
    local n="$1"; shift
    local fn="$1"; shift
    export -f "$fn" 2>/dev/null || true
    xargs -P "$n" -I{} bash -c "$fn \"\$1\"" _ {}
}

# ============ Safe bounded concurrent background runner ============
# Tracks spawned pids so cleanup can kill them.
PAINTEST_BG_PIDS=()
spawn_bg() {
    "$@" &
    PAINTEST_BG_PIDS+=("$!")
}
wait_bg() {
    local pid
    for pid in "${PAINTEST_BG_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
    PAINTEST_BG_PIDS=()
}
