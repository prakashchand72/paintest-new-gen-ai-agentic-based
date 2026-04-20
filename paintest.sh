#!/usr/bin/env bash
################################################################################
# Paintest Framework v6 — pentesting recon pipeline
# Orchestrator; actual phase logic lives in lib/*.sh
#
# Usage:
#   ./paintest.sh <target>                    → single-target pentest
#   ./paintest.sh -sd <target>                → + subdomain discovery
#   ./paintest.sh -sd -r <target>             → + resume from last run
#   ./paintest.sh -sd -d <target>             → + diff against previous run
#   ./paintest.sh -ai <target>                → + AI triage after scan
#   ./paintest.sh --ai-active <target>        → + bounded AI-assisted validation
#   ./paintest.sh --deep <target>             → + deep validation + extra checks
#
# Env knobs of note:
#   BOUNTY_HANDLE, CALLBACK_DOMAIN, WEBHOOK_URL
#   AUTH_HEADER, AUTH_COOKIE, SCOPE_FILE
#   THREADS, RATE, DEEP_THREADS, DEEP_RATE
#   AI_PROVIDER=openai|anthropic, AI_API_TOKEN, AI_MODEL, AI_ACTIVE_MAX_TESTS
#   HTTP_PROXY            proxy passthrough (Burp tee etc.)
#   GITHUB_TOKEN          GitHub dork + trufflehog org scans
#   SQLMAP_RISK=1         allow sqlmap handoff on SQLi candidates
#   PAINTEST_ADAPTIVE=0   disable adaptive RATE/THREADS backoff
################################################################################

set -uo pipefail
# No -e: tool failures must not abort the pipeline.

# ============= AUTO-LOAD CONFIG =============
# Priority: ~/.recon.conf < $(pwd)/.env < script defaults
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
                Enable deep validation checks and broader real-world coverage
  --test-webhook
                Send one webhook test message and exit
  -h, --help    Show this help
EOF
            exit 0
            ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [ "$TEST_WEBHOOK_MODE" -eq 1 ] && [ -z "$TARGET" ]; then
    TARGET="webhook-test"
fi

[ -z "$TARGET" ] && { echo "Usage: $0 [-sd] [-r] [-d] [-ai|--ai] [--ai-active] [--deep] [--test-webhook] <target>" >&2; exit 1; }

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

# ============= CONFIG DEFAULTS =============
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
HTTP_PROXY="${HTTP_PROXY:-}"
PAINTEST_ADAPTIVE="${PAINTEST_ADAPTIVE:-1}"

if [ "$AI_PROVIDER" = "openai" ] && [ -z "$AI_MODEL" ]; then
    AI_MODEL="gpt-5.4-mini"
elif [ "$AI_PROVIDER" = "anthropic" ] && [ -z "$AI_MODEL" ]; then
    AI_MODEL="claude-sonnet-4-5"
fi
[ -z "$AI_API_TOKEN" ] && [ "$AI_PROVIDER" = "openai" ] && AI_API_TOKEN="${OPENAI_API_KEY:-}"
[ -z "$AI_API_TOKEN" ] && [ "$AI_PROVIDER" = "anthropic" ] && AI_API_TOKEN="${ANTHROPIC_API_KEY:-}"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MODE_TAG=$([ "$SUBDOMAIN_MODE" -eq 1 ] && echo "sd" || echo "single")

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

PREV_RUN=""
if [ "$DIFF_MODE" -eq 1 ]; then
    PREV_RUN=$(ls -dt "$(pwd)/recon_${TARGET_SAFE}_${MODE_TAG}_"* 2>/dev/null \
        | grep -v "$(basename "$OUTPUT_DIR")" | head -1 || true)
    [ -n "$PREV_RUN" ] && echo "[diff] Comparing against: $PREV_RUN"
fi

STATE_FILE="$OUTPUT_DIR/.phase_state"

# ============= SOURCE LIB =============
PAINTEST_LIB="${PAINTEST_LIB:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib}"
for f in common.sh engine.sh recon.sh vuln.sh validate.sh report.sh ai.sh; do
    if [ -r "$PAINTEST_LIB/$f" ]; then
        # shellcheck disable=SC1090
        source "$PAINTEST_LIB/$f"
    else
        echo "[X] Missing lib: $PAINTEST_LIB/$f" >&2
        exit 1
    fi
done

# ============= PHASES =============
# Edit this list to reorder / disable / add phases. Keep it in dataflow order:
# earlier phases write files that later phases read.
PHASES=(
    "passive_recon:do_passive_recon"
    "github_recon:do_github_recon"
    "subdomain_enum:do_subdomain_enum"
    "asn_expand:do_asn_expand"
    "port_scan:do_port_scan"
    "web_probe:do_web_probe"
    "favicon_pivot:do_favicon_pivot"
    "cloud_recon:do_cloud_recon"
    "url_discovery:do_url_discovery"
    "api_spec_hunt:do_api_spec_hunt"
    "custom_wordlist:do_custom_wordlist"
    "dir_fuzz:do_dir_fuzz"
    "js_analysis:do_js_analysis"
    "vuln_scan:do_vuln_scan"
    "cve_correlate:do_cve_correlate"
    "sqli_scan:do_sqli_scan"
    "ssrf_verify:do_ssrf_verify"
    "jwt_scan:do_jwt_scan"
    "graphql_scan:do_graphql_scan"
    "oauth_scan:do_oauth_scan"
    "ssti_scan:do_ssti_scan"
    "nosql_scan:do_nosql_scan"
    "proto_pollution_scan:do_proto_pollution_scan"
    "deep_checks:do_deep_checks"
    "xss_validate:do_xss_validate"
    "idor_probe:do_idor_probe"
    "race_probe:do_race_probe"
    "param_mining:do_param_mining"
    "auth_surface:do_auth_surface"
    "chain_findings:do_chain_findings"
)

PHASE_TOTAL=$(( ${#PHASES[@]} + 2 + AI_MODE + AI_ACTIVE_MODE ))  # +2 for diff+report
PHASE_CURRENT=0

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
 ║   Paintest Recon Framework v6 (pentest-tier)   ║
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
    [ -n "$HTTP_PROXY"  ] && echo -e "${G}[+] Proxy:     ${HTTP_PROXY}${N}"
    [ -n "${GITHUB_TOKEN:-}" ] && echo -e "${G}[+] GitHub:    token set${N}"
    [ -n "${SQLMAP_RISK:-}" ]  && echo -e "${R}[+] sqlmap:    ENABLED (risk=${SQLMAP_RISK})${N}"
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

check_tools() {
    log "Checking tools"
    local tools=(subfinder assetfinder amass httpx nuclei naabu dnsx katana gau
                 waybackurls ffuf nmap dalfox gf wafw00f testssl.sh
                 trufflehog gitleaks arjun unfurl anew qsreplace gotator
                 gowitness subjs jsluice uro jq)
    local optional=(asnmap metabigor mapcidr s3scanner cloud_enum
                    gitdorks_go jwt_tool graphql-cop sqlmap gh python3)
    local missing=() opt_missing=()
    local t
    for t in "${tools[@]}"; do have "$t" || missing+=("$t"); done
    for t in "${optional[@]}"; do have "$t" || opt_missing+=("$t"); done
    [ ${#missing[@]} -gt 0 ]     && warn "Missing (will skip): ${missing[*]}"
    [ ${#opt_missing[@]} -gt 0 ] && info "Optional missing (phases degrade): ${opt_missing[*]}"
}

setup() {
    mkdir -p "$OUTPUT_DIR"/{recon,recon/github,recon/cloud,recon/asn,recon/apispec,recon/favicon,\
subdomains,ports,web,vulns,vulns/sqli,vulns/ssrf,vulns/jwt,vulns/graphql,vulns/oauth,vulns/ssti,\
vulns/nosql,vulns/proto_pollution,vulns/cve,vulns/deep,vulns/ai_active,\
fuzzing,screenshots,js,js/content,params,checklist,reports,diffs,tmp,validate,validate/race}
    cd "$OUTPUT_DIR" || exit 1
    touch "$STATE_FILE"
    log "Working dir: $OUTPUT_DIR"
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

    # Run all registered phases
    local entry name fn
    for entry in "${PHASES[@]}"; do
        name="${entry%%:*}"
        fn="${entry##*:}"
        run_phase "$name" "$fn"
    done

    # Optional AI active runs between chain_findings and diff/report
    [ "$AI_ACTIVE_MODE" -eq 1 ] && run_phase "ai_active" do_ai_active

    run_phase "diff"   do_diff
    run_phase "report" do_report

    [ "$AI_MODE" -eq 1 ] && run_phase "ai_triage" do_ai_triage

    # Summary counts for final webhook
    local crit high hosts subs deep_xss deep_lfi basic ai_active_confirmed
    local sqli_err sqli_time ssrf_meta graphql_intro jwt_tokens xss_conf idor chains
    crit=$(wc -l < vulns/nuclei_critical.txt 2>/dev/null || echo 0)
    high=$(wc -l < vulns/nuclei_high.txt 2>/dev/null || echo 0)
    hosts=$(wc -l < web/live.txt 2>/dev/null || echo 0)
    subs=$(wc -l < subdomains/all.txt 2>/dev/null || echo 0)
    deep_xss=$(wc -l < vulns/deep/reflected_xss_confirmed.txt 2>/dev/null || echo 0)
    deep_lfi=$(wc -l < vulns/deep/lfi_confirmed.txt 2>/dev/null || echo 0)
    basic=$(wc -l < vulns/basic_checks.txt 2>/dev/null || echo 0)
    ai_active_confirmed=$(wc -l < vulns/ai_active/confirmed.txt 2>/dev/null || echo 0)
    sqli_err=$(wc -l < vulns/sqli/error_based.tsv 2>/dev/null || echo 0)
    sqli_time=$(wc -l < vulns/sqli/time_based.tsv 2>/dev/null || echo 0)
    ssrf_meta=$(wc -l < vulns/ssrf/localhost_probe.tsv 2>/dev/null || echo 0)
    graphql_intro=$(wc -l < vulns/graphql/introspection.tsv 2>/dev/null || echo 0)
    jwt_tokens=$(wc -l < vulns/jwt/found_tokens.tsv 2>/dev/null || echo 0)
    xss_conf=$(wc -l < validate/xss_confirmed.tsv 2>/dev/null || echo 0)
    idor=$(wc -l < validate/idor_candidates.tsv 2>/dev/null || echo 0)
    chains=$(grep -c '^## Chain ' reports/attack_chains.md 2>/dev/null || echo 0)

    local msg="✅ Recon done: \`${INPUT_TARGET}\`
• Subs: ${subs}
• Live hosts: ${hosts}
• Critical: ${crit}
• High: ${high}
• XSS confirmed: ${xss_conf}
• SQLi err/time: ${sqli_err}/${sqli_time}
• SSRF metadata: ${ssrf_meta}
• GraphQL introspect: ${graphql_intro}
• JWT tokens: ${jwt_tokens}
• IDOR candidates: ${idor}
• Basic checks: ${basic}
• Attack chains: ${chains}"
    if [ "$DEEP_MODE" -eq 1 ]; then
        msg="${msg}
• Deep XSS: ${deep_xss}
• Deep LFI: ${deep_lfi}"
    fi
    if [ "$DIFF_MODE" -eq 1 ] && [ -n "$PREV_RUN" ]; then
        local new
        new=$(wc -l < diffs/new_nuclei_findings.txt 2>/dev/null || echo 0)
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
    echo -e "${Y}[!] Open reports/report_${TARGET_SAFE}_${TIMESTAMP}.md and checklist/MANUAL_CHECKLIST.md${N}\n"
}

main
