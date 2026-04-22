# shellcheck shell=bash
# Paintest — reporting: Markdown, SARIF, HTML, CVSS-ish scoring, PoC snippets.

# ============ Tech version classification (OWASP A06) ============
# Static baselines for the app-layer libraries wappalyzer/httpx typically tags.
# Server-layer (Apache/nginx/PHP/...) is already handled by
# record_outdated_version_candidates() in common.sh — keep that authoritative.
# NOTE: this is a manual table, not a live feed. Drift is expected; treat
# "outdated" as a signal to verify, not a guarantee.
declare -gA PAINTEST_TECH_LATEST=(
    [jquery]="3.7.1"
    [jquery-migrate]="3.5.2"
    [wordpress]="6.7.0"
    [elementor]="3.21.0"
    [yoast-seo]="23.0"
    [wpml]="4.6.12"
    [site-kit]="1.134.0"
    [imagesloaded]="5.0.0"
    [bootstrap]="5.3.3"
    [angular]="18.0.0"
    [react]="18.3.0"
    [vue]="3.4.0"
    [nextjs]="14.2.0"
    [laravel]="11.0"
    [drupal]="10.3.0"
    [django]="5.0"
    [rails]="7.1.0"
)

# Versions strictly below which a known-exploitable CVE applies.
declare -gA PAINTEST_TECH_VULN_BELOW=(
    [jquery]="3.5.0"
    [jquery-migrate]="3.4.0"
    [wordpress]="6.0.4"
    [drupal]="9.5.0"
    [django]="4.2.0"
    [laravel]="9.52.0"
    [rails]="6.1.7"
    [bootstrap]="4.3.1"
)

declare -gA PAINTEST_TECH_VULN_NOTE=(
    [jquery]="CVE-2020-11022/11023 (XSS via .html())"
    [jquery-migrate]="XSS via jQuery Migrate <3.4"
    [wordpress]="multiple pre-6.0.4 core CVEs"
    [drupal]="multiple pre-9.5 core CVEs"
    [django]="multiple pre-4.2 core CVEs (SQLi, DoS)"
    [laravel]="pre-9.52 has Reflected XSS / auth bypass CVEs"
    [rails]="pre-6.1.7 has multiple CVEs"
    [bootstrap]="CVE-2019-8331 (XSS)"
)

# Lowercase + hyphenate a tech name so it keys into the tables above.
tech_key() {
    printf '%s' "$1" \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/\.js$//; s/[[:space:]]+/-/g; s/[^a-z0-9.-]//g'
}

# Classify a (name, version) pair. Writes the short note (CVE if any) to
# stdout line 2, the status word to stdout line 1. Empty version → "detected".
tech_classify() {
    local name="$1" version="$2" key latest vuln_below note status
    if [ -z "$version" ]; then
        printf 'detected\n\n'; return 0
    fi
    key=$(tech_key "$name")
    latest="${PAINTEST_TECH_LATEST[$key]:-}"
    vuln_below="${PAINTEST_TECH_VULN_BELOW[$key]:-}"

    if [ -n "$vuln_below" ] && is_version_older "$version" "$vuln_below"; then
        note="${PAINTEST_TECH_VULN_NOTE[$key]:-known CVE below $vuln_below}"
        if [ -n "$latest" ] && is_version_older "$version" "$latest"; then
            status="vulnerable+outdated"
        else
            status="vulnerable"
        fi
        printf '%s\n%s\n' "$status" "$note"
        return 0
    fi

    if [ -n "$latest" ]; then
        if is_version_older "$version" "$latest"; then
            printf 'outdated\nlatest %s\n' "$latest"
            return 0
        fi
        printf 'up-to-date\n\n'
        return 0
    fi
    printf 'unknown\n\n'
}

# ============ CVSS-ish scoring ============
# Very rough: maps finding class → CVSS v3.1 base score estimate.
# This is intentionally conservative; real scoring must come from manual triage.
cvss_for_class() {
    case "$1" in
        xss-confirmed)         echo "6.1 CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";;
        sqli-confirmed|sqli-time) echo "9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";;
        sqli-error)            echo "7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";;
        ssrf-metadata)         echo "9.1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N";;
        ssrf)                  echo "7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";;
        takeover)              echo "9.1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N";;
        graphql-introspection) echo "5.3 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";;
        idor-diff)             echo "7.1 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N";;
        open-redirect)         echo "6.1 CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";;
        oauth-redirect-bypass) echo "8.2 CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N";;
        lfi-confirmed)         echo "7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";;
        ssti)                  echo "9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";;
        nosql)                 echo "7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";;
        proto-pollution)       echo "6.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L";;
        leaked-secret)         echo "7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";;
        jwt-weak)              echo "7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";;
        cors-null|cors-reflected|cors-subdomain) echo "5.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";;
        missing-header)        echo "3.1 CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N";;
        mixed-content)         echo "3.7 CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N";;
        tls-legacy)            echo "5.3 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";;
        *)                     echo "0.0 CVSS:3.1/N/A";;
    esac
}

# Render a curl PoC for a finding: (class, url, payload)
curl_poc() {
    local class="$1" url="$2" payload="${3:-}"
    local hdr_args=()
    hdr_args+=("-H" "$ID_HEADER")
    [ -n "${AUTH_HEADER:-}" ] && hdr_args+=("-H" "$AUTH_HEADER")
    [ -n "${AUTH_COOKIE:-}" ] && hdr_args+=("-H" "Cookie: $AUTH_COOKIE")
    local hdr_str=""
    local h
    for h in "${hdr_args[@]}"; do
        hdr_str+=" \\
    ${h@Q}"
    done
    case "$class" in
        oauth-redirect-bypass|open-redirect)
            printf 'curl -sS -I -A %q%s \\\n    %q\n' "$UA" "$hdr_str" "$url";;
        ssrf-metadata|ssrf)
            printf 'curl -sS -A %q%s \\\n    %q  # SSRF — monitor OAST for %q\n' "$UA" "$hdr_str" "$url" "$CALLBACK_DOMAIN";;
        graphql-introspection)
            printf 'curl -sS -A %q -H %q%s \\\n    -d %q \\\n    %q\n' \
                "$UA" "Content-Type: application/json" "$hdr_str" \
                '{"query":"query{__schema{queryType{name}}}"}' "$url";;
        *)
            printf 'curl -sS -A %q%s \\\n    %q\n' "$UA" "$hdr_str" "$url";;
    esac
}

# ============ Phase: report ============
do_report() {
    local report="reports/report_${TARGET_SAFE}_${TIMESTAMP}.md"
    local findings_jsonl="reports/findings.jsonl"
    : > "$findings_jsonl"

    # ----- Build a normalized findings.jsonl for SARIF/HTML to consume -----
    _emit() {
        local class="$1" severity="$2" url="$3" evidence="$4" payload="${5:-}"
        local cvss
        cvss=$(cvss_for_class "$class")
        local poc
        poc=$(curl_poc "$class" "$url" "$payload" 2>/dev/null || echo "")
        jq -cn \
            --arg class "$class" \
            --arg severity "$severity" \
            --arg url "$url" \
            --arg evidence "$evidence" \
            --arg payload "$payload" \
            --arg cvss "$cvss" \
            --arg poc "$poc" \
            '{class:$class, severity:$severity, url:$url, evidence:$evidence, payload:$payload, cvss:$cvss, poc:$poc}' \
            >> "$findings_jsonl"
    }

    if [ -s vulns/nuclei_all.jsonl ]; then
        jq -c '{
            class: ("nuclei-" + .info.severity),
            severity: .info.severity,
            url: (.["matched-at"] // .host),
            evidence: .info.name,
            payload: "",
            cvss: ""
        }' vulns/nuclei_all.jsonl 2>/dev/null >> "$findings_jsonl"
    fi

    if [ -s validate/xss_confirmed.tsv ]; then
        while IFS=$'\t' read -r _ url payload; do
            _emit "xss-confirmed" "high" "$url" "reflected payload marker" "$payload"
        done < validate/xss_confirmed.tsv
    fi
    if [ -s vulns/sqli/error_based.tsv ]; then
        while IFS=$'\t' read -r _ url payload; do
            _emit "sqli-error" "high" "$url" "SQL error string in response" "$payload"
        done < vulns/sqli/error_based.tsv
    fi
    if [ -s vulns/sqli/time_based.tsv ]; then
        while IFS=$'\t' read -r _ url payload dur; do
            _emit "sqli-time" "critical" "$url" "response delayed: $dur" "$payload"
        done < vulns/sqli/time_based.tsv
    fi
    if [ -s vulns/ssrf/localhost_probe.tsv ]; then
        while IFS=$'\t' read -r _ url payload; do
            _emit "ssrf-metadata" "critical" "$url" "metadata/etc-passwd pattern in response" "$payload"
        done < vulns/ssrf/localhost_probe.tsv
    fi
    if [ -s vulns/ssrf/requests_fired.tsv ]; then
        while IFS=$'\t' read -r url payload tag; do
            _emit "ssrf" "medium" "$url" "fired OAST callback tag=$tag" "$payload"
        done < vulns/ssrf/requests_fired.tsv
    fi
    if [ -s vulns/graphql/introspection.tsv ]; then
        while IFS=$'\t' read -r _ url; do
            _emit "graphql-introspection" "medium" "$url" "__schema returned full type graph" ""
        done < vulns/graphql/introspection.tsv
    fi
    if [ -s vulns/oauth/redirect_bypass.tsv ]; then
        while IFS=$'\t' read -r _ url payload location; do
            _emit "oauth-redirect-bypass" "high" "$url" "Location: $location" "$payload"
        done < vulns/oauth/redirect_bypass.tsv
    fi
    if [ -s vulns/deep/open_redirect_confirmed.txt ]; then
        while read -r url; do
            [ -z "$url" ] && continue
            _emit "open-redirect" "medium" "$url" "Location header echoed callback" ""
        done < vulns/deep/open_redirect_confirmed.txt
    fi
    if [ -s vulns/deep/lfi_confirmed.txt ]; then
        while read -r url; do
            [ -z "$url" ] && continue
            _emit "lfi-confirmed" "high" "$url" "/etc/passwd pattern in response" "../../../../../../etc/passwd"
        done < vulns/deep/lfi_confirmed.txt
    fi
    if [ -s vulns/ssti/confirmed.tsv ]; then
        while IFS=$'\t' read -r _ url payload expected; do
            _emit "ssti" "critical" "$url" "expression evaluated: $expected" "$payload"
        done < vulns/ssti/confirmed.tsv
    fi
    if [ -s vulns/nosql/candidates.tsv ]; then
        while IFS=$'\t' read -r _ url payload detail; do
            _emit "nosql" "medium" "$url" "${detail:-operator-injection divergence}" "$payload"
        done < vulns/nosql/candidates.tsv
    fi
    if [ -s validate/idor_candidates.tsv ]; then
        while IFS=$'\t' read -r _ base alt sizes; do
            _emit "idor-diff" "high" "$alt" "size diff vs base: $sizes" ""
        done < validate/idor_candidates.tsv
    fi
    if [ -s vulns/proto_pollution/candidates.tsv ]; then
        while IFS=$'\t' read -r _ url; do
            _emit "proto-pollution" "medium" "$url" "canary reflected via __proto__ injection" ""
        done < vulns/proto_pollution/candidates.tsv
    fi
    if [ -s js/highvalue_secrets.txt ]; then
        while read -r line; do
            [ -z "$line" ] && continue
            _emit "leaked-secret" "high" "js/content/" "$line" ""
        done < js/highvalue_secrets.txt
    fi
    # jsluice secrets (JSON-per-line; emit each).
    if [ -s js/jsluice_secrets.txt ]; then
        while read -r line; do
            [ -z "$line" ] && continue
            _emit "leaked-secret-jsluice" "high" "js/content/" "${line:0:200}" ""
        done < js/jsluice_secrets.txt
    fi
    # trufflehog (line-based).
    if [ -s js/trufflehog.txt ]; then
        while read -r line; do
            [ -z "$line" ] && continue
            _emit "leaked-secret-trufflehog" "high" "js/content/" "${line:0:200}" ""
        done < js/trufflehog.txt
    fi
    # Dalfox confirmed XSS (line-per-hit).
    if [ -s vulns/xss.txt ]; then
        while read -r line; do
            [ -z "$line" ] && continue
            local dfx_url
            dfx_url=$(printf '%s' "$line" | grep -oE 'https?://[^[:space:]"]+' | head -1)
            _emit "xss-dalfox" "high" "${dfx_url:-dalfox}" "${line:0:200}" ""
        done < vulns/xss.txt
    fi
    # GraphQL endpoints discovered (one URL per line). Medium: discovery is
    # itself a meaningful attack surface (introspection, auth bypass, DoS).
    if [ -s checklist/graphql_endpoints.txt ]; then
        while read -r gql_url; do
            [ -z "$gql_url" ] && continue
            _emit "graphql-endpoint" "medium" "$gql_url" "GraphQL endpoint exposed — test introspection, batching, depth/complexity, auth" ""
        done < checklist/graphql_endpoints.txt
    fi
    # Subjack vulnerable takeovers (format: "[Vulnerable:<service>] host").
    if [ -s vulns/subjack.txt ]; then
        grep -iE '^\[Vulnerable' vulns/subjack.txt 2>/dev/null | while read -r sj_line; do
            local sj_host sj_svc
            sj_host=$(printf '%s' "$sj_line" | awk '{print $NF}')
            sj_svc=$(printf '%s' "$sj_line" | grep -oE ':[^][:space:]]+' | head -1 | tr -d ':]')
            _emit "takeover" "critical" "$sj_host" "subjack:${sj_svc:-unknown}" ""
        done
    fi
    if [ -s vulns/jwt/found_tokens.tsv ]; then
        while IFS=$'\t' read -r url tok; do
            _emit "jwt-weak" "medium" "$url" "JWT observed in response: ${tok:0:40}..." ""
        done < vulns/jwt/found_tokens.tsv
    fi
    if [ -s vulns/takeovers.jsonl ]; then
        jq -r '[.host,.info.name] | @tsv' vulns/takeovers.jsonl 2>/dev/null \
            | while IFS=$'\t' read -r host name; do
                _emit "takeover" "critical" "$host" "$name" ""
            done
    fi
    if [ -s vulns/cors_manual.txt ]; then
        while read -r line; do
            [ -z "$line" ] && continue
            local cls
            case "$line" in
                NULL-ALLOWED:*)        cls="cors-null";;
                REFLECTED:*)           cls="cors-reflected";;
                SUBDOMAIN-TRUSTED:*)   cls="cors-subdomain";;
                *)                     cls="cors-reflected";;
            esac
            _emit "$cls" "medium" "${line#*: }" "$line" ""
        done < vulns/cors_manual.txt
    fi

    # ----- Basic checks: stream into findings.jsonl -----
    # Each helper emits all rows from one basic_*.txt file with one jq call.
    _emit_basic_tsv() {
        local file="$1" class="$2" severity="$3" url_col="$4" ev_col="$5"
        [ ! -s "$file" ] && return 0
        have jq || return 0
        awk -F'\t' -v OFS=$'\t' -v u="$url_col" -v e="$ev_col" '
            {
                url = (u > 0 && u <= NF) ? $u : ""
                ev  = (e > 0 && e <= NF) ? $e : $0
                gsub(/\r/, "", url); gsub(/\r/, "", ev)
                print url, ev
            }
        ' "$file" | jq -cR --arg class "$class" --arg severity "$severity" '
            split("\t") as $f | {
                class: $class, severity: $severity,
                url: $f[0], evidence: $f[1],
                payload: "", cvss: "", poc: ""
            }
        ' >> "$findings_jsonl"
    }

    # HTTP cleartext
    _emit_basic_tsv vulns/basic_http_exposure.txt            "http-cleartext"          low    2 3
    # Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
    _emit_basic_tsv vulns/basic_missing_security_headers.txt "missing-security-header" low    2 3
    # Server / X-Powered-By disclosure
    _emit_basic_tsv vulns/basic_server_disclosure.txt        "server-disclosure"       low    2 3
    # Outdated server/runtime versions — url\tdescription\traw-header
    _emit_basic_tsv vulns/basic_outdated_versions.txt        "outdated-software"       medium 1 2
    # Insecure cookies — Secure / HttpOnly / SameSite / over-HTTP
    _emit_basic_tsv vulns/basic_insecure_cookies.txt         "insecure-cookie"         low    2 3
    # Extra open ports (non 80/443)
    _emit_basic_tsv vulns/basic_extra_ports.txt              "extra-open-ports"        low    2 3
    # Legacy TLS versions (1.0 / 1.1)
    _emit_basic_tsv vulns/basic_tls_legacy.txt               "tls-legacy-protocol"     medium 2 3
    # TLS certificate CN/SAN mismatch
    _emit_basic_tsv vulns/basic_tls_name_mismatch.txt        "tls-name-mismatch"       medium 2 3
    # Missing Subresource Integrity
    _emit_basic_tsv vulns/basic_sri_missing.txt              "sri-missing"             low    2 3
    # Host-header injection (reflected in headers/body)
    _emit_basic_tsv vulns/basic_host_header_injection.txt    "host-header-injection"   medium 2 3
    # Dangerous HTTP methods / TRACE enabled
    _emit_basic_tsv vulns/basic_dangerous_methods.txt        "dangerous-http-methods"  medium 2 3
    # Directory listing exposed
    _emit_basic_tsv vulns/basic_directory_listing.txt        "directory-listing"       medium 2 3
    # Mixed content (http:// resources on https pages)
    _emit_basic_tsv vulns/basic_mixed_content.txt            "mixed-content"           low    2 3

    # Helper: emit httpx-style "<url> [<status>] [<size>]" lines as findings.
    # Severity: 200 → medium (reachable + returning content), else low.
    _emit_httpx_paths() {
        local file="$1" class="$2"
        [ ! -s "$file" ] && return 0
        have jq || return 0
        awk -v OFS=$'\t' '
            {
                url = $1
                status = $2; gsub(/[\[\]]/, "", status)
                size   = $3; gsub(/[\[\]]/, "", size)
                sev = (status == "200") ? "medium" : "low"
                print sev, url, "status=" status " size=" size
            }
        ' "$file" | jq -cR --arg class "$class" '
            split("\t") as $f | {
                class: $class, severity: $f[0],
                url: $f[1], evidence: $f[2],
                payload: "", cvss: "", poc: ""
            }
        ' >> "$findings_jsonl"
    }

    # Tech-stack classification: emit outdated / vulnerable libraries as
    # findings so they flow into HTML table, SARIF, and Discord summary.
    # Server-layer outdated entries (Apache/nginx/PHP/...) already come from
    # basic_outdated_versions.txt — don't duplicate.
    if [ -s web/tech.tsv ] && have jq; then
        while IFS=$'\t' read -r host tech_list; do
            [ -z "$host" ] && continue
            [ -z "$tech_list" ] && continue
            local IFS_OLD="$IFS"
            IFS=','
            local tech
            for tech in $tech_list; do
                tech="${tech# }"; tech="${tech% }"
                local name version status note sev cls
                name="${tech%%:*}"
                if [[ "$tech" == *:* ]]; then
                    version="${tech#*:}"
                else
                    version=""
                fi
                [ -z "$version" ] && continue
                { read -r status; read -r note; } < <(tech_classify "$name" "$version")
                case "$status" in
                    vulnerable*) sev="high"; cls="vulnerable-library" ;;
                    outdated)    sev="medium"; cls="outdated-library" ;;
                    *) continue ;;
                esac
                jq -cn --arg class "$cls" --arg severity "$sev" \
                       --arg url "$host" \
                       --arg evidence "$name $version ($note)" \
                       --arg payload "" --arg cvss "" --arg poc "" \
                       '{class:$class,severity:$severity,url:$url,evidence:$evidence,payload:$payload,cvss:$cvss,poc:$poc}' \
                    >> "$findings_jsonl"
            done
            IFS="$IFS_OLD"
        done < web/tech.tsv
    fi

    # High-value paths: intentionally NOT emitted as findings. They are recon
    # pointers (things worth manually poking), not vulns. Rendered in their
    # own dedicated section of the MD/HTML report instead of the findings table.

    # Discovered API specs (Swagger / OpenAPI) — often unauthenticated goldmines.
    _emit_httpx_paths recon/apispec/found.txt             "api-spec-exposed"
    # Interesting cloud buckets (S3 / Azure Web App / GCS).
    _emit_httpx_paths recon/cloud/buckets_interesting.txt "cloud-bucket-exposed"

    # Gitleaks secrets found in downloaded JS. Always high severity — these
    # are real secret matches, not hueristic "X-Powered-By" noise.
    if [ -s js/gitleaks.json ] && have jq; then
        jq -c '
            if type == "array" then .[] else . end
            | select(.Secret != null and .Secret != "")
            | {
                class: "leaked-secret-js",
                severity: "high",
                url: (.File // "js/content/"),
                evidence: (
                    (.Description // "secret")
                    + " rule=" + (.RuleID // "")
                    + " line=" + ((.StartLine // 0) | tostring)
                    + " match=" + ((.Match // "") | tostring | .[0:120])
                ),
                payload: "",
                cvss: "",
                poc: ""
              }
        ' js/gitleaks.json 2>/dev/null >> "$findings_jsonl"
    fi

    # testssl.sh raw findings (no tab structure). Strip ANSI color codes
    # because older runs were captured before --color 0 was added.
    if [ -s vulns/basic_tls_testssl.txt ] && have jq; then
        ansi_strip < vulns/basic_tls_testssl.txt \
          | jq -cRn --arg class "tls-ssl-finding" --arg severity "medium" '
                [inputs | select(length > 0)] | .[] | {
                    class: $class, severity: $severity,
                    url: "", evidence: .,
                    payload: "", cvss: "", poc: ""
                }
            ' >> "$findings_jsonl"
    fi

    # ----- Markdown report -----
    {
        echo "# Recon Report: $INPUT_TARGET"
        echo "**Date:** $(date)"
        echo "**Handle:** $HANDLE"
        echo "**Mode:** $([ "$SUBDOMAIN_MODE" -eq 1 ] && echo "Subdomain (-sd)" || echo "Single-target")"
        [ "$DIFF_MODE" -eq 1 ] && echo "**Diff vs:** ${PREV_RUN:-none}"
        echo
        echo "## Executive summary"
        echo
        local crit high med
        crit=$(jq -s '[.[] | select(.severity=="critical")] | length' "$findings_jsonl" 2>/dev/null || echo 0)
        high=$(jq -s '[.[] | select(.severity=="high")] | length' "$findings_jsonl" 2>/dev/null || echo 0)
        med=$(jq -s '[.[] | select(.severity=="medium")] | length' "$findings_jsonl" 2>/dev/null || echo 0)
        echo "| Severity | Count |"
        echo "|---|---|"
        echo "| Critical | $crit |"
        echo "| High     | $high |"
        echo "| Medium   | $med |"
        echo
        echo "## Top ranked findings (with PoC)"
        jq -s 'sort_by(
                    if .severity=="critical" then 0
                    elif .severity=="high"  then 1
                    elif .severity=="medium" then 2
                    elif .severity=="low"   then 3
                    else 4 end
               ) | .[0:25] | .[]' "$findings_jsonl" 2>/dev/null \
            | while read -r _; do :; done
        jq -s -r '
            sort_by(
                if .severity=="critical" then 0
                elif .severity=="high"  then 1
                elif .severity=="medium" then 2
                elif .severity=="low"   then 3
                else 4 end
            ) | .[0:25] | .[] |
            "### [\(.severity | ascii_upcase)] \(.class)\n\n- URL: `\(.url)`\n- Evidence: \(.evidence)\n- CVSS: \(.cvss)\n\nPoC:\n```bash\n\(.poc)\n```\n"
        ' "$findings_jsonl" 2>/dev/null

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
        echo

        if [ -s reports/attack_chains.md ]; then
            echo "## Attack chains"
            sed 's/^# Attack Chains//; s/^## /### /' reports/attack_chains.md
            echo
        fi

        if [ -s web/tech.tsv ]; then
            echo "## Technologies detected"
            echo
            echo "_Version-freshness check against a built-in static baseline — verify manually before reporting as a CVE hit._"
            echo
            echo "| Host | Technology | Version | Status | Note |"
            echo "|---|---|---|---|---|"
            local md_host md_list md_tech md_name md_ver md_status md_note
            while IFS=$'\t' read -r md_host md_list; do
                [ -z "$md_host" ] && continue
                [ -z "$md_list" ] && continue
                local IFS_OLD="$IFS"; IFS=','
                for md_tech in $md_list; do
                    md_tech="${md_tech# }"; md_tech="${md_tech% }"
                    md_name="${md_tech%%:*}"
                    if [[ "$md_tech" == *:* ]]; then md_ver="${md_tech#*:}"; else md_ver=""; fi
                    { read -r md_status; read -r md_note; } < <(tech_classify "$md_name" "$md_ver")
                    echo "| \`$md_host\` | $md_name | \`${md_ver:-—}\` | $md_status | $md_note |"
                done
                IFS="$IFS_OLD"
            done < web/tech.tsv
            echo
        fi

        if [ -s vulns/highvalue_paths.txt ]; then
            echo "## High-value endpoints"
            echo
            echo "_Sensitive paths that returned 200/301/302/401/403. These are recon pointers for manual triage, not vulnerabilities._"
            echo
            echo '```'
            head -500 vulns/highvalue_paths.txt
            echo '```'
            echo
        fi

        echo "## Detail sections"
        echo
        echo "### Nuclei — Critical"; echo '```'; head -20 vulns/nuclei_critical.txt 2>/dev/null; echo '```'
        echo "### Nuclei — High";     echo '```'; head -30 vulns/nuclei_high.txt 2>/dev/null;     echo '```'
        echo "### Nuclei — Medium";   echo '```'; head -30 vulns/nuclei_medium.txt 2>/dev/null;   echo '```'

        if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
            echo "### Subdomain takeovers"; echo '```'
            jq -r '[.info.name, .host] | @tsv' vulns/takeovers.jsonl 2>/dev/null
            cat vulns/subjack.txt 2>/dev/null
            echo '```'
        fi
        echo "### Detected WAF";           echo '```'; head -20  web/waf.txt 2>/dev/null;                        echo '```'
        echo "### API specs (Swagger/OpenAPI)"; echo '```'; head -100 recon/apispec/found.txt 2>/dev/null;       echo '```'
        echo "### Discovered GraphQL endpoints"; echo '```'; head -60 checklist/graphql_endpoints.txt 2>/dev/null; echo '```'
        echo "### JS-discovered FQDN endpoints"; echo '```'; head -300 js/endpoints_fqdn.txt 2>/dev/null;          echo '```'
        echo "### Gitleaks secrets (JS)";  echo '```'; jq -r '.[] | "\(.File):\(.StartLine)  \(.Description)  rule=\(.RuleID)  \(.Match[0:100])"' js/gitleaks.json 2>/dev/null | head -100; echo '```'
        echo "### XSS confirmed";          echo '```'; head -30 validate/xss_confirmed.tsv 2>/dev/null;           echo '```'
        echo "### Dalfox XSS";             echo '```'; head -30 vulns/xss.txt 2>/dev/null;                        echo '```'
        echo "### SQLi error-based";       echo '```'; head -30 vulns/sqli/error_based.tsv 2>/dev/null;           echo '```'
        echo "### SQLi time-based";        echo '```'; head -30 vulns/sqli/time_based.tsv 2>/dev/null;            echo '```'
        echo "### SSRF metadata hits";     echo '```'; head -30 vulns/ssrf/localhost_probe.tsv 2>/dev/null;       echo '```'
        echo "### SSRF fired callbacks";   echo '```'; head -30 vulns/ssrf/requests_fired.tsv 2>/dev/null;        echo '```'
        echo "### JWT tokens found";       echo '```'; head -30 vulns/jwt/found_tokens.tsv 2>/dev/null;           echo '```'
        echo "### GraphQL introspection";  echo '```'; head -30 vulns/graphql/introspection.tsv 2>/dev/null;      echo '```'
        echo "### OAuth redirect bypass";  echo '```'; head -30 vulns/oauth/redirect_bypass.tsv 2>/dev/null;      echo '```'
        echo "### SSTI confirmed";         echo '```'; head -30 vulns/ssti/confirmed.tsv 2>/dev/null;             echo '```'
        echo "### NoSQL candidates";       echo '```'; head -30 vulns/nosql/candidates.tsv 2>/dev/null;           echo '```'
        echo "### IDOR candidates";        echo '```'; head -30 validate/idor_candidates.tsv 2>/dev/null;         echo '```'
        echo "### Proto-pollution";        echo '```'; head -30 vulns/proto_pollution/candidates.tsv 2>/dev/null; echo '```'
        echo "### Leaked high-value secrets"; echo '```'; head -30 js/highvalue_secrets.txt 2>/dev/null;          echo '```'
        echo "### Cloud buckets";          echo '```'; head -30 recon/cloud/buckets_interesting.txt 2>/dev/null;  echo '```'
        echo "### CVE correlation";        echo '```'; head -30 vulns/cve/correlated.tsv 2>/dev/null;             echo '```'
        echo "### CORS";                   echo '```'; head -30 vulns/cors_manual.txt 2>/dev/null;                echo '```'

        echo
        echo "## Basic checks"
        echo "### HTTP cleartext";              echo '```'; head -30 vulns/basic_http_exposure.txt 2>/dev/null;            echo '```'
        echo "### Insecure cookies";            echo '```'; head -30 vulns/basic_insecure_cookies.txt 2>/dev/null;         echo '```'
        echo "### Missing security headers";    echo '```'; head -50 vulns/basic_missing_security_headers.txt 2>/dev/null; echo '```'
        echo "### Server/framework disclosure"; echo '```'; head -30 vulns/basic_server_disclosure.txt 2>/dev/null;        echo '```'
        echo "### Outdated version candidates"; echo '```'; head -30 vulns/basic_outdated_versions.txt 2>/dev/null;        echo '```'
        echo "### Extra open ports";            echo '```'; head -30 vulns/basic_extra_ports.txt 2>/dev/null;              echo '```'
        echo "### Legacy TLS";                  echo '```'; head -30 vulns/basic_tls_legacy.txt 2>/dev/null;               echo '```'
        echo "### TLS name mismatch";           echo '```'; head -30 vulns/basic_tls_name_mismatch.txt 2>/dev/null;        echo '```'
        echo "### TLS/SSL tool findings";       echo '```'; head -40 vulns/basic_tls_testssl.txt 2>/dev/null;              echo '```'
        echo "### Missing SRI";                 echo '```'; head -30 vulns/basic_sri_missing.txt 2>/dev/null;              echo '```'
        echo "### Host-header injection";       echo '```'; head -30 vulns/basic_host_header_injection.txt 2>/dev/null;    echo '```'
        echo "### Dangerous HTTP methods";      echo '```'; head -30 vulns/basic_dangerous_methods.txt 2>/dev/null;        echo '```'
        echo "### Directory listing";           echo '```'; head -30 vulns/basic_directory_listing.txt 2>/dev/null;        echo '```'
        echo "### Mixed content";               echo '```'; head -30 vulns/basic_mixed_content.txt 2>/dev/null;            echo '```'

        if [ "$DEEP_MODE" -eq 1 ]; then
            echo "## Deep validation"
            cat vulns/deep/summary.md 2>/dev/null
            echo "### Reflected XSS";        echo '```'; head -30 vulns/deep/reflected_xss_confirmed.txt 2>/dev/null;   echo '```'
            echo "### SQL error candidates"; echo '```'; head -30 vulns/deep/sql_error_candidates.txt 2>/dev/null;      echo '```'
            echo "### LFI confirmed";        echo '```'; head -30 vulns/deep/lfi_confirmed.txt 2>/dev/null;             echo '```'
            echo "### Open redirects";       echo '```'; head -30 vulns/deep/open_redirect_confirmed.txt 2>/dev/null;   echo '```'
        fi

        if [ "$AI_ACTIVE_MODE" -eq 1 ]; then
            echo "## AI active validation"
            cat vulns/ai_active/summary.md 2>/dev/null
        fi

        echo "## JS secrets (jsluice)"; echo '```'; head -30 js/jsluice_secrets.txt 2>/dev/null; echo '```'
        echo "## JS secrets (trufflehog)"; echo '```'; head -30 js/trufflehog.txt 2>/dev/null; echo '```'
        echo "## JS secrets (gitleaks)"; echo '```'; jq -r '.[] | "\(.File):\(.StartLine)  \(.Description)  rule=\(.RuleID)  \((.Match // "") | .[0:100])"' js/gitleaks.json 2>/dev/null | head -100; echo '```'
        echo "## Cloud buckets (detail)"; echo '```'; head -50 recon/cloud/buckets_interesting.txt 2>/dev/null; echo '```'

        if [ "$DIFF_MODE" -eq 1 ] && [ -n "$PREV_RUN" ]; then
            echo
            echo "## 🔥 NEW since last run"
            echo "### New subdomains";     echo '```'; head -30 diffs/new_subdomains_all.txt 2>/dev/null;    echo '```'
            echo "### New findings";       echo '```'; head -30 diffs/new_nuclei_findings.txt 2>/dev/null;   echo '```'
            echo "### New basic checks";   echo '```'; head -30 diffs/new_vulns_basic_checks.txt 2>/dev/null; echo '```'
            echo "### New AI active";      echo '```'; head -30 diffs/new_vulns_ai_active_confirmed.txt 2>/dev/null; echo '```'
            echo "### New XSS confirmed";  echo '```'; head -30 diffs/new_validate_xss_confirmed.tsv 2>/dev/null;    echo '```'
            echo "### New SQLi";           echo '```'; head -30 diffs/new_vulns_sqli_error_based.tsv 2>/dev/null;    echo '```'
        fi
    } > "$report"

    # ----- SARIF (tools reading CI artifacts) -----
    render_sarif
    # ----- HTML (standalone, single file) -----
    render_html

    cat > checklist/MANUAL_CHECKLIST.md <<EOF
# Manual Hunting Checklist — $TARGET

This checklist is generated so you can walk through the highest-signal
manual checks Paintest cannot automate safely.

## Reports
- [ ] Review \`reports/report_${TARGET_SAFE}_${TIMESTAMP}.md\`
- [ ] Review \`reports/attack_chains.md\`

## Vulnerable & outdated components (OWASP A06:2021)
- [ ] Review \`vulns/basic_outdated_versions.txt\` — confirm each flagged Apache / nginx / PHP / OpenSSL / IIS / Tomcat version against its vendor CHANGELOG and published CVEs
- [ ] Cross-check \`vulns/cve/correlated.tsv\` against vendor advisories and NVD
- [ ] Pull detected stack from \`web/tech.tsv\` and search each component+version in CVE feeds (plugins/themes especially)
- [ ] For WordPress targets, enumerate plugins via \`/wp-json/wp/v2/plugins\` or plugin-slug guessing, then cross-reference WPScan CVE database
- [ ] Review \`vulns/nuclei_critical.txt\` and \`vulns/nuclei_high.txt\` — validate each hit isn't a false positive

## High-value recon to act on
- [ ] Review **High-value endpoints** section of the HTML report — each path is a sensitive route that was reachable
- [ ] Triage \`vulns/highvalue_paths.txt\` status codes: test 200s for content leakage, test 401/403 for auth-bypass tricks (TRACE, method-override headers, verb tampering)
- [ ] Parse \`recon/apispec/found.txt\` — download any 200-status Swagger/OpenAPI doc and use it to enumerate undocumented routes
- [ ] Inspect cloud buckets in \`recon/cloud/buckets_interesting.txt\` for public listing, signed-URL leaks, or write access

## Injection / logic
- [ ] Check OAST logs for \`*.${CALLBACK_DOMAIN}\` DNS/HTTP hits (SSRF)
- [ ] Manually exploit confirmed XSS payloads: \`validate/xss_confirmed.tsv\`
- [ ] Verify SQLi with sqlmap (requires SQLMAP_RISK=1 re-run): \`vulns/sqli/\`
- [ ] Validate IDOR candidates against a low-privileged account
- [ ] Validate OAuth redirect_uri bypasses manually
- [ ] Test GraphQL mutations that touch auth from introspection dump
- [ ] Try JWT attacks with \`jwt_tool\` on discovered tokens

## Secrets & leakage
- [ ] Review \`js/gitleaks.json\` — validate each matched secret against the live service before reporting
- [ ] Chase secrets from \`js/highvalue_secrets.txt\` against discovered APIs
- [ ] Check \`recon/github/\` for leaked secrets in external repos
EOF

    log "Report: $report"
    log "SARIF:  reports/findings.sarif"
    log "HTML:   reports/report_${TARGET_SAFE}_${TIMESTAMP}.html"

    notify_scan_summary "$findings_jsonl" "$report"
    return 0
}

# ============ Final webhook summary ============
# Posts a compact scan summary to WEBHOOK_URL (Discord/Slack/Telegram).
# Kept well under Discord's 2000-char limit.
notify_scan_summary() {
    [ -z "${WEBHOOK_URL:-}" ] && return 0
    local findings_jsonl="$1" report_path="$2"

    local crit=0 high=0 med=0 low=0 total=0
    if [ -s "$findings_jsonl" ] && have jq; then
        crit=$(jq -s '[.[] | select(.severity=="critical")] | length' "$findings_jsonl" 2>/dev/null || echo 0)
        high=$(jq -s '[.[] | select(.severity=="high")]     | length' "$findings_jsonl" 2>/dev/null || echo 0)
        med=$(jq  -s '[.[] | select(.severity=="medium")]   | length' "$findings_jsonl" 2>/dev/null || echo 0)
        low=$(jq  -s '[.[] | select(.severity=="low")]      | length' "$findings_jsonl" 2>/dev/null || echo 0)
        total=$(wc -l < "$findings_jsonl" 2>/dev/null || echo 0)
    fi

    local top=""
    if [ -s "$findings_jsonl" ] && have jq; then
        top=$(jq -s -r '
            sort_by(
                if .severity=="critical" then 0
                elif .severity=="high"   then 1
                elif .severity=="medium" then 2
                elif .severity=="low"    then 3
                else 4 end
            ) | .[0:8] | .[] |
            "• [\(.severity | ascii_upcase)] \(.class) — \(.url)"
        ' "$findings_jsonl" 2>/dev/null | cut -c1-180)
    fi

    local subs live urls
    subs=$(safe_wcl subdomains/all.txt)
    live=$(safe_wcl web/live.txt)
    urls=$(safe_wcl web/all_urls.txt)

    local mode_label
    mode_label=$([ "$SUBDOMAIN_MODE" -eq 1 ] && echo "subdomain" || echo "single")

    # ----- Basic-check category counts (line count per file) -----
    local bc_http      bc_hdrs     bc_srv      bc_outdated bc_cookies
    local bc_ports     bc_tls_leg  bc_tls_mm   bc_tls_ssl  bc_sri
    local bc_hhi       bc_methods  bc_dirlist  bc_mixed
    bc_http=$(safe_wcl     vulns/basic_http_exposure.txt)
    bc_hdrs=$(safe_wcl     vulns/basic_missing_security_headers.txt)
    bc_srv=$(safe_wcl      vulns/basic_server_disclosure.txt)
    bc_outdated=$(safe_wcl vulns/basic_outdated_versions.txt)
    bc_cookies=$(safe_wcl  vulns/basic_insecure_cookies.txt)
    bc_ports=$(safe_wcl    vulns/basic_extra_ports.txt)
    bc_tls_leg=$(safe_wcl  vulns/basic_tls_legacy.txt)
    bc_tls_mm=$(safe_wcl   vulns/basic_tls_name_mismatch.txt)
    bc_tls_ssl=$(safe_wcl  vulns/basic_tls_testssl.txt)
    bc_sri=$(safe_wcl      vulns/basic_sri_missing.txt)
    bc_hhi=$(safe_wcl      vulns/basic_host_header_injection.txt)
    bc_methods=$(safe_wcl  vulns/basic_dangerous_methods.txt)
    bc_dirlist=$(safe_wcl  vulns/basic_directory_listing.txt)
    bc_mixed=$(safe_wcl    vulns/basic_mixed_content.txt)
    local bc_total
    bc_total=$(safe_wcl    vulns/basic_checks.txt)

    local msg
    msg=$(printf '✅ Paintest scan complete — %s (%s)\n' "$INPUT_TARGET" "$mode_label")
    msg+=$(printf '\nFindings: %s total  |  🔴 crit %s  🟠 high %s  🟡 med %s  ⚪ low %s' \
        "$total" "$crit" "$high" "$med" "$low")
    msg+=$(printf '\nRecon: %s subs • %s live • %s urls' "$subs" "$live" "$urls")

    if [ "${bc_total:-0}" -gt 0 ] 2>/dev/null; then
        msg+=$'\n\nBasic checks ('"$bc_total"' total):'
        [ "$bc_http"      -gt 0 ] 2>/dev/null && msg+=$'\n• HTTP cleartext: '"$bc_http"
        [ "$bc_tls_leg"   -gt 0 ] 2>/dev/null && msg+=$'\n• Legacy TLS (1.0/1.1): '"$bc_tls_leg"
        [ "$bc_tls_mm"    -gt 0 ] 2>/dev/null && msg+=$'\n• TLS cert name mismatch: '"$bc_tls_mm"
        [ "$bc_tls_ssl"   -gt 0 ] 2>/dev/null && msg+=$'\n• TLS/SSL testssl findings: '"$bc_tls_ssl"
        [ "$bc_hdrs"      -gt 0 ] 2>/dev/null && msg+=$'\n• Missing security headers: '"$bc_hdrs"
        [ "$bc_srv"       -gt 0 ] 2>/dev/null && msg+=$'\n• Server/framework disclosure: '"$bc_srv"
        [ "$bc_outdated"  -gt 0 ] 2>/dev/null && msg+=$'\n• Outdated versions: '"$bc_outdated"
        [ "$bc_cookies"   -gt 0 ] 2>/dev/null && msg+=$'\n• Insecure cookies: '"$bc_cookies"
        [ "$bc_ports"     -gt 0 ] 2>/dev/null && msg+=$'\n• Extra open ports: '"$bc_ports"
        [ "$bc_sri"       -gt 0 ] 2>/dev/null && msg+=$'\n• Missing SRI: '"$bc_sri"
        [ "$bc_hhi"       -gt 0 ] 2>/dev/null && msg+=$'\n• Host-header injection: '"$bc_hhi"
        [ "$bc_methods"   -gt 0 ] 2>/dev/null && msg+=$'\n• Dangerous HTTP methods: '"$bc_methods"
        [ "$bc_dirlist"   -gt 0 ] 2>/dev/null && msg+=$'\n• Directory listing: '"$bc_dirlist"
        [ "$bc_mixed"     -gt 0 ] 2>/dev/null && msg+=$'\n• Mixed content: '"$bc_mixed"
    fi

    if [ -n "$top" ]; then
        msg+=$'\n\nTop findings:\n'
        msg+="$top"
    fi
    msg+=$(printf '\n\nReport: %s' "$report_path")

    msg=${msg:0:1800}
    notify "$msg"
}

# ============ SARIF 2.1.0 renderer ============
render_sarif() {
    local sarif="reports/findings.sarif"
    [ ! -s reports/findings.jsonl ] && { printf '{"version":"2.1.0","runs":[]}\n' > "$sarif"; return 0; }

    jq -s '{
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: "paintest", version: "v6", informationUri: "https://github.com/your/paintest" } },
        results: [ .[] | {
            ruleId: .class,
            level: (
                if .severity=="critical" then "error"
                elif .severity=="high" then "error"
                elif .severity=="medium" then "warning"
                elif .severity=="low" then "note"
                else "note" end),
            message: { text: (.evidence + (if .payload != "" then " | payload=" + .payload else "" end)) },
            locations: [{
                physicalLocation: {
                    artifactLocation: { uri: .url }
                }
            }],
            properties: { cvss: .cvss, poc: .poc }
        }]
      }]
    }' reports/findings.jsonl > "$sarif" 2>/dev/null
}

# ============ Standalone HTML renderer ============
render_html() {
    local html="reports/report_${TARGET_SAFE}_${TIMESTAMP}.html"
    local json_inline
    json_inline=$(jq -s '.' reports/findings.jsonl 2>/dev/null || echo '[]')

    # HTML-escape helper for embedding raw tool output.
    # Also strips ANSI color codes that leak in from tools like testssl.sh.
    html_escape() {
        ansi_strip | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
    }

    # Collapsible section from a file. Skips when file is empty.
    # Usage: html_section <title> <file> [maxlines]
    html_section() {
        local title="$1" file="$2" maxlines="${3:-200}" count
        [ ! -s "$file" ] && return 0
        count=$(safe_wcl "$file")
        printf '<details><summary>%s <span class="muted">(%s)</span></summary>\n<pre>' \
            "$title" "$count"
        head -n "$maxlines" "$file" | html_escape
        printf '</pre></details>\n'
    }

    # Severity counts for executive summary.
    local h_crit h_high h_med h_low h_total
    h_crit=$(jq -s  '[.[] | select(.severity=="critical")] | length' reports/findings.jsonl 2>/dev/null || echo 0)
    h_high=$(jq -s  '[.[] | select(.severity=="high")]     | length' reports/findings.jsonl 2>/dev/null || echo 0)
    h_med=$(jq -s   '[.[] | select(.severity=="medium")]   | length' reports/findings.jsonl 2>/dev/null || echo 0)
    h_low=$(jq -s   '[.[] | select(.severity=="low")]      | length' reports/findings.jsonl 2>/dev/null || echo 0)
    h_total=$(safe_wcl reports/findings.jsonl)

    # Recon stats.
    local s_subs s_live s_dedup s_urls s_js s_gql s_api s_basic s_apispec s_buckets s_highv
    s_subs=$(safe_wcl  subdomains/all.txt)
    s_live=$(safe_wcl  web/live.txt)
    s_dedup=$(safe_wcl web/live_dedup.txt)
    s_urls=$(safe_wcl  web/all_urls.txt)
    s_js=$(safe_wcl    js/js_urls.txt)
    s_gql=$(safe_wcl   checklist/graphql_endpoints.txt)
    s_api=$(safe_wcl   checklist/api_endpoints.txt)
    s_basic=$(safe_wcl vulns/basic_checks.txt)
    s_apispec=$(safe_wcl  recon/apispec/found.txt)
    s_buckets=$(safe_wcl  recon/cloud/buckets_interesting.txt)
    s_highv=$(safe_wcl    vulns/highvalue_paths.txt)

    # Detected WAF — last whitespace token per line is the identified WAF
    # (the file is variable-width, not tab-delimited).
    local h_waf
    h_waf=$(awk 'NF>0 {print $NF}' web/waf.txt 2>/dev/null \
            | sort -u | grep -v '^$' | paste -sd, - 2>/dev/null)
    [ -z "$h_waf" ] && h_waf="(none detected)"

    local mode_label="Single-target"
    [ "$SUBDOMAIN_MODE" -eq 1 ] && mode_label="Subdomain (-sd)"

    cat > "$html" <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Paintest report — ${INPUT_TARGET}</title>
<meta name="color-scheme" content="only light">
<style>
:root { color-scheme: only light; --bg:#ffffff; --fg:#1a1a1a; --fg-muted:#555; --border:#d0d0d0; --surface:#f4f5f7; --surface-alt:#eef0f3; --accent:#0b63c4; --accent-hover:#084a94; }
html, body { background: var(--bg) !important; color: var(--fg) !important; }
body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; margin: 2em; max-width: 1400px; }
h1 { margin-bottom: 0; color: var(--fg); }
h2 { border-bottom: 2px solid var(--border); padding-bottom: 4px; margin-top: 2em; color: var(--fg); }
h3 { margin-top: 1.2em; color: var(--fg); }
a { color: var(--accent); }
a:hover { color: var(--accent-hover); }
.sub { color: var(--fg-muted); margin-top: .2em; }
.muted { color: var(--fg-muted); font-weight: normal; font-size: 90%; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; background: var(--bg); color: var(--fg); }
th, td { border: 1px solid var(--border); padding: 6px 10px; text-align: left; vertical-align: top; color: var(--fg); }
th { background: var(--surface); font-weight: 600; }
tbody tr:nth-child(even) { background: #fafbfc; }
tbody tr:hover { background: #eef6ff; }
/* Severity tint — colored LEFT BORDER instead of full row bg, so text contrast stays strong on any background. */
.sev-critical, .sev-critical td:first-child { border-left: 4px solid #c0392b !important; background: #fff4f3; }
.sev-high,     .sev-high     td:first-child { border-left: 4px solid #e67e22 !important; background: #fff7ee; }
.sev-medium,   .sev-medium   td:first-child { border-left: 4px solid #d4ac0d !important; background: #fffdf0; }
.sev-low,      .sev-low      td:first-child { border-left: 4px solid #27ae60 !important; background: #f2faf5; }
.sev-info,     .sev-info     td:first-child { border-left: 4px solid #95a5a6 !important; background: #f6f7f9; }
.sev-critical td, .sev-high td, .sev-medium td, .sev-low td, .sev-info td { color: var(--fg) !important; }
.summary-table td.num { text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }
.stats { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px,1fr)); gap: 8px; margin: 1em 0; }
.stats div { padding: 8px 12px; background: var(--surface); border-left: 3px solid #aab; border-radius: 3px; color: var(--fg); display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.stats strong { font-variant-numeric: tabular-nums; white-space: nowrap; }
code, pre { font: 12px/1.45 "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace; background: var(--surface-alt); color: var(--fg); padding: 2px 5px; border-radius: 3px; }
pre { padding: 10px; overflow: auto; border-radius: 6px; white-space: pre-wrap; word-break: break-word; max-height: 520px; border: 1px solid var(--border); }
.filter { margin: 1em 0; }
.filter input, .filter select { padding: 5px 10px; font: inherit; background: var(--bg); color: var(--fg); border: 1px solid var(--border); border-radius: 4px; }
details { margin-bottom: .5em; border: 1px solid var(--border); border-radius: 5px; padding: 0 10px; background: var(--bg); }
details[open] { padding-bottom: 6px; }
summary { cursor: pointer; font-weight: 600; padding: 8px 0; color: var(--fg); }
summary:hover { color: var(--accent); }
nav.toc { background: var(--surface); padding: 12px 18px; border-radius: 6px; margin: 1em 0; border: 1px solid var(--border); }
nav.toc a { margin-right: 14px; text-decoration: none; color: var(--accent); font-weight: 500; }
nav.toc a:hover { text-decoration: underline; }
.meta { color: var(--fg-muted); font-size: 90%; margin: .4em 0 .8em; }
/* Prevent browsers from forcibly dark-inverting our palette. */
@media (prefers-color-scheme: dark) {
  html, body { background: #ffffff !important; color: #1a1a1a !important; }
}
</style>
</head>
<body>
<h1>Paintest report</h1>
<div class="sub">
  Target: <code>${INPUT_TARGET}</code>
  · Handle: <code>${HANDLE}</code>
  · Mode: ${mode_label}
  · Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
</div>

<nav class="toc">
  <a href="#summary">Summary</a>
  <a href="#stats">Stats</a>
  <a href="#tech">Technologies</a>
  <a href="#chains">Chains</a>
  <a href="#findings">Findings</a>
  <a href="#highvalue">High-value endpoints</a>
  <a href="#details">Details</a>
  <a href="#basic">Basic checks</a>
  <a href="#deep">Deep</a>
  <a href="#ai">AI</a>
  <a href="#js">JS secrets</a>
  <a href="#diff">Diff</a>
</nav>

<h2 id="summary">Executive summary</h2>
<table class="summary-table">
  <thead><tr><th>Severity</th><th>Count</th></tr></thead>
  <tbody>
    <tr class="sev-critical"><td>Critical</td><td class="num">${h_crit}</td></tr>
    <tr class="sev-high"><td>High</td><td class="num">${h_high}</td></tr>
    <tr class="sev-medium"><td>Medium</td><td class="num">${h_med}</td></tr>
    <tr class="sev-low"><td>Low</td><td class="num">${h_low}</td></tr>
    <tr><td><strong>Total</strong></td><td class="num"><strong>${h_total}</strong></td></tr>
  </tbody>
</table>

<h2 id="stats">Recon stats</h2>
<div class="stats">
  <div>Subdomains <strong>${s_subs}</strong></div>
  <div>Live hosts <strong>${s_live}</strong></div>
  <div>Unique-content hosts <strong>${s_dedup}</strong></div>
  <div>URLs (normalized) <strong>${s_urls}</strong></div>
  <div>JS files <strong>${s_js}</strong></div>
  <div>GraphQL endpoints <strong>${s_gql}</strong></div>
  <div>API endpoints <strong>${s_api}</strong></div>
  <div>API specs (Swagger/OpenAPI) <strong>${s_apispec}</strong></div>
  <div>Interesting cloud buckets <strong>${s_buckets}</strong></div>
  <div>High-value paths <strong>${s_highv}</strong></div>
  <div>Basic-check findings <strong>${s_basic}</strong></div>
</div>

<h3>Environment</h3>
<div class="stats">
  <div>WAF <strong>${h_waf}</strong></div>
</div>
HTML

    # ----- Technologies detected (dedicated section) -----
    if [ -s web/tech.tsv ]; then
        {
            printf '<h2 id="tech">Technologies detected</h2>\n'
            printf '<div class="meta">App-layer stack per live host, with version-freshness check against a built-in static baseline (drifts over time — treat as a manual-verification pointer).</div>\n'
            printf '<table class="tech-table">\n'
            printf '  <thead><tr><th>Host</th><th>Technology</th><th>Version</th><th>Status</th><th>Note</th></tr></thead>\n'
            printf '  <tbody>\n'
            local host tech_list tech name version status note row_cls
            while IFS=$'\t' read -r host tech_list; do
                [ -z "$host" ] && continue
                [ -z "$tech_list" ] && continue
                local IFS_OLD="$IFS"; IFS=','
                for tech in $tech_list; do
                    tech="${tech# }"; tech="${tech% }"
                    name="${tech%%:*}"
                    if [[ "$tech" == *:* ]]; then version="${tech#*:}"; else version=""; fi
                    { read -r status; read -r note; } < <(tech_classify "$name" "$version")
                    case "$status" in
                        vulnerable*) row_cls="sev-high" ;;
                        outdated)    row_cls="sev-medium" ;;
                        up-to-date)  row_cls="sev-low" ;;
                        *)           row_cls="sev-info" ;;
                    esac
                    printf '    <tr class="%s"><td><code>%s</code></td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>\n' \
                        "$row_cls" \
                        "$(printf '%s' "$host" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g')" \
                        "$(printf '%s' "$name" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g')" \
                        "${version:-—}" \
                        "$status" \
                        "$(printf '%s' "$note" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g')"
                done
                IFS="$IFS_OLD"
            done < web/tech.tsv
            printf '  </tbody>\n</table>\n'
        } >> "$html"
    fi

    # ----- Attack chains -----
    if [ -s reports/attack_chains.md ]; then
        {
            printf '<h2 id="chains">Attack chains</h2>\n<pre>'
            html_escape < reports/attack_chains.md
            printf '</pre>\n'
        } >> "$html"
    fi

    # ----- Interactive findings table (existing) -----
    cat >> "$html" <<HTML
<h2 id="findings">Interactive findings</h2>
<div class="meta">All findings from <code>reports/findings.jsonl</code> — use the filter below to search by URL, class, or evidence.</div>
<div class="filter">
  <input id="q" placeholder="filter (regex)" size="30" />
  <select id="sev">
    <option value="">all severities</option>
    <option value="critical">critical</option>
    <option value="high">high</option>
    <option value="medium">medium</option>
    <option value="low">low</option>
  </select>
</div>
<table id="tbl">
  <thead><tr><th>Sev</th><th>Class</th><th>URL</th><th>Evidence</th><th>CVSS</th><th>PoC</th></tr></thead>
  <tbody></tbody>
</table>
HTML

    # ----- High-value endpoints (own top-level section) -----
    # Not emitted as findings (they're recon pointers, not vulns), so they get
    # a dedicated section here so the analyst sees them at a glance.
    if [ -s vulns/highvalue_paths.txt ]; then
        {
            printf '<h2 id="highvalue">High-value endpoints</h2>\n'
            printf '<div class="meta">Sensitive paths (admin panels, API bases, dotfiles, backups) that returned 200/301/302/401/403. Not counted as vulnerabilities — each one is a manual-triage pointer.</div>\n'
            printf '<pre>'
            head -500 vulns/highvalue_paths.txt | html_escape
            printf '</pre>\n'
        } >> "$html"
    fi

    # ----- Detail sections (raw tool output, collapsible) -----
    {
        printf '<h2 id="details">Detail sections</h2>\n'

        html_section "Nuclei — Critical"          vulns/nuclei_critical.txt                 50
        html_section "Nuclei — High"              vulns/nuclei_high.txt                     50
        html_section "Nuclei — Medium"            vulns/nuclei_medium.txt                   50

        if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
            html_section "Subjack takeovers"      vulns/subjack.txt                         60
        fi

        html_section "API specs (Swagger/OpenAPI)" recon/apispec/found.txt                 200
        html_section "Detected WAF"               web/waf.txt                              100
        html_section "Discovered GraphQL endpoints" checklist/graphql_endpoints.txt         60
        html_section "JS-discovered FQDN endpoints" js/endpoints_fqdn.txt                  300
        html_section "XSS confirmed"              validate/xss_confirmed.tsv                60
        html_section "Dalfox XSS"                 vulns/xss.txt                             60
        html_section "SQLi error-based"           vulns/sqli/error_based.tsv                60
        html_section "SQLi time-based"            vulns/sqli/time_based.tsv                 60
        html_section "SSRF metadata hits"         vulns/ssrf/localhost_probe.tsv            60
        html_section "SSRF fired callbacks"       vulns/ssrf/requests_fired.tsv             60
        html_section "JWT tokens found"           vulns/jwt/found_tokens.tsv                60
        html_section "GraphQL introspection"      vulns/graphql/introspection.tsv           60
        html_section "OAuth redirect bypass"      vulns/oauth/redirect_bypass.tsv           60
        html_section "SSTI confirmed"             vulns/ssti/confirmed.tsv                  60
        html_section "NoSQL candidates"           vulns/nosql/candidates.tsv                60
        html_section "IDOR candidates"            validate/idor_candidates.tsv              60
        html_section "Proto-pollution"            vulns/proto_pollution/candidates.tsv      60
        html_section "Leaked high-value secrets"  js/highvalue_secrets.txt                  60
        html_section "Cloud buckets"              recon/cloud/buckets_interesting.txt       60
        html_section "CVE correlation"            vulns/cve/correlated.tsv                  60
        html_section "CORS"                       vulns/cors_manual.txt                     60

        printf '<h2 id="basic">Basic checks</h2>\n'
        html_section "HTTP cleartext"             vulns/basic_http_exposure.txt             60
        html_section "Insecure cookies"           vulns/basic_insecure_cookies.txt          60
        html_section "Missing security headers"   vulns/basic_missing_security_headers.txt 100
        html_section "Server/framework disclosure" vulns/basic_server_disclosure.txt        60
        html_section "Outdated version candidates" vulns/basic_outdated_versions.txt        60
        html_section "Extra open ports"           vulns/basic_extra_ports.txt               60
        html_section "Legacy TLS"                 vulns/basic_tls_legacy.txt                60
        html_section "TLS name mismatch"          vulns/basic_tls_name_mismatch.txt         60
        html_section "TLS/SSL tool findings"      vulns/basic_tls_testssl.txt               80
        html_section "Missing SRI"                vulns/basic_sri_missing.txt               60
        html_section "Host-header injection"      vulns/basic_host_header_injection.txt     60
        html_section "Dangerous HTTP methods"     vulns/basic_dangerous_methods.txt         60
        html_section "Directory listing"          vulns/basic_directory_listing.txt         60
        html_section "Mixed content"              vulns/basic_mixed_content.txt             60

        if [ "$DEEP_MODE" -eq 1 ]; then
            printf '<h2 id="deep">Deep validation</h2>\n'
            if [ -s vulns/deep/summary.md ]; then
                printf '<pre>'; html_escape < vulns/deep/summary.md; printf '</pre>\n'
            fi
            html_section "Reflected XSS"          vulns/deep/reflected_xss_confirmed.txt    60
            html_section "SQL error candidates"   vulns/deep/sql_error_candidates.txt       60
            html_section "LFI confirmed"          vulns/deep/lfi_confirmed.txt              60
            html_section "Open redirects"         vulns/deep/open_redirect_confirmed.txt    60
        fi

        if [ "$AI_ACTIVE_MODE" -eq 1 ]; then
            printf '<h2 id="ai">AI active validation</h2>\n'
            if [ -s vulns/ai_active/summary.md ]; then
                printf '<pre>'; html_escape < vulns/ai_active/summary.md; printf '</pre>\n'
            fi
        fi

        printf '<h2 id="js">JS secrets</h2>\n'
        html_section "jsluice"    js/jsluice_secrets.txt 60
        html_section "trufflehog" js/trufflehog.txt      60

        # Gitleaks is JSON — render as a flattened list.
        if [ -s js/gitleaks.json ] && have jq; then
            local gl_count
            gl_count=$(jq 'if type=="array" then length else 1 end' js/gitleaks.json 2>/dev/null || echo 0)
            if [ "${gl_count:-0}" -gt 0 ] 2>/dev/null; then
                printf '<details open><summary>gitleaks <span class="muted">(%s)</span></summary>\n<pre>' "$gl_count"
                jq -r '
                    (if type=="array" then .[] else . end)
                    | "\(.File // ""):\(.StartLine // 0)  \(.Description // "secret")  rule=\(.RuleID // "")  \((.Match // "") | tostring | .[0:120])"
                ' js/gitleaks.json 2>/dev/null | html_escape
                printf '</pre></details>\n'
            fi
        fi

        if [ "$DIFF_MODE" -eq 1 ] && [ -n "${PREV_RUN:-}" ]; then
            printf '<h2 id="diff">NEW since last run</h2>\n'
            html_section "New subdomains"      diffs/new_subdomains_all.txt              60
            html_section "New findings"        diffs/new_nuclei_findings.txt             60
            html_section "New basic checks"    diffs/new_vulns_basic_checks.txt          60
            html_section "New AI active"       diffs/new_vulns_ai_active_confirmed.txt   60
            html_section "New XSS confirmed"   diffs/new_validate_xss_confirmed.tsv      60
            html_section "New SQLi"            diffs/new_vulns_sqli_error_based.tsv      60
        fi
    } >> "$html"

    # ----- Findings-table JS + footer -----
    cat >> "$html" <<HTML

<script>
const findings = ${json_inline};
const tbody = document.querySelector("#tbl tbody");
function render() {
  const q = new RegExp(document.getElementById("q").value || ".", "i");
  const s = document.getElementById("sev").value;
  tbody.innerHTML = "";
  findings
    .filter(f => (!s || f.severity===s) && (q.test(f.url) || q.test(f.class) || q.test(f.evidence||"")))
    .sort((a,b) => ["critical","high","medium","low","info",""].indexOf(a.severity) - ["critical","high","medium","low","info",""].indexOf(b.severity))
    .forEach(f => {
       const tr = document.createElement("tr");
       tr.className = "sev-" + (f.severity||"info");
       tr.innerHTML =
         "<td>"+(f.severity||"")+"</td>" +
         "<td><code>"+f.class+"</code></td>" +
         "<td><code>"+(f.url||"")+"</code></td>" +
         "<td>"+(f.evidence||"").replace(/</g,"&lt;")+"</td>" +
         "<td>"+(f.cvss||"")+"</td>" +
         "<td><details><summary>copy</summary><pre>"+(f.poc||"").replace(/</g,"&lt;")+"</pre></details></td>";
       tbody.appendChild(tr);
    });
}
document.getElementById("q").addEventListener("input", render);
document.getElementById("sev").addEventListener("change", render);
render();
</script>
</body>
</html>
HTML
}
