# shellcheck shell=bash
# Paintest — reporting: Markdown, SARIF, HTML, CVSS-ish scoring, PoC snippets.

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
        echo "### High-value paths";       echo '```'; head -30 vulns/highvalue_paths.txt 2>/dev/null;           echo '```'
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

- [ ] Review \`reports/report_${TARGET_SAFE}_${TIMESTAMP}.md\`
- [ ] Review \`reports/attack_chains.md\`
- [ ] Check OAST logs for \`*.${CALLBACK_DOMAIN}\` DNS/HTTP hits (SSRF)
- [ ] Manually exploit confirmed XSS payloads: \`validate/xss_confirmed.tsv\`
- [ ] Verify SQLi with sqlmap (requires SQLMAP_RISK=1 re-run): \`vulns/sqli/\`
- [ ] Validate IDOR candidates against a low-privileged account
- [ ] Validate OAuth redirect_uri bypasses manually
- [ ] Test GraphQL mutations that touch auth from introspection dump
- [ ] Try JWT attacks with \`jwt_tool\` on discovered tokens
- [ ] Chase secrets from \`js/highvalue_secrets.txt\` against discovered APIs
- [ ] Check \`recon/github/\` for leaked secrets in external repos
- [ ] Inspect cloud buckets in \`recon/cloud/\` for public listing
- [ ] Cross-check \`vulns/cve/correlated.tsv\` against vendor advisories
EOF

    log "Report: $report"
    log "SARIF:  reports/findings.sarif"
    log "HTML:   reports/report_${TARGET_SAFE}_${TIMESTAMP}.html"
    return 0
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

    cat > "$html" <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Paintest report — ${INPUT_TARGET}</title>
<style>
body { font: 14px/1.45 -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; margin: 2em; color: #222; }
h1 { margin-bottom: 0 }
.sub { color: #666; margin-top: .2em }
table { border-collapse: collapse; width: 100%; margin: 1em 0 }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; vertical-align: top }
th { background: #f6f6f6; cursor: pointer }
tr:hover { background: #fafafa }
.sev-critical { background: #ffdddd }
.sev-high     { background: #ffe6c2 }
.sev-medium   { background: #fff8c2 }
.sev-low      { background: #e6f7e6 }
.sev-info     { background: #f0f0f0 }
code, pre { font: 12px/1.4 "JetBrains Mono", "SF Mono", Menlo, monospace; background: #f4f4f4; padding: 2px 4px; border-radius: 3px }
pre { padding: 8px; overflow: auto; border-radius: 6px }
.filter { margin: 1em 0 }
.filter input, .filter select { padding: 4px 8px; font: inherit }
details { margin-bottom: .5em }
summary { cursor: pointer; font-weight: 600 }
</style>
</head>
<body>
<h1>Paintest report</h1>
<div class="sub">Target: <code>${INPUT_TARGET}</code> · Handle: <code>${HANDLE}</code> · Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)</div>

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
