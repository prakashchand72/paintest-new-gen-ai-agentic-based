# shellcheck shell=bash
# Paintest — validation / confirmation phases.
# Reduce false positives, confirm real impact, and stitch findings into
# attack chains.

# ============ Phase: xss_validate (NEW) ============
# Response-diff XSS confirmation: body must reflect the payload unescaped AND
# a control payload must NOT match. Guards against template-only matches.
do_xss_validate() {
    [ ! -s web/all_urls.txt ] && return 0
    have qsreplace || return 0
    mkdir -p validate
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    : > validate/xss_confirmed.tsv
    local marker="paintestxss${RANDOM}"
    local control="paintestctl${RANDOM}"
    local payload="\"><svg/onload=${marker}>"

    local target_set
    if [ -s params/xss.txt ]; then
        target_set=$(head -200 params/xss.txt)
    else
        target_set=$(grep '=' web/all_urls.txt | head -150)
    fi

    log "XSS response-diff validation"
    while read -r url; do
        [ -z "$url" ] && continue
        local test_url ctl_url body_t body_c
        test_url=$(printf '%s' "$url" | qsreplace "$payload")
        ctl_url=$(printf '%s' "$url"  | qsreplace "$control")
        body_t=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$test_url" 2>/dev/null)
        body_c=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$ctl_url" 2>/dev/null)
        # marker present in test only AND raw payload echoed → strong signal
        if printf '%s' "$body_t" | grep -Fq "$marker" \
           && ! printf '%s' "$body_c" | grep -Fq "$marker" \
           && printf '%s' "$body_t" | grep -Fq "onload=${marker}"; then
            printf 'XSS-CONFIRMED\t%s\t%s\n' "$test_url" "$payload" >> validate/xss_confirmed.tsv
        fi
    done <<< "$target_set"
    sort -u -o validate/xss_confirmed.tsv validate/xss_confirmed.tsv 2>/dev/null || true
    log "XSS confirmed: $(wc -l < validate/xss_confirmed.tsv)"
    return 0
}

# ============ Phase: idor_probe (NEW) ============
# Numeric-ID swap IDOR probe: requires auth (AUTH_HEADER or AUTH_COOKIE) —
# otherwise skipped. For each URL with id=N, requests id=N-1 and id=N+1,
# records when response differs significantly but still returns 200.
do_idor_probe() {
    [ -z "${AUTH_HEADER:-}${AUTH_COOKIE:-}" ] && {
        info "idor_probe skipped (no AUTH_HEADER/AUTH_COOKIE set)"
        return 0
    }
    [ ! -s web/all_urls.txt ] && return 0
    mkdir -p validate
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)

    : > validate/idor_candidates.tsv
    log "IDOR numeric-swap probe"

    grep -Ei '(id|uid|user|user_id|account|account_id|order|invoice|doc|file|object)=[0-9]+' \
        web/all_urls.txt | head -80 | sort -u | while read -r url; do
        [ -z "$url" ] && continue
        local base_num body_base body_alt1 body_alt2 sz_base sz_alt1 sz_alt2 alt1 alt2 code1 code2
        base_num=$(printf '%s' "$url" | grep -oE '(id|uid|user|user_id|account|account_id|order|invoice|doc|file|object)=[0-9]+' | head -1 | awk -F= '{print $2}')
        [ -z "$base_num" ] && continue
        alt1=$((base_num + 1))
        alt2=$((base_num - 1))
        [ "$alt2" -lt 1 ] && alt2=$((base_num + 2))
        local u1 u2
        u1=$(printf '%s' "$url" | sed -E "s/(=)${base_num}(&|$)/\1${alt1}\2/")
        u2=$(printf '%s' "$url" | sed -E "s/(=)${base_num}(&|$)/\1${alt2}\2/")
        body_base=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url"  2>/dev/null)
        body_alt1=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$u1" 2>/dev/null)
        body_alt2=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$u2" 2>/dev/null)
        code1=$(curl_p -sk -o /dev/null -w '%{http_code}' --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$u1" 2>/dev/null)
        code2=$(curl_p -sk -o /dev/null -w '%{http_code}' --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$u2" 2>/dev/null)
        sz_base=$(printf '%s' "$body_base" | wc -c)
        sz_alt1=$(printf '%s' "$body_alt1" | wc -c)
        sz_alt2=$(printf '%s' "$body_alt2" | wc -c)
        # If alt returns 200 with a materially different body, flag it.
        if [[ "$code1" =~ ^2 ]] && [ "$sz_alt1" -gt 200 ] \
           && [ "$((sz_alt1 > sz_base ? sz_alt1 - sz_base : sz_base - sz_alt1))" -gt 150 ]; then
            printf 'IDOR-DIFF\t%s\t%s\t%s→%s\n' "$url" "$u1" "$sz_base" "$sz_alt1" \
                >> validate/idor_candidates.tsv
        fi
        if [[ "$code2" =~ ^2 ]] && [ "$sz_alt2" -gt 200 ] \
           && [ "$((sz_alt2 > sz_base ? sz_alt2 - sz_base : sz_base - sz_alt2))" -gt 150 ]; then
            printf 'IDOR-DIFF\t%s\t%s\t%s→%s\n' "$url" "$u2" "$sz_base" "$sz_alt2" \
                >> validate/idor_candidates.tsv
        fi
    done

    sort -u -o validate/idor_candidates.tsv validate/idor_candidates.tsv 2>/dev/null || true
    log "IDOR candidates: $(wc -l < validate/idor_candidates.tsv)"
    return 0
}

# ============ Phase: race_probe (NEW) ============
# Simple race-condition prober: fires N parallel identical requests to a
# state-changing endpoint and compares response codes + body lengths.
# Only runs on endpoints user explicitly lists in checklist/race_targets.txt,
# or in --deep mode against discovered /api/ POST-shaped URLs.
do_race_probe() {
    local targets="checklist/race_targets.txt"
    if [ ! -s "$targets" ]; then
        [ "$DEEP_MODE" -ne 1 ] && { info "race_probe skipped (no race_targets.txt and not --deep)"; return 0; }
        grep -Ei '/api/(.*(transfer|redeem|coupon|promo|withdraw|vote|like|claim|purchase)[^ ]*)' \
            web/all_urls.txt 2>/dev/null | head -20 > "$targets"
    fi
    [ ! -s "$targets" ] && return 0

    mkdir -p validate/race
    local c_hdrs
    mapfile -t c_hdrs < <(curl_headers)
    : > validate/race/results.tsv

    log "Race-condition probe (20× parallel)"
    while read -r url; do
        [ -z "$url" ] && continue
        local tmp
        tmp=$(mktemp -d)
        local i
        for i in $(seq 1 20); do
            (
                curl_p -sk -o "$tmp/$i.body" -w '%{http_code}\t%{size_download}\n' \
                    --max-time 10 -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null \
                    > "$tmp/$i.meta"
            ) &
        done
        wait
        # Aggregate unique (code, size) pairs — more than one unique pair
        # on an idempotent endpoint is suspicious.
        local uniq
        uniq=$(cat "$tmp"/*.meta 2>/dev/null | sort -u | wc -l)
        local sig
        sig=$(cat "$tmp"/*.meta 2>/dev/null | sort | uniq -c | awk '{print $2":"$3"x"$1}' | paste -sd, -)
        printf 'RACE\t%s\tuniq=%s\t%s\n' "$url" "$uniq" "$sig" >> validate/race/results.tsv
        rm -rf "$tmp"
    done < "$targets"
    return 0
}

# ============ Phase: chain_findings (NEW) ============
# Correlates individually-low findings into high-severity attack chains.
# Writes reports/attack_chains.md.
do_chain_findings() {
    mkdir -p reports
    local out="reports/attack_chains.md"
    : > "$out"
    {
        echo "# Attack Chains"
        echo
        echo "_Automatically stitched from individual findings. Each chain"
        echo "represents related low/medium signals that, combined, justify a"
        echo "higher severity than any single finding would on its own._"
        echo
    } >> "$out"

    local any=0

    # Chain A: dangling CNAME + takeover fingerprint
    if [ -s vulns/takeovers.jsonl ] || [ -s vulns/subjack.txt ]; then
        {
            echo "## Chain A — Subdomain takeover"
            echo
            echo "Unclaimed CNAME + provider fingerprint → full-subdomain takeover."
            echo
            echo '```'
            [ -s vulns/takeovers.jsonl ] && jq -r '[.info.name,.host] | @tsv' vulns/takeovers.jsonl 2>/dev/null | head -15
            [ -s vulns/subjack.txt ]     && head -15 vulns/subjack.txt
            echo '```'
            echo
        } >> "$out"
        any=1
    fi

    # Chain B: leaked JS secret + recognisable API host
    if [ -s js/highvalue_secrets.txt ] && [ -s js/endpoints_fqdn.txt ]; then
        {
            echo "## Chain B — Leaked credentials usable against discovered API"
            echo
            echo "High-entropy secret in shipped JS combined with a discovered"
            echo "API FQDN. Validate by calling the API with the leaked key."
            echo
            echo '### Secrets'
            echo '```'
            head -10 js/highvalue_secrets.txt
            echo '```'
            echo '### API hosts'
            echo '```'
            head -10 js/endpoints_fqdn.txt
            echo '```'
            echo
        } >> "$out"
        any=1
    fi

    # Chain C: CORS null/reflected + JWT-exposing endpoint
    if [ -s vulns/cors_manual.txt ] && [ -s checklist/jwt_endpoints.txt ]; then
        {
            echo "## Chain C — CORS → token theft"
            echo
            echo "Permissive CORS combined with endpoints that return/accept"
            echo "JWTs. A malicious origin can read the token cross-site."
            echo
            echo '### CORS'
            echo '```'
            head -10 vulns/cors_manual.txt
            echo '```'
            echo '### JWT surface'
            echo '```'
            head -10 checklist/jwt_endpoints.txt
            echo '```'
            echo
        } >> "$out"
        any=1
    fi

    # Chain D: open-redirect + OAuth redirect_uri
    if [ -s vulns/deep/open_redirect_confirmed.txt ] && [ -s vulns/oauth/candidates.txt ]; then
        {
            echo "## Chain D — Open redirect → OAuth token steal"
            echo
            echo "Confirmed open-redirect + visible OAuth \`redirect_uri\`"
            echo "endpoints can chain into access-token hijack if the"
            echo "authorization server allows the redirect host."
            echo
            echo '### Open redirects'
            echo '```'
            head -10 vulns/deep/open_redirect_confirmed.txt
            echo '```'
            echo '### OAuth endpoints'
            echo '```'
            head -10 vulns/oauth/candidates.txt
            echo '```'
            echo
        } >> "$out"
        any=1
    fi

    # Chain E: SSRF + cloud metadata endpoints hinted by bucket enum
    if [ -s vulns/ssrf/requests_fired.tsv ] && { [ -s recon/cloud/buckets_interesting.txt ] || [ -s vulns/ssrf/localhost_probe.tsv ]; }; then
        {
            echo "## Chain E — SSRF → cloud metadata"
            echo
            echo "SSRF-capable endpoints plus observed AWS/GCP metadata"
            echo "responses. Potential credential theft from IMDS."
            echo
            [ -s vulns/ssrf/localhost_probe.tsv ] && {
                echo '### Metadata-leaking responses'
                echo '```'
                head -10 vulns/ssrf/localhost_probe.tsv
                echo '```'
            }
            echo '### Discoverable buckets'
            echo '```'
            head -10 recon/cloud/buckets_interesting.txt 2>/dev/null
            echo '```'
        } >> "$out"
        any=1
    fi

    # Chain F: GraphQL introspection + auth surface
    if [ -s vulns/graphql/introspection.tsv ] && [ -s checklist/auth_endpoints.txt ]; then
        {
            echo "## Chain F — GraphQL schema → auth bypass"
            echo
            echo "Exposed introspection reveals mutations/queries an attacker"
            echo "can reach without the documented API client."
            echo
            echo '### Introspective endpoints'
            echo '```'
            head -10 vulns/graphql/introspection.tsv
            echo '```'
        } >> "$out"
        any=1
    fi

    [ "$any" -eq 0 ] && echo "_No chains stitched — individual findings stand alone._" >> "$out"
    log "Attack chains: $out"
    return 0
}

# ============ Phase: diff ============
# (kept here because it validates prior-run delta)
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
        "vulns/sqli/error_based.tsv"
        "vulns/sqli/time_based.tsv"
        "vulns/ssrf/localhost_probe.tsv"
        "vulns/graphql/introspection.tsv"
        "vulns/jwt/found_tokens.tsv"
        "vulns/oauth/redirect_bypass.tsv"
        "validate/xss_confirmed.tsv"
        "validate/idor_candidates.tsv"
        "vulns/ai_active/confirmed.txt"
    )
    for f in "${sections[@]}"; do
        local cur="$f"
        local prev="$PREV_RUN/$f"
        [ -s "$cur" ] && [ -s "$prev" ] || continue
        local out="diffs/new_$(echo "$f" | tr '/' '_')"
        comm -23 <(sort -u "$cur") <(sort -u "$prev") > "$out"
    done

    if [ -s vulns/nuclei.jsonl ] && [ -s "$PREV_RUN/vulns/nuclei.jsonl" ]; then
        jq -r '[.info.name, .host, .["matched-at"]] | @tsv' vulns/nuclei.jsonl \
            | sort -u > tmp/cur_nuclei.txt
        jq -r '[.info.name, .host, .["matched-at"]] | @tsv' "$PREV_RUN/vulns/nuclei.jsonl" \
            | sort -u > tmp/prev_nuclei.txt
        comm -23 tmp/cur_nuclei.txt tmp/prev_nuclei.txt > diffs/new_nuclei_findings.txt
    fi

    local new_subs new_urls new_vulns
    new_subs=$(wc -l < diffs/new_subdomains_all.txt 2>/dev/null || echo 0)
    new_urls=$(wc -l < diffs/new_web_all_urls.txt 2>/dev/null || echo 0)
    new_vulns=$(wc -l < diffs/new_nuclei_findings.txt 2>/dev/null || echo 0)
    info "Diffs: +${new_subs} subs, +${new_urls} urls, +${new_vulns} findings"
    return 0
}
