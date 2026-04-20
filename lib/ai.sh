# shellcheck shell=bash
# Paintest — AI triage + AI active validation.
# AI code paths are inert unless AI_MODE=1 or AI_ACTIVE_MODE=1.

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
        echo "## Findings summary (normalized)"
        head -200 reports/findings.jsonl 2>/dev/null
        echo
        echo "## Attack chains"
        cat reports/attack_chains.md 2>/dev/null
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
        echo "## XSS confirmed"
        head -80 validate/xss_confirmed.tsv 2>/dev/null
        echo
        echo "## SQLi error / time"
        head -80 vulns/sqli/error_based.tsv 2>/dev/null
        head -80 vulns/sqli/time_based.tsv 2>/dev/null
        echo
        echo "## SSRF metadata / OAST"
        head -80 vulns/ssrf/localhost_probe.tsv 2>/dev/null
        head -80 vulns/ssrf/requests_fired.tsv 2>/dev/null
        echo
        echo "## GraphQL"
        head -60 vulns/graphql/introspection.tsv 2>/dev/null
        echo
        echo "## OAuth"
        head -60 vulns/oauth/redirect_bypass.tsv 2>/dev/null
        echo
        echo "## JWT"
        head -60 vulns/jwt/found_tokens.tsv 2>/dev/null
        echo
        echo "## CVE correlated"
        head -60 vulns/cve/correlated.tsv 2>/dev/null
        echo
        echo "## JS secret signals"
        head -60 js/highvalue_secrets.txt 2>/dev/null
        head -60 js/jsluice_secrets.txt 2>/dev/null
        head -60 js/trufflehog.txt 2>/dev/null
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
            http_code=$(curl_p -sS --max-time 120 \
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
            http_code=$(curl_p -sS --max-time 120 \
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
                body=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
                printf '%s' "$body" | grep -F "$payload" >/dev/null \
                    && printf 'AI-XSS-REFLECTED\t%s\t%s\t%s\n' "$url" "$payload" "$reason" >> vulns/ai_active/reflected_xss.txt
                ;;
            sqli)
                body=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
                printf '%s' "$body" | grep -Eiq 'SQL syntax|mysql_fetch|ORA-[0-9]|PostgreSQL|SQLite|ODBC|MariaDB|You have an error in your SQL|SQLSTATE' \
                    && printf 'AI-SQL-ERROR\t%s\t%s\t%s\n' "$url" "$payload" "$reason" >> vulns/ai_active/sql_error_candidates.txt
                ;;
            lfi)
                body=$(curl_p -skL --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
                printf '%s' "$body" | grep -E 'root:.*:0:0:|daemon:.*:1:1:' >/dev/null \
                    && printf 'AI-LFI-CONFIRMED\t%s\t%s\t%s\n' "$url" "$payload" "$reason" >> vulns/ai_active/lfi_confirmed.txt
                ;;
            redirect)
                headers=$(curl_p -skI --max-time "$HTTP_TIMEOUT" -A "$UA" "${c_hdrs[@]}" "$url" 2>/dev/null)
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
