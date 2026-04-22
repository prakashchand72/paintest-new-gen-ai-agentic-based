# shellcheck shell=bash
# Paintest — recon phases. Sourced after lib/common.sh and lib/engine.sh.

# ============ Phase: passive_recon ============
do_passive_recon() {
    ( timeout "$API_TIMEOUT" whois "$TARGET" > recon/whois.txt 2>/dev/null ) &
    dig "$TARGET" ANY +noall +answer  > recon/dns.txt 2>/dev/null
    dig "$TARGET" TXT +short         >> recon/dns.txt 2>/dev/null
    dig "$TARGET" MX  +short         >> recon/dns.txt 2>/dev/null
    dig "$TARGET" NS  +short         >> recon/dns.txt 2>/dev/null
    dig "$TARGET" CAA +short         >> recon/dns.txt 2>/dev/null
    dig "$TARGET" SPF +short         >> recon/dns.txt 2>/dev/null
    dig "$TARGET" DMARC TXT +short   >> recon/dns.txt 2>/dev/null
    dig "_dmarc.$TARGET" TXT +short  >> recon/dns.txt 2>/dev/null

    ( curl_p --max-time "$API_TIMEOUT" -sS -A "$UA" \
        "https://api.hackertarget.com/aslookup/?q=${TARGET}" \
        > recon/asn.txt 2>/dev/null ) &

    if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
        ( curl_p --max-time 60 -sS -A "$UA" "https://crt.sh/?q=%25.${TARGET}&output=json" \
            | jq -r '.[].name_value' 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' | tr ',' '\n' | sed 's/^\*\.//' \
            | sort -u > recon/crtsh.txt ) &
        ( curl_p --max-time 30 -sS -A "$UA" \
            "https://jldc.me/anubis/subdomains/${TARGET}" \
            | jq -r '.[]?' 2>/dev/null > recon/anubis.txt ) &
        ( curl_p --max-time 30 -sS -A "$UA" \
            "https://dns.bufferover.run/dns?q=.${TARGET}" \
            | jq -r '.FDNS_A[]? | split(",")[1] // empty' 2>/dev/null \
            | sort -u > recon/bufferover.txt ) &
        ( curl_p --max-time 30 -sS -A "$UA" \
            "https://rapiddns.io/subdomain/${TARGET}?full=1#result" 2>/dev/null \
            | grep -oE "[a-zA-Z0-9._-]+\\.${TARGET//./\\.}" | sort -u \
            > recon/rapiddns.txt ) &
    fi

    if [ "$SUBDOMAIN_MODE" -eq 1 ] && have httpx; then
        ( httpx_p -u "https://${TARGET}" -favicon -silent -timeout 20 \
            > recon/favicon.txt 2>/dev/null ) &
    fi

    cat > checklist/github_dorks.txt <<EOF
# Run manually on github.com/search — or use gitdorks_go for automation
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

# ============ Phase: github_recon (NEW) ============
do_github_recon() {
    [ "$SUBDOMAIN_MODE" -ne 1 ] && { info "github_recon skipped (single target mode)"; return 0; }
    mkdir -p recon/github

    if [ -n "${GITHUB_TOKEN:-}" ] && have gitdorks_go; then
        log "gitdorks_go (secrets via GitHub dorks)"
        local dorks_wl
        for p in \
            /opt/gitdorks_go/Dorks/medium_dorks.txt \
            "$HOME/tools/gitdorks_go/Dorks/medium_dorks.txt" \
            /usr/share/gitdorks/medium_dorks.txt; do
            [ -f "$p" ] && dorks_wl="$p" && break
        done
        if [ -n "${dorks_wl:-}" ]; then
            timeout 300 gitdorks_go -gd "$dorks_wl" -nws 5 -target "$TARGET" \
                -tf <(echo "$GITHUB_TOKEN") \
                > recon/github/gitdorks.txt 2>/dev/null || true
        fi
    else
        info "gitdorks_go or GITHUB_TOKEN missing — writing dork hints only"
    fi

    if [ -n "${GITHUB_TOKEN:-}" ] && have trufflehog; then
        log "trufflehog github org scan (best-effort)"
        local org="${TARGET%%.*}"
        timeout 300 trufflehog github \
            --org "$org" --token "$GITHUB_TOKEN" --no-update \
            > recon/github/trufflehog_org.txt 2>/dev/null || true
    fi

    if have gh && [ -n "${GITHUB_TOKEN:-}" ]; then
        log "gh code search (top 20 hits per dork)"
        : > recon/github/gh_code_search.txt
        for q in "password" "api_key" "secret" "token" "BEGIN RSA PRIVATE KEY" \
                 "aws_access_key_id" "-----BEGIN"; do
            gh api -X GET search/code \
                -f q="\"${TARGET}\" ${q}" \
                --jq '.items[] | [.repository.full_name,.path,.html_url] | @tsv' \
                2>/dev/null | head -20 >> recon/github/gh_code_search.txt
            sleep 1
        done
    fi
    return 0
}

# ============ Phase: subdomain_enum ============
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
    cp recon/bufferover.txt subdomains/bufferover.txt 2>/dev/null
    cp recon/rapiddns.txt subdomains/rapiddns.txt 2>/dev/null

    cat subdomains/*.txt 2>/dev/null | tr '[:upper:]' '[:lower:]' \
        | grep -E '^[a-z0-9._-]+$' | sort -u > subdomains/all_passive.txt

    if [ "${BRUTEFORCE_MODE:-0}" -eq 1 ]; then
        local wl="$SECLISTS/Discovery/DNS/subdomains-top1million-20000.txt"
        [ "$DEEP_MODE" -eq 1 ] && [ -f "$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt" ] && \
            wl="$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt"
        if have dnsx && [ -f "$wl" ]; then
            log "DNS bruteforce ($(basename "$wl"), cap ${DNS_BRUTE_TIMEOUT:-600}s)"
            timeout "${DNS_BRUTE_TIMEOUT:-600}" \
                dnsx -d "$TARGET" -w "$wl" -silent \
                -o subdomains/bruteforce.txt 2>/dev/null
        fi

        if have gotator && [ -s subdomains/all_passive.txt ] \
           && [ "$(wc -l < subdomains/all_passive.txt)" -lt 500 ]; then
            local permwl="$SECLISTS/Discovery/DNS/dns-Jhaddix.txt"
            if [ -f "$permwl" ]; then
                log "Permutations (cap ${DNS_PERM_TIMEOUT:-600}s)"
                timeout "${DNS_PERM_TIMEOUT:-600}" bash -c '
                    gotator -sub subdomains/all_passive.txt -perm "$1" \
                        -depth 1 -numbers 3 -mindup -adv -md 2>/dev/null \
                    | dnsx -silent 2>/dev/null > subdomains/permutations.txt
                ' _ "$permwl"
            fi
        fi
    else
        info "DNS bruteforce skipped (pass -bf/--bruteforce to enable)"
    fi

    cat subdomains/*.txt 2>/dev/null | sort -u > subdomains/all_unfiltered.txt
    echo "$TARGET" >> subdomains/all_unfiltered.txt
    apply_scope subdomains/all_unfiltered.txt subdomains/all.txt
    log "In-scope subdomains: $(wc -l < subdomains/all.txt)"

    have dnsx && dnsx -l subdomains/all.txt -silent -a -resp \
        -o subdomains/resolved.txt 2>/dev/null
    return 0
}

# ============ Phase: asn_expand (NEW) ============
do_asn_expand() {
    [ "$SUBDOMAIN_MODE" -ne 1 ] && { info "asn_expand skipped (single target mode)"; return 0; }
    mkdir -p recon/asn

    if have asnmap; then
        log "asnmap → CIDR ranges"
        timeout 120 asnmap -d "$TARGET" -silent 2>/dev/null | sort -u > recon/asn/cidrs.txt
    fi

    if have metabigor && [ ! -s recon/asn/cidrs.txt ]; then
        log "metabigor net → CIDR ranges"
        echo "$TARGET" | timeout 120 metabigor net --org \
            > recon/asn/metabigor.txt 2>/dev/null
        awk '{print $NF}' recon/asn/metabigor.txt 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' \
            | sort -u > recon/asn/cidrs.txt
    fi

    if [ -s recon/asn/cidrs.txt ] && have mapcidr; then
        mapcidr -cl recon/asn/cidrs.txt -silent 2>/dev/null \
            | sort -u > recon/asn/ips_from_asn.txt
        info "ASN expansion: $(wc -l < recon/asn/ips_from_asn.txt) IPs across $(wc -l < recon/asn/cidrs.txt) CIDRs"
    fi
    return 0
}

# ============ Phase: favicon_pivot (NEW) ============
do_favicon_pivot() {
    [ "$SUBDOMAIN_MODE" -ne 1 ] && { info "favicon_pivot skipped (single target mode)"; return 0; }
    [ ! -s web/live_dedup.txt ] && return 0
    mkdir -p recon/favicon

    if have httpx; then
        log "favicon hashing (mmh3) across live hosts"
        httpx_p -l web/live_dedup.txt -favicon -silent \
            -o recon/favicon/hashes.txt 2>/dev/null
    fi

    if [ -s recon/favicon/hashes.txt ]; then
        awk '{print $NF}' recon/favicon/hashes.txt | sort -u \
            > recon/favicon/hashes_unique.txt
        : > recon/favicon/shodan_queries.txt
        : > recon/favicon/fofa_queries.txt
        while read -r h; do
            [ -z "$h" ] && continue
            printf 'https://www.shodan.io/search?query=http.favicon.hash%%3A%s\n' "$h" \
                >> recon/favicon/shodan_queries.txt
            printf 'https://en.fofa.info/result?qbase64=%s\n' \
                "$(printf 'icon_hash="%s"' "$h" | base64 -w0 2>/dev/null || printf 'icon_hash="%s"' "$h" | base64)" \
                >> recon/favicon/fofa_queries.txt
        done < recon/favicon/hashes_unique.txt
    fi
    return 0
}

# ============ Phase: port_scan ============
do_port_scan() {
    grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
        subdomains/resolved.txt 2>/dev/null | sort -u > ports/ips.txt
    [ ! -s ports/ips.txt ] && dig +short "$TARGET" > ports/ips.txt
    [ -s recon/asn/ips_from_asn.txt ] && cat recon/asn/ips_from_asn.txt >> ports/ips.txt
    sort -u -o ports/ips.txt ports/ips.txt

    if have naabu && [ -s ports/ips.txt ]; then
        local rate_val
        rate_val=$([ "$DEEP_MODE" -eq 1 ] && echo 1000 || echo 500)
        local ports_flag="-top-ports 1000"
        [ "$DEEP_MODE" -eq 1 ] && ports_flag="-p -"
        # shellcheck disable=SC2086
        naabu -list ports/ips.txt $ports_flag -rate "$rate_val" -silent \
            -o ports/naabu.txt 2>/dev/null
    fi
    if have nmap && [ -s ports/naabu.txt ]; then
        local pp
        pp=$(awk -F: '{print $2}' ports/naabu.txt | sort -un | paste -sd, -)
        local nmap_scripts="default,vuln"
        [ "$DEEP_MODE" -eq 1 ] || nmap_scripts="default"
        [ -n "$pp" ] && ( nmap -iL ports/ips.txt -sV -Pn -T3 -p "$pp" \
            --script "$nmap_scripts" \
            -oA ports/nmap 2>/dev/null >/dev/null ) &
        disown
    fi
    return 0
}

# ============ Phase: web_probe ============
do_web_probe() {
    if ! have httpx; then
        warn "httpx not found — skipping web probe"
        return 0
    fi
    local hdrs
    mapfile -t hdrs < <(httpx_hdrs)

    httpx_p -l subdomains/all.txt -silent -threads "$THREADS" \
        -status-code -title -tech-detect -web-server -location -cdn \
        -follow-redirects -random-agent \
        "${hdrs[@]}" \
        -rate-limit "$RATE" \
        -hash sha256 -json \
        -o web/httpx.jsonl 2>/dev/null

    jq -r '.url // ."input"' web/httpx.jsonl 2>/dev/null | sort -u > web/live.txt

    if [ -s web/httpx.jsonl ]; then
        jq -r 'select(.hash!=null) | [.hash.body_sha256 // .hash, .url] | @tsv' \
            web/httpx.jsonl 2>/dev/null \
            | sort -u -k1,1 | cut -f2 > web/live_dedup.txt
        [ ! -s web/live_dedup.txt ] && cp web/live.txt web/live_dedup.txt
    else
        cp web/live.txt web/live_dedup.txt 2>/dev/null
    fi

    jq -r '[.url, ((.tech // [])|join(","))] | @tsv' web/httpx.jsonl 2>/dev/null \
        > web/tech.tsv

    [ -s web/live.txt ] && adaptive_probe "$(head -1 web/live.txt)"

    have wafw00f   && ( wafw00f -i web/live.txt -o web/waf.txt 2>/dev/null ) &
    have gowitness && ( gowitness file -f web/live_dedup.txt -P screenshots/ 2>/dev/null ) &
    wait

    log "Live hosts: $(wc -l < web/live.txt 2>/dev/null || echo 0) \
(unique-content: $(wc -l < web/live_dedup.txt 2>/dev/null || echo 0))"
    return 0
}

# ============ Phase: cloud_recon (NEW) ============
do_cloud_recon() {
    [ ! -s subdomains/all.txt ] && return 0
    mkdir -p recon/cloud

    local base="${TARGET%%.*}"
    : > recon/cloud/bucket_candidates.txt
    for bucket in \
        "${base}" "${base}-dev" "${base}-prod" "${base}-staging" \
        "${base}-backup" "${base}-backups" "${base}-test" "${base}-media" \
        "${base}-assets" "${base}-uploads" "${base}-data" "${base}-cdn" \
        "${base}-files" "${base}-static" "${base}-internal"; do
        echo "https://${bucket}.s3.amazonaws.com" >> recon/cloud/bucket_candidates.txt
        echo "https://s3.amazonaws.com/${bucket}" >> recon/cloud/bucket_candidates.txt
        echo "https://storage.googleapis.com/${bucket}" >> recon/cloud/bucket_candidates.txt
        echo "https://${bucket}.blob.core.windows.net" >> recon/cloud/bucket_candidates.txt
        echo "https://${bucket}.azurewebsites.net" >> recon/cloud/bucket_candidates.txt
        echo "https://${bucket}.digitaloceanspaces.com" >> recon/cloud/bucket_candidates.txt
    done

    if have httpx; then
        httpx_p -l recon/cloud/bucket_candidates.txt -silent \
            -status-code -title -content-length \
            -mc 200,206,301,302,403 \
            -o recon/cloud/buckets_interesting.txt 2>/dev/null
    fi

    if have s3scanner && [ -s subdomains/all.txt ]; then
        log "s3scanner sweep"
        timeout 180 s3scanner scan --bucket-file subdomains/all.txt \
            > recon/cloud/s3scanner.txt 2>/dev/null || true
    fi

    if have cloud_enum; then
        log "cloud_enum sweep"
        timeout 300 cloud_enum -k "$base" --disable-gcp --disable-azure \
            -l recon/cloud/cloud_enum.txt 2>/dev/null || true
    fi
    return 0
}

# ============ Phase: url_discovery ============
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

    if have uro; then
        uro < web/all_urls_scoped.txt > web/all_urls.txt 2>/dev/null
    else
        dedup_urls web/all_urls_scoped.txt web/all_urls.txt
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

    # Historical secret regex sweep on wayback data
    if [ -s web/gau.txt ] || [ -s web/wayback.txt ]; then
        cat web/gau.txt web/wayback.txt 2>/dev/null \
            | grep -EiI '(api[_-]?key|secret|token|password|aws_access|bearer|authorization)=[^&]{8,}' \
            | sort -u > web/historical_secret_urls.txt
    fi
    return 0
}

# ============ Phase: api_spec_hunt (NEW) ============
do_api_spec_hunt() {
    [ ! -s web/live_dedup.txt ] && return 0
    mkdir -p recon/apispec
    local -a paths=(
        /swagger.json /swagger.yaml /swagger-ui.html /swagger-ui/
        /openapi.json /openapi.yaml /v2/api-docs /v3/api-docs
        /api-docs /api/docs /api/swagger /api/openapi.json
        /graphql /graphiql /api/graphql /playground
        /.well-known/openapi.json /.well-known/openid-configuration
        /actuator /actuator/mappings /actuator/beans
        /api /api/v1 /api/v2 /docs /redoc
    )
    : > recon/apispec/candidates.txt
    while read -r host; do
        [ -z "$host" ] && continue
        for p in "${paths[@]}"; do
            printf '%s%s\n' "${host%/}" "$p" >> recon/apispec/candidates.txt
        done
    done < web/live_dedup.txt

    if have httpx; then
        httpx_p -l recon/apispec/candidates.txt -silent \
            -status-code -content-type -content-length -title \
            -mc 200,301,302,401,403 \
            -o recon/apispec/found.txt 2>/dev/null

        # For each found JSON/YAML spec, try to pull operation paths
        while read -r line; do
            [ -z "$line" ] && continue
            local url
            url=$(echo "$line" | awk '{print $1}')
            [[ "$line" =~ (json|yaml|graphql) ]] || continue
            local body
            body=$(curl_p -sL --max-time "$HTTP_TIMEOUT" -A "$UA" "$url" 2>/dev/null)
            [ -z "$body" ] && continue
            printf '%s\n' "$body" | jq -r '
                (.paths // {}) as $p
                | ($p | keys[]? | "PATH\t" + .)' 2>/dev/null \
                >> recon/apispec/extracted_paths.tsv
        done < recon/apispec/found.txt
    fi
    return 0
}

# ============ Phase: dir_fuzz ============
do_dir_fuzz() {
    [ ! -s web/live_dedup.txt ] && return 0
    local wl="$SECLISTS/Discovery/Web-Content/raft-small-directories.txt"
    [ "$DEEP_MODE" -eq 1 ] && [ -f "$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt" ] && \
        wl="$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt"
    [ "$DEEP_MODE" -eq 1 ] && [ -f "$SECLISTS/Discovery/Web-Content/raft-large-directories.txt" ] && \
        wl="$SECLISTS/Discovery/Web-Content/raft-large-directories.txt"
    [ ! -f "$wl" ] && wl="$SECLISTS/Discovery/Web-Content/common.txt"
    [ ! -f "$wl" ] && { warn "No wordlist, skipping"; return 0; }

    local hdrs=(-H "$ID_HEADER" -H "User-Agent: $UA")
    [ -n "${AUTH_HEADER:-}" ] && hdrs+=(-H "$AUTH_HEADER")
    [ -n "${AUTH_COOKIE:-}" ] && hdrs+=(-H "Cookie: $AUTH_COOKIE")

    if have ffuf; then
        local hosts_to_fuzz
        if [ "$SUBDOMAIN_MODE" -eq 1 ]; then
            if [ "$DEEP_MODE" -eq 1 ]; then
                hosts_to_fuzz=$(head -200 web/live_dedup.txt)
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
            ffuf_p -u "${url}/FUZZ" -w "$wl" \
                 -mc 200,201,204,301,302,307,401,403 \
                 -fc 404 -ac \
                 -maxtime-job "$([ "$DEEP_MODE" -eq 1 ] && echo 600 || echo 180)" \
                 -t "$([ "$DEEP_MODE" -eq 1 ] && echo "$DEEP_THREADS" || echo "$THREADS")" \
                 -rate "$([ "$DEEP_MODE" -eq 1 ] && echo "$DEEP_RATE" || echo "$RATE")" -s \
                 "${hdrs[@]}" \
                 -o "fuzzing/${safe}.json" -of json 2>/dev/null
        done
    fi

    cat > tmp/highvalue_paths.txt <<'EOF'
.git/config
.git/HEAD
.git/logs/HEAD
.git/index
.env
.env.local
.env.production
.env.development
.env.staging
.DS_Store
.svn/entries
.hg/hgrc
.bzr/README
config.json
config.yml
composer.json
package.json
package-lock.json
yarn.lock
.npmrc
backup.sql
backup.zip
backup.tar.gz
db.sql
dump.sql
wp-config.php.bak
wp-config.php~
wp-config.old
server-status
server-info
actuator
actuator/env
actuator/health
actuator/heapdump
actuator/mappings
actuator/threaddump
actuator/httptrace
actuator/configprops
actuator/beans
actuator/logfile
api/swagger.json
swagger.json
swagger-ui.html
swagger-ui/
openapi.json
openapi.yaml
v2/api-docs
v3/api-docs
phpinfo.php
info.php
test.php
debug
debug.php
console
admin
admin/
administrator/
administration
robots.txt
sitemap.xml
crossdomain.xml
.well-known/security.txt
.well-known/openid-configuration
.well-known/assetlinks.json
jmx-console
web-console
manager/html
management
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
wp-json/wp/v2/users
wp-json/
xmlrpc.php
.aws/credentials
.kube/config
.ssh/id_rsa
.ssh/authorized_keys
EOF
    if have httpx; then
        local hx_hdrs
        mapfile -t hx_hdrs < <(httpx_hdrs)
        while read -r host; do
            while read -r path; do
                echo "${host}/${path}"
            done < tmp/highvalue_paths.txt
        done < web/live_dedup.txt | httpx_p -silent -mc 200,301,302,401,403 \
            "${hx_hdrs[@]}" -rate-limit "$RATE" \
            -status-code -content-length \
            -o vulns/highvalue_paths.txt 2>/dev/null
    fi
    return 0
}

# ============ Phase: js_analysis ============
do_js_analysis() {
    [ ! -s js/js_urls.txt ] && return 0

    if have subjs; then
        subjs -i web/live_dedup.txt 2>/dev/null | sort -u \
            | anew js/js_urls.txt >/dev/null
    fi

    log "Fetching JS files (max ${MAX_JS_FILES})"
    local -a hdrs=(-A "$UA" -H "$ID_HEADER")
    [ -n "${AUTH_HEADER:-}" ] && hdrs+=(-H "$AUTH_HEADER")
    [ -n "${AUTH_COOKIE:-}" ] && hdrs+=(-H "Cookie: $AUTH_COOKIE")

    local count=0
    while read -r jsurl && [ "$count" -lt "$MAX_JS_FILES" ]; do
        local fname
        fname=$(echo "$jsurl" | md5sum | cut -d' ' -f1).js
        [ -f "js/content/${fname}" ] && { ((count++)); continue; }
        curl_p -sL --max-time "$HTTP_TIMEOUT" "${hdrs[@]}" "$jsurl" \
            -o "js/content/${fname}" 2>/dev/null
        ((count++))
    done < js/js_urls.txt

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

    grep -rhoE '"(/[a-zA-Z0-9_/.-]+)"' js/content/ 2>/dev/null \
        | tr -d '"' | sort -u | grep -vE '\.(png|jpg|gif|css|svg|woff|ttf|ico)' \
        > js/endpoints_regex.txt

    # Extra-spicy JS regex: inline API hosts, tokens, cloud keys
    grep -rhoE 'https?://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+(/[A-Za-z0-9_./-]*)?' js/content/ 2>/dev/null \
        | sort -u > js/endpoints_fqdn.txt
    grep -rhoE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]{10,}' \
        js/content/ 2>/dev/null | sort -u > js/highvalue_secrets.txt

    cat js/jsluice_urls.txt js/endpoints_regex.txt 2>/dev/null \
        | sort -u > js/endpoints.txt
    return 0
}

# ============ Phase: custom_wordlist ============
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

# ============ Phase: param_mining ============
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
    [ -n "${AUTH_HEADER:-}" ] && arjun_hdrs+=("$AUTH_HEADER")
    [ -n "${AUTH_COOKIE:-}" ] && arjun_hdrs+=("Cookie: $AUTH_COOKIE")

    echo "$hosts" | while read -r url; do
        [ -z "$url" ] && continue
        arjun -u "$url" -t 10 --stable \
            --headers "$(IFS=$'\n'; echo "${arjun_hdrs[*]}")" \
            -oT "params/arjun_$(echo "$url" | md5sum | cut -c1-8).txt" \
            2>/dev/null
    done
    return 0
}

# ============ Phase: auth_surface ============
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
