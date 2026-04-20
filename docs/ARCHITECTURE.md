# Architecture (v6)

## Design Philosophy

- Orchestrator + per-concern libraries. `paintest.sh` wires phases; `lib/*.sh` implement them.
- Output-first: phases pass data through plain text, TSV, JSONL, Markdown, SARIF, HTML.
- Resumable: completed phases are recorded in `.phase_state`.
- Tool-tolerant: missing optional tools are reported and skipped.
- Scope-aware: discovered assets are filtered through `scope.txt` / `$SCOPE_FILE`.
- AI-inert by default. Destructive probes (sqlmap) gated behind explicit env vars.

## Layout

```
paintest.sh         arg/config parse, PHASES[], main loop
lib/common.sh       logging, notify/webhook, scope, phase checkpoint, header helpers
lib/engine.sh       proxy wrappers (curl_p/httpx_p/nuclei_p/ffuf_p), adaptive rate,
                    URL normalize + dedup, parallel_map
lib/recon.sh        passive, github, subdomain, asn, port, web_probe, favicon,
                    cloud, url_discovery, api_spec_hunt, dir_fuzz, js, custom_wordlist,
                    param_mining, auth_surface
lib/vuln.sh         basic checks, nuclei, cve_correlate, sqli, ssrf_verify, jwt,
                    graphql, oauth, ssti, nosql, proto_pollution, deep_checks
lib/validate.sh     xss_validate (response-diff), idor_probe, race_probe,
                    chain_findings, diff
lib/report.sh       Markdown report, SARIF, standalone HTML, CVSS-ish scoring,
                    curl PoC generator
lib/ai.sh           ai_triage, ai_active (inert unless flag set)
```

## Startup Flow

```text
load ~/.recon.conf
load .env if present
parse args
build output path
banner
start webhook notification
check tools (required + optional)
create output directories
source lib/*.sh
iterate PHASES[]
optional ai_active
run diff + report
optional ai_triage
final webhook notification
```

## Phase order (data flow)

```text
 1  passive_recon           whois, dig, crt.sh, bufferover, rapiddns, favicon hint
 2  github_recon            gitdorks_go / trufflehog github / gh code search
 3  subdomain_enum          subfinder/assetfinder/amass/findomain + dnsx + gotator
 4  asn_expand              asnmap → mapcidr → IP ranges
 5  port_scan               naabu (+ nmap --script default[,vuln] in --deep)
 6  web_probe               httpx, hash dedup, wafw00f, gowitness, adaptive backoff
 7  favicon_pivot           mmh3 favicon → Shodan/FOFA query hints
 8  cloud_recon             s3/gcs/azure/do bucket probe + s3scanner + cloud_enum
 9  url_discovery           gau, waybackurls, katana, uro, historical secret sweep
10  api_spec_hunt           swagger/openapi/graphql schema fetch + path extract
11  custom_wordlist         target-tailored wordlist from JS + URLs + titles
12  dir_fuzz                ffuf + high-value paths (actuator, git, env, etc.)
13  js_analysis             subjs, jsluice, trufflehog, gitleaks + high-entropy regex
14  vuln_scan               nuclei consolidated, dalfox, CORS, JWT surface, testssl, subjack
15  cve_correlate           nuclei -tags cve,<detected-tech>
16  sqli_scan               error + time-based payloads; sqlmap handoff if SQLMAP_RISK set
17  ssrf_verify             OAST callbacks to $CALLBACK_DOMAIN + IMDS/localhost probes
18  jwt_scan                collect JWTs from responses; jwt_tool; alg/kid analysis
19  graphql_scan            introspection + suggestion-leak + graphql-cop
20  oauth_scan              redirect_uri bypass variants
21  ssti_scan               engine-fingerprint arithmetic markers
22  nosql_scan              operator-injection divergence probe
23  proto_pollution_scan    client-side __proto__ canary reflection
24  deep_checks             reflected XSS / SQL error / LFI / open-redirect validation
25  xss_validate            response-diff confirmation (marker-only; control-negative)
26  idor_probe              numeric-ID swap; requires AUTH_HEADER/AUTH_COOKIE
27  race_probe              20× parallel identical requests; diverges → race suspicion
28  param_mining            arjun
29  auth_surface            sensitive files, SSRF params, OAuth/SAML, proto-pollution URLs
30  chain_findings          stitches low-individual findings into attack chains
31  ai_active (optional)    bounded AI-generated payload validation
32  diff                    compare with previous run
33  report                  Markdown + SARIF + HTML + manual checklist
34  ai_triage (optional)    provider-API triage summary
```

## Checkpoints

Each successful phase appends one line to `.phase_state`:

```text
passive_recon:done
github_recon:done
...
```

With `-r`, `run_phase` skips already-done phases. `PHASE_TOTAL` is derived from `${#PHASES[@]}` plus two for diff/report plus one each if `AI_MODE`/`AI_ACTIVE_MODE` is set — no manual counter upkeep.

## Config Loading

1. `~/.recon.conf`
2. Project `.env`, if present (overrides persistent config)
3. Script defaults

AI settings are inert unless `-ai` / `--ai-active`. Destructive `sqlmap` handoff only runs if `SQLMAP_RISK` is explicitly set. Adaptive backoff is on by default; disable with `PAINTEST_ADAPTIVE=0`.

## Data Flow

```text
subdomains/all.txt
        |
        v
web/live.txt → web/live_dedup.txt → web/all_urls.txt
        |                                   |
        |                         params/*.txt, checklist/*.txt
        |
        v
js/js_urls.txt → js/content/ → js/endpoints.txt
        |                    → js/jsluice_secrets.txt
        |                    → js/highvalue_secrets.txt
        v
vulns/{sqli,ssrf,jwt,graphql,oauth,ssti,nosql,proto_pollution,cve}/*
validate/{xss_confirmed,idor_candidates,race/}*
        |
        v
reports/findings.jsonl  ← canonical, feeds SARIF + HTML + Markdown + AI prompt
reports/report_*.md, reports/findings.sarif, reports/report_*.html,
reports/attack_chains.md
```

## Adding A Phase

1. Write `do_my_phase()` in the right `lib/*.sh` (usually `recon.sh`, `vuln.sh`, or `validate.sh`). Guard with `[ ! -s <input-file> ] && return 0` style early exits so missing prereqs are not fatal.
2. Register it in `PHASES` (`paintest.sh`) at the correct dataflow position.
3. If it emits new finding classes, teach `lib/report.sh:do_report()` to `_emit` them so they show up in SARIF and HTML.

## Proxy / Rate / Dedup

- All outgoing HTTP goes through the `*_p` wrappers (`curl_p`, `httpx_p`, `nuclei_p`, `ffuf_p`). Set `HTTP_PROXY` to route via Burp / ZAP.
- `adaptive_probe` runs once during `web_probe` and halves `RATE`/`THREADS` when the target throttles.
- `dedup_urls` normalizes URLs (lowercase host, drop default port, sorted unique-keyed query) via Python; falls back to `sort -u` when Python is unavailable.
