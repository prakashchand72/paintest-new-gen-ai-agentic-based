# Paintest Recon Framework (v6)

Paintest is a Bash pentesting pipeline for authorized bug bounty and pentest work. It chains recon, active vulnerability, and validation tools into resumable phases, emits Markdown + SARIF + standalone HTML reports, and sends Discord, Slack, or Telegram progress notifications.

> Architecture: an orchestrator (`paintest.sh`) plus per-concern libraries under `lib/*.sh`. See `docs/ARCHITECTURE.md`.

> Use only on targets where you have explicit permission.
> No automated scanner can guarantee vulnerability discovery. Paintest improves coverage and repeatability, but exploitable findings still depend on target behavior, authentication, templates, wordlists, and manual validation.

## Features

### Recon
- Passive DNS, CAA/SPF/DMARC, crt.sh, bufferover, anubis, rapiddns, favicon hash
- Subdomain enumeration (subfinder/assetfinder/amass/findomain) + dnsx + gotator
- ASN expansion → CIDR → IP with `asnmap` / `metabigor` / `mapcidr`
- Favicon mmh3 pivot → Shodan/FOFA query hints
- Cloud bucket discovery (S3 / GCS / Azure / DO Spaces) + `s3scanner` / `cloud_enum`
- GitHub dorking via `gitdorks_go` / `trufflehog github` / `gh` API (with `GITHUB_TOKEN`)
- API spec hunting (Swagger/OpenAPI/GraphQL schemas) with path extraction
- Target-tailored wordlist from JS + URLs + titles

### Vulnerability & validation
- Nuclei consolidated runs + CVE correlation keyed by detected tech
- SQLi error-based + time-based, optional `sqlmap` handoff (gated by `SQLMAP_RISK`)
- SSRF OAST verification against `$CALLBACK_DOMAIN` + cloud IMDS/localhost probes
- JWT collection + `jwt_tool` + alg/kid analysis
- GraphQL introspection + suggestion-leak + `graphql-cop`
- OAuth `redirect_uri` bypass variants
- SSTI, NoSQL, client-side prototype-pollution probes
- Response-diff XSS confirmation (marker-only; control-negative) — reduces false positives
- IDOR numeric-ID swap (requires auth) + race-condition prober
- Subdomain takeover (nuclei takeovers/ + subjack)
- Basic checks: insecure cookies, missing sec headers, server/version disclosure, legacy TLS, TLS name mismatch, SRI, host-header injection, dangerous HTTP methods, directory listing, mixed content, HTTP cleartext

### Reporting
- **Markdown** report with executive summary, top-ranked findings, and curl PoC per finding
- **SARIF 2.1.0** export (`reports/findings.sarif`) for CI consumption
- **Standalone HTML** report (`reports/report_*.html`) with live filter + severity sort
- **Attack chains** document (`reports/attack_chains.md`) stitching individually-low findings
- **Normalized JSONL** (`reports/findings.jsonl`) — canonical stream for every export
- Manual hunting checklist

### Engine
- Resumable `.phase_state` checkpoints
- Subdomain mode `-sd`, resume `-r`, diff `-d`, deep `--deep`
- Discord, Slack, and Telegram webhook notifications (per-phase progress + final summary)
- Scope filtering through `scope.txt` or `SCOPE_FILE`
- Authenticated recon through `AUTH_HEADER` and `AUTH_COOKIE`
- Proxy passthrough with `HTTP_PROXY` (Burp/ZAP tee)
- Adaptive RATE/THREADS backoff when the target returns 429/5xx
- Optional AI triage `-ai`; bounded AI active validation `--ai-active` — no AI token is used unless the flag is set

## Detection Expectations

Paintest is designed to maximize recon coverage in a test environment, not to guarantee findings. It is strongest at finding exposed services, forgotten files, known-template issues, reflected XSS candidates, CORS mistakes, JS secrets, takeover candidates, and interesting endpoints. Logic bugs, authorization flaws, chained exploits, and authenticated workflows still require manual testing.

For authorized real targets or localhost CTFs, run `--deep`. This enables broader nuclei template coverage, deeper crawling, larger fuzzing, and validation probes for real-world bug classes like reflected XSS, SQL errors, LFI, open redirects, debug exposure, GraphQL exposure, admin panels, and known vulnerable CTF apps.

## Repository Layout

| Path | Purpose |
|---|---|
| `paintest.sh` | Orchestrator: arg/config parsing, phase list, main loop |
| `lib/common.sh` | Logging, notifications, scope, phase checkpointing |
| `lib/engine.sh` | Proxy wrappers, adaptive rate, URL normalize/dedup |
| `lib/recon.sh` | Passive + subdomain + cloud + GitHub + ASN + favicon + URL discovery + fuzz + JS |
| `lib/vuln.sh` | Basic + nuclei + SQLi + SSRF + JWT + GraphQL + OAuth + SSTI + NoSQL + proto-pollution + CVE correlation |
| `lib/validate.sh` | Response-diff XSS, IDOR, race-condition, attack-chain stitcher, diff |
| `lib/report.sh` | Markdown + SARIF + HTML + CVSS scoring + curl PoC |
| `lib/ai.sh` | AI triage and bounded AI active validation |
| `install.sh` | Installs dependencies and prepares `~/.recon.conf` |
| `recon.conf.example` | Default persistent config template |
| `scope.txt.example` | Example scope filter patterns |
| `docs/ARCHITECTURE.md` | Phase/data-flow overview |
| `docs/TROUBLESHOOTING.md` | Common fixes and debugging commands |

## Tools Used

| Phase | Tools |
|---|---|
| Passive recon | `whois`, `dig`, `curl`, `jq`, crt.sh, Anubis, bufferover, rapiddns |
| GitHub recon | `gitdorks_go`, `trufflehog github`, `gh` (needs `GITHUB_TOKEN`) |
| Subdomains | `subfinder`, `assetfinder`, `amass`, `findomain`, `dnsx`, `gotator` |
| ASN | `asnmap`, `metabigor`, `mapcidr` |
| Cloud | `s3scanner`, `cloud_enum` + built-in bucket probe |
| Favicon pivot | `httpx -favicon` (mmh3) |
| Port scanning | `naabu`, `nmap` (+ `--script vuln` in `--deep`) |
| Web probing | `httpx`, `wafw00f`, `gowitness` |
| URL discovery | `gau`, `waybackurls`, `katana`, `uro` |
| API spec hunt | `httpx`, `jq` |
| Fuzzing | `ffuf`, SecLists |
| JS analysis | `subjs`, `jsluice`, `trufflehog`, `gitleaks` + high-entropy regex |
| Vuln checks (core) | `nuclei`, `dalfox`, `testssl.sh`, `subjack`, `qsreplace` |
| SQLi | built-in error/time probes, optional `sqlmap` handoff (gated) |
| SSRF | OAST callback fires + IMDS/localhost probes |
| JWT | `jwt_tool`, built-in alg/kid analysis |
| GraphQL | `graphql-cop` + built-in introspection/suggestion probes |
| Validation | built-in response-diff XSS, IDOR, race-condition prober |
| Parameter mining | `gf`, `unfurl`, `arjun` |
| Reporting | `jq` (Markdown + SARIF + HTML generation) |
| Utilities | `anew`, `jq`, `curl`, `wget`, `git`, `python3`, Go |

Missing tools are reported and skipped where possible.

## Install

```bash
chmod +x install.sh paintest.sh
./install.sh
```

Install options:

```bash
./install.sh --no-sudo          # avoid sudo where possible
./install.sh --skip-seclists    # skip the large SecLists clone
```

The installer also creates `~/.recon.conf` from `recon.conf.example` when it does not exist, keeps permissions at `600`, and ensures webhook timeout/retry settings are present.

## Configure

Edit the generated config:

```bash
nano ~/.recon.conf
chmod 600 ~/.recon.conf
```

Common settings:

```bash
BOUNTY_HANDLE="your_handle"
CALLBACK_DOMAIN="your.oast.domain"
WEBHOOK_URL="https://discord.com/api/webhooks/..."
AUTH_HEADER=""
AUTH_COOKIE=""
THREADS=25
RATE=30
WEBHOOK_CONNECT_TIMEOUT=20
WEBHOOK_TIMEOUT=30
WEBHOOK_RETRIES=3
DEEP_THREADS=50
DEEP_RATE=100
AI_PROVIDER="openai"
AI_API_TOKEN=""      # optional; prefer OPENAI_API_KEY / ANTHROPIC_API_KEY env vars
AI_MODEL=""          # blank selects provider default
AI_ACTIVE_MAX_TESTS=50

# Wall-clock caps (seconds) — stop stalls on CDN-fronted / slow targets.
PORT_SCAN_TIMEOUT=600    # naabu cap per phase
NMAP_TIMEOUT=600         # background nmap script run cap

# Override the default User-Agent / identity header if a bug bounty
# program requires a specific UA or their WAF blocks the default.
# UA=""                  # default: realistic Chrome UA (won't trigger WAFs)
# ID_HEADER="X-Bug-Bounty: your_handle"
```

Config load order:

1. `~/.recon.conf`
2. Project `.env`, if present
3. Script defaults for anything still unset

Because `.env` loads after `~/.recon.conf`, a project-local `.env` can override persistent settings.

## Scope

Create `scope.txt` in the project directory, or set `SCOPE_FILE` in `~/.recon.conf`.

Example:

```text
target.com
api.target.com
staging-
.internal.target.io
```

Patterns are literal string matches. Do not include comment lines in a real scope file unless you want those strings to be matched.

## Usage

Single target:

```bash
./paintest.sh target.com
```

Subdomain discovery:

```bash
./paintest.sh -sd target.com
```

Resume the latest run for the same target and mode:

```bash
./paintest.sh -sd -r target.com
```

Diff against the previous run:

```bash
./paintest.sh -sd -d target.com
```

Deep authorized scan:

```bash
./paintest.sh --deep http://127.0.0.1:3000
./paintest.sh --deep https://target.example
```

AI triage after the scan:

```bash
AI_API_TOKEN="sk-..." ./paintest.sh -ai target.com
AI_PROVIDER=anthropic AI_API_TOKEN="sk-ant-..." ./paintest.sh -ai --deep target.com
```

AI-assisted active validation:

```bash
AI_API_TOKEN="sk-..." CALLBACK_DOMAIN="your-oob.example" ./paintest.sh --ai-active --deep target.com
AI_PROVIDER=anthropic AI_API_TOKEN="sk-ant-..." AI_ACTIVE_MAX_TESTS=25 ./paintest.sh --ai-active target.com
```

`--ai-active` is intentionally bounded: the model proposes JSON payload candidates, the script filters them through scope, and Paintest performs deterministic validation checks. AI does not execute commands or directly control tools.

Runtime overrides:

```bash
THREADS=50 RATE=100 ./paintest.sh -sd target.com
WEBHOOK_URL="https://discord.com/api/webhooks/..." ./paintest.sh target.com
AI_PROVIDER=openai AI_MODEL=gpt-5.4-mini ./paintest.sh -ai target.com

# Route all HTTP through Burp / ZAP
HTTP_PROXY=http://127.0.0.1:8080 ./paintest.sh --deep target.com

# Unlock sqlmap handoff on SQLi candidates (opt-in, noisy)
SQLMAP_RISK=1 ./paintest.sh --deep target.com

# GitHub dorking (requires a token with public_repo scope)
GITHUB_TOKEN=ghp_... ./paintest.sh -sd target.com

# Disable adaptive rate backoff
PAINTEST_ADAPTIVE=0 ./paintest.sh target.com
```

Test webhook delivery without scanning:

```bash
./paintest.sh --test-webhook
```

## Output

Each run writes to:

```text
recon_<target>_<mode>_<timestamp>/
```

Important directories:

| Directory | Contents |
|---|---|
| `recon/` | Whois, DNS, ASN, crt.sh, passive notes |
| `recon/github/` | GitHub dork + trufflehog + `gh` code search output |
| `recon/asn/` | `asnmap` / `metabigor` CIDR ranges and expanded IPs |
| `recon/cloud/` | Bucket candidates + `s3scanner` / `cloud_enum` output |
| `recon/apispec/` | Found Swagger/OpenAPI/GraphQL schema URLs + extracted paths |
| `recon/favicon/` | Favicon mmh3 hashes + Shodan/FOFA query hints |
| `subdomains/` | Passive, brute-forced, resolved, and scoped hosts |
| `ports/` | `naabu` and `nmap` output |
| `web/` | Live hosts, httpx JSONL, discovered URLs, tech TSV |
| `js/` | JS URLs, downloaded JS, endpoints, secret findings |
| `params/` | GF/arjun/unfurl parameter outputs |
| `fuzzing/` | ffuf results and custom wordlist |
| `vulns/` | nuclei, dalfox, CORS, SSL/testssl, takeover findings, `basic_*` checks |
| `vulns/sqli/` | Error-based + time-based + optional sqlmap output |
| `vulns/ssrf/` | OAST callbacks fired + IMDS/localhost probe results |
| `vulns/jwt/` | Tokens observed + jwt_tool output + alg/kid analysis |
| `vulns/graphql/` | Introspection dumps + graphql-cop output |
| `vulns/oauth/` | `redirect_uri` bypass candidates |
| `vulns/ssti/` | SSTI confirmation candidates |
| `vulns/nosql/` | NoSQL operator-injection candidates |
| `vulns/proto_pollution/` | Client-side prototype-pollution canary hits |
| `vulns/cve/` | Detected-tech-keyed nuclei CVE correlation |
| `vulns/deep/` | Deep validation checks (when `--deep` is enabled) |
| `vulns/ai_active/` | AI-generated active validation (when `--ai-active`) |
| `validate/` | Response-diff XSS, IDOR candidates, race-probe output |
| `checklist/` | Manual hunting files |
| `diffs/` | New findings when `-d` is enabled |
| `reports/` | `report_*.md`, `report_*.html`, `findings.sarif`, `findings.jsonl`, `attack_chains.md` + optional AI outputs |

## Webhook Notifications

Paintest auto-detects webhook type from `WEBHOOK_URL`:

- Discord: `discord.com` or `discordapp.com`
- Slack: `hooks.slack.com`
- Telegram: `api.telegram.org`

During a scan it sends:

- Start notification
- One progress notification per phase with percentage
- Final summary with host, severity, basic-check, and optional AI-active counts

If delivery fails, the local terminal prints the HTTP code and curl return code.

## Phases

1. `passive_recon`
2. `github_recon`
3. `subdomain_enum`
4. `asn_expand`
5. `port_scan`
6. `web_probe`
7. `favicon_pivot`
8. `cloud_recon`
9. `url_discovery`
10. `api_spec_hunt`
11. `custom_wordlist`
12. `dir_fuzz`
13. `js_analysis`
14. `vuln_scan`
15. `cve_correlate`
16. `sqli_scan`
17. `ssrf_verify`
18. `jwt_scan`
19. `graphql_scan`
20. `oauth_scan`
21. `ssti_scan`
22. `nosql_scan`
23. `proto_pollution_scan`
24. `deep_checks` (only active in `--deep`)
25. `xss_validate`
26. `idor_probe` (requires `AUTH_HEADER`/`AUTH_COOKIE`)
27. `race_probe` (opt-in via `checklist/race_targets.txt` or `--deep`)
28. `param_mining`
29. `auth_surface`
30. `chain_findings`
31. `ai_active` when `--ai-active` is enabled
32. `diff`
33. `report`
34. `ai_triage` when `-ai` is enabled

## Troubleshooting

Check syntax:

```bash
bash -n paintest.sh
bash -n install.sh
```

Check config loading:

```bash
bash -c 'source "$HOME/.recon.conf"; echo "${WEBHOOK_URL:+webhook configured}"'
```

Test a Discord webhook directly:

```bash
curl -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"paintest webhook test"}'
```

More help is in [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

## Legal

This project is for authorized security testing only. You are responsible for permission, scope, rate limits, disclosure rules, and local law.

## License

Paintest is released under the MIT License. See [`LICENSE`](LICENSE) for the full text.
