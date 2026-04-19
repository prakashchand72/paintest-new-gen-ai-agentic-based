# Paintest Recon Framework

Paintest is a single-file Bash reconnaissance pipeline for authorized bug bounty and pentest work. It chains common recon tools into resumable phases, writes plain text/JSONL outputs, and sends Discord, Slack, or Telegram progress notifications.

> Use only on targets where you have explicit permission.
> No automated scanner can guarantee vulnerability discovery. Paintest improves coverage and repeatability, but exploitable findings still depend on target behavior, authentication, templates, wordlists, and manual validation.

## Features

- Resumable scans with `.phase_state` checkpoints
- Single host mode or full subdomain discovery with `-sd`
- Diff mode for repeat scans with `-d`
- Discord, Slack, and Telegram webhook notifications
- Optional AI triage with `-ai`; no AI token is used unless this flag is set
- Optional AI active validation with `--ai-active` for bounded AI-generated payload candidates
- Per-phase progress notifications with percentage updates
- Scope filtering through `scope.txt` or `SCOPE_FILE`
- Authenticated recon through `AUTH_HEADER` and `AUTH_COOKIE`
- Response-hash live host deduplication
- URL normalization and parameter extraction
- JS endpoint and secret discovery
- Basic vuln checks for insecure cookies, missing security headers, server/version disclosure, extra open ports, legacy TLS, TLS name mismatch, missing SRI, host header injection, dangerous HTTP methods, directory listing, mixed content, and HTTP cleartext exposure
- Markdown report plus manual hunting checklist
- Deep mode for real websites and localhost CTF targets

## Detection Expectations

Paintest is designed to maximize recon coverage in a test environment, not to guarantee findings. It is strongest at finding exposed services, forgotten files, known-template issues, reflected XSS candidates, CORS mistakes, JS secrets, takeover candidates, and interesting endpoints. Logic bugs, authorization flaws, chained exploits, and authenticated workflows still require manual testing.

For authorized real targets or localhost CTFs, run `--deep`. This enables broader nuclei template coverage, deeper crawling, larger fuzzing, and validation probes for real-world bug classes like reflected XSS, SQL errors, LFI, open redirects, debug exposure, GraphQL exposure, admin panels, and known vulnerable CTF apps.

## Repository Layout

| Path | Purpose |
|---|---|
| `paintest.sh` | Main recon pipeline |
| `install.sh` | Installs dependencies and prepares `~/.recon.conf` |
| `recon.conf.example` | Default persistent config template |
| `scope.txt.example` | Example scope filter patterns |
| `docs/ARCHITECTURE.md` | Phase/data-flow overview |
| `docs/TROUBLESHOOTING.md` | Common fixes and debugging commands |

## Tools Used

| Phase | Tools |
|---|---|
| Passive recon | `whois`, `dig`, `curl`, `jq`, crt.sh, Anubis |
| Subdomains | `subfinder`, `assetfinder`, `amass`, `findomain`, `dnsx`, `gotator` |
| Port scanning | `naabu`, `nmap` |
| Web probing | `httpx`, `wafw00f`, `gowitness` |
| URL discovery | `gau`, `waybackurls`, `katana`, `uro` |
| Fuzzing | `ffuf`, SecLists |
| JS analysis | `subjs`, `jsluice`, `trufflehog`, `gitleaks` |
| Vulnerability checks | `nuclei`, `dalfox`, `testssl.sh`, `subjack`, `qsreplace` |
| Parameter mining | `gf`, `unfurl`, `arjun` |
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
| `subdomains/` | Passive, brute-forced, resolved, and scoped hosts |
| `ports/` | `naabu` and `nmap` output |
| `web/` | Live hosts, httpx JSONL, discovered URLs |
| `js/` | JS URLs, downloaded JS, endpoints, secret findings |
| `params/` | GF/arjun/unfurl parameter outputs |
| `fuzzing/` | ffuf results and custom wordlist |
| `vulns/` | nuclei, dalfox, CORS, SSL/testssl, takeover findings, and `basic_*` checks |
| `vulns/deep/` | Deep validation checks when `--deep` is enabled |
| `vulns/ai_active/` | AI-generated active validation candidates and confirmed evidence |
| `checklist/` | Manual hunting files |
| `diffs/` | New findings when `-d` is enabled |
| `reports/` | Final Markdown report plus optional `ai_input_*`, `ai_active_*`, and `ai_triage_*` outputs |

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
2. `subdomain_enum`
3. `port_scan`
4. `web_probe`
5. `url_discovery`
6. `custom_wordlist`
7. `dir_fuzz`
8. `js_analysis`
9. `vuln_scan`
10. `deep_checks`
11. `param_mining`
12. `auth_surface`
13. `ai_active` when `--ai-active` is enabled
14. `diff`
15. `report`
16. `ai_triage` when `-ai` is enabled

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
