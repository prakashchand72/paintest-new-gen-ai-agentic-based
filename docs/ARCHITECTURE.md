# Architecture

## Design Philosophy

- Single-file runtime: `paintest.sh` contains the scan pipeline.
- Output-first design: phases pass data through plain text, JSONL, and Markdown files.
- Resumable execution: completed phases are recorded in `.phase_state`.
- Tool-tolerant behavior: missing optional tools are reported and skipped where practical.
- Scope-aware output: discovered assets are filtered through `scope.txt` or `SCOPE_FILE`.

## Startup Flow

```text
load ~/.recon.conf
load .env if present
parse args
build output path
banner
start webhook notification
check tools
create output directories
run phases
optional AI active validation
final report
optional AI triage
final webhook notification
```

## Phase Flow

```text
1.  passive_recon      whois, dig, crt.sh, Anubis, favicon hints
2.  subdomain_enum     subfinder, assetfinder, amass, findomain, dnsx
3.  port_scan          naabu plus background nmap
4.  web_probe          httpx, response hash dedup, wafw00f, gowitness
5.  url_discovery      gau, waybackurls, katana, uro
6.  custom_wordlist    target-specific word extraction
7.  dir_fuzz           ffuf and high-value path checks
8.  js_analysis        subjs, jsluice, trufflehog, gitleaks
9.  vuln_scan          nuclei, dalfox, CORS, JWT, basic web/TLS/SRI/header checks, testssl, takeover checks
10. deep_checks         deep validation probes when --deep is enabled
11. param_mining       arjun
12. auth_surface       auth, sensitive file, OAuth, SSRF candidate extraction
13. ai_active          optional bounded AI-generated payload validation when --ai-active is enabled
14. diff               compare with the previous run when -d is enabled
15. report             Markdown report and manual checklist
16. ai_triage          optional provider API triage when -ai is enabled
```

## Checkpoints

Each successful phase appends one line to `.phase_state`:

```text
passive_recon:done
subdomain_enum:done
...
```

When `-r` is used, `run_phase` checks `.phase_state` and skips phases already marked done.

## Config Loading

`paintest.sh` loads config before argument parsing:

1. `~/.recon.conf`
2. Project `.env`, if present
3. Script defaults for unset values

Because `.env` loads after `~/.recon.conf`, project-local values can override persistent values.

AI settings are inert unless `-ai` or `--ai-active` is passed. `--ai-active` implies `-ai`, requests bounded JSON candidates from the configured provider, filters URLs through scope, and lets Paintest perform the actual validation.

## Data Flow

```text
subdomains/all.txt
        |
        v
web/live.txt -> web/live_dedup.txt -> web/all_urls.txt
        |                                |
        |                                v
        |                          params/*.txt
        |
        v
js/js_urls.txt -> js/content/ -> js/endpoints.txt -> js/jsluice_secrets.txt
        |
        v
vulns/*.txt, vulns/*.jsonl, vulns/deep/*, and vulns/ai_active/*
        |
        v
reports/report_<target>_<timestamp>.md and optional ai_* outputs
```

## Adding A Phase

1. Add a function:

```bash
do_my_phase() {
    log "Doing my thing"
    return 0
}
```

2. Register it in `main`:

```bash
run_phase "my_phase" do_my_phase
```

3. Update `PHASE_TOTAL` if the phase should count toward webhook progress. Optional AI phases are counted dynamically.
