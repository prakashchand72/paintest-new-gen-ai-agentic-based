# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Shape

Paintest v6 is a **Bash pentesting pipeline** organized as an orchestrator (`paintest.sh`) plus per-concern libraries under `lib/`. There is no build system, package manager, or test suite — edits go directly into `paintest.sh`, `install.sh`, or one of the `lib/*.sh` files.

```
paintest.sh         orchestrator: arg/config parsing, PHASES list, main loop
lib/common.sh       logging, notify, webhook, scope, phase checkpoint
lib/engine.sh       curl/httpx/nuclei proxy wrappers, adaptive rate limiting, URL dedup
lib/recon.sh        passive/subdomain/port/web/url/js/fuzz/params + github/cloud/asn/favicon/api-spec
lib/vuln.sh         basic + nuclei + SQLi + SSRF + JWT + GraphQL + OAuth + SSTI + NoSQL + proto-pollution + CVE correlation
lib/validate.sh     response-diff XSS, IDOR numeric-swap, race-condition probe, attack-chain stitcher, diff phase
lib/report.sh       Markdown report, SARIF export, standalone HTML, CVSS-ish scoring, curl PoC per finding
lib/ai.sh           AI triage + AI active validation (inert unless -ai / --ai-active)
```

## Common Commands

Syntax-check after edits (no linter or test runner):

```bash
for f in paintest.sh install.sh lib/*.sh; do bash -n "$f" && echo "OK $f"; done
```

Smoke-test webhook delivery without running a scan:

```bash
./paintest.sh --test-webhook
```

Debug trace a run:

```bash
bash -x ./paintest.sh -sd target.com 2>&1 | tee debug.log
```

Verify config loading outside of a scan:

```bash
bash -c 'source "$HOME/.recon.conf"; echo "${WEBHOOK_URL:+webhook configured}"'
```

Runtime mode flags: `-sd`, `-r`, `-d`, `-ai`, `--ai-active`, `--deep` (aliases `--aggressive`, `--lab`).

## Architecture

### Phase pipeline

`main()` iterates the `PHASES` array (`name:do_fn` pairs) and calls `run_phase` for each. `run_phase` records `<name>:done` to `$OUTPUT_DIR/.phase_state` on success — that file is the resume checkpoint. With `-r`, already-done phases are skipped; a phase that exits non-zero is **not** marked done, so it will re-run next time.

Phase order (see `PHASES` in paintest.sh): `passive_recon → github_recon → subdomain_enum → asn_expand → port_scan → web_probe → favicon_pivot → cloud_recon → url_discovery → api_spec_hunt → custom_wordlist → dir_fuzz → js_analysis → vuln_scan → cve_correlate → sqli_scan → ssrf_verify → jwt_scan → graphql_scan → oauth_scan → ssti_scan → nosql_scan → proto_pollution_scan → deep_checks → xss_validate → idor_probe → race_probe → param_mining → auth_surface → chain_findings → [ai_active] → diff → report → [ai_triage]`.

### Adding a phase

1. Define `do_my_phase()` in the relevant `lib/*.sh`, returning 0 on success.
2. Add `"my_phase:do_my_phase"` to the `PHASES` array in `paintest.sh` at the right dataflow spot.
3. `PHASE_TOTAL` is computed from `${#PHASES[@]}` automatically — no manual counter update.

### Intentional behaviors (do not "fix")

- **`set -uo pipefail` without `-e`** is deliberate. Individual tool failures must not abort the pipeline.
- **Config precedence `~/.recon.conf` → `.env` → script defaults**. `.env` loads *after* `~/.recon.conf`, so project-local `.env` intentionally overrides the user-global config.
- **AI code paths are inert unless `-ai` or `--ai-active` is passed.** No AI token is read or sent otherwise.
- **Proxy passthrough**: `HTTP_PROXY` routes all curl/httpx/nuclei/ffuf via the `*_p` wrappers in `lib/engine.sh`. Respect the wrappers when adding new calls so Burp tee keeps working.
- **Adaptive rate limiting** (`adaptive_probe` in `lib/engine.sh`) halves `RATE`/`THREADS` when the target returns ≥2/5 429-or-5xx. Set `PAINTEST_ADAPTIVE=0` to disable.
- **Webhook type is auto-detected from `WEBHOOK_URL`**: Discord, Slack, and Telegram each need a different payload shape.
- **Destructive tools are opt-in**: `sqlmap` handoff only runs if `SQLMAP_RISK` is set; `jwt_tool` is only invoked when tokens are actually observed; `--ai-active` is bounded by `AI_ACTIVE_MAX_TESTS`.
- Missing optional tools should be reported via `have`/`warn` and skipped, not treated as fatal.

### Output layout

Each run writes to `recon_<target-safe>_<mode>_<timestamp>/` (gitignored as `recon_*_single_*/` and `recon_*_sd_*/`). Key subdirectories:

```
recon/{github,cloud,asn,apispec,favicon}/
subdomains/, ports/, web/, js/
vulns/{sqli,ssrf,jwt,graphql,oauth,ssti,nosql,proto_pollution,cve,deep,ai_active}/
validate/{race/}
reports/        Markdown + SARIF + standalone HTML + findings.jsonl
diffs/          delta vs. PREV_RUN
checklist/      manual hunting hints
```

`reports/findings.jsonl` is the canonical normalized finding stream — all export formats (SARIF, HTML, AI prompt) read from it. If you add a new finding class, emit it via `_emit` in `do_report`.

### Scope filtering

`scope.txt` (or `$SCOPE_FILE`) contains **literal substring patterns**, not globs or regex. No comment syntax — every non-empty line is matched as a string.

## Authorization Boundary

This is offensive-security tooling. Changes that weaken scope filtering, remove bounded caps (`AI_ACTIVE_MAX_TESTS`, `SQLMAP_RISK` gate, rate/thread limits), or broaden targets beyond the provided scope file should be flagged explicitly to the user, not made silently. SSRF verification only fires OAST callbacks to `$CALLBACK_DOMAIN`; never change the default away from user-owned infrastructure.

## Further reading

- `README.md` — user-facing usage and install steps
- `docs/ARCHITECTURE.md` — phase/data-flow diagram (v6)
- `docs/TROUBLESHOOTING.md` — known failure modes
