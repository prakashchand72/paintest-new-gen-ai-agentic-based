# Troubleshooting

## PATH Not Refreshed After Install

Open a new terminal or run:

```bash
source ~/.bashrc
```

For Go tools:

```bash
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> ~/.bashrc
```

## Missing Tools

Run the installer again:

```bash
./install.sh
```

The scanner can still run with missing optional tools, but affected phases will be skipped or reduced.

## `naabu` Libpcap Error

```bash
sudo apt install libpcap-dev
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

## `gowitness` Fails Or Hangs

Install Chromium or Chrome:

```bash
sudo apt install chromium
```

If you see `unknown command "file" for "gowitness"`, you have gowitness v3 but an older code path was trying v2's CLI shape. Update paintest to the current main branch — v3 uses `gowitness scan file -f <list> -s <dir>`.

## Rate Limits Or 429 Responses

Lower concurrency and request rate in `~/.recon.conf`:

```bash
THREADS=10
RATE=10
```

For deep mode, tune:

```bash
DEEP_THREADS=25
DEEP_RATE=50
```

## Basic checks Report Empty Against WAF Target

If `vulns/basic_server_disclosure.txt` and `vulns/basic_missing_security_headers.txt` come back empty even though the target clearly has those issues, a WAF (Apache mod_security, Cloudflare, Imperva) is likely dropping the probe requests.

Paintest's default UA is a real Chrome string to avoid this, but some targets are stricter and require further tuning. Try overriding the UA/ID header in `~/.recon.conf`:

```bash
# Drop the bug-bounty marker header entirely for scans on very strict WAFs.
ID_HEADER=""
# Or use a specific UA that a given bug bounty program accepts.
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."
```

Then re-run the affected phases with `-r` or delete `vuln_scan:done` from `.phase_state` to force a re-scan:

```bash
sed -i '/^vuln_scan:done/d;/^report:done/d' recon_*/.phase_state
./paintest.sh target.com -r
```

## `port_scan` Hangs Forever

`naabu` top-1000 scans against CDN-fronted IPs (Cloudflare, Akamai, Fastly) stall because the CDN black-holes SYN probes. Paintest caps the phase at 10 minutes by default. To shorten for quick recon or extend for exhaustive scans:

```bash
PORT_SCAN_TIMEOUT=180 ./paintest.sh target.com   # 3 min cap
PORT_SCAN_TIMEOUT=1800 ./paintest.sh target.com  # 30 min cap
NMAP_TIMEOUT=900      ./paintest.sh target.com   # backgrounded nmap cap
```

Partial naabu results are kept even if the timeout fires.

## Webhook Not Firing

Confirm the config loads:

```bash
bash -c 'source "$HOME/.recon.conf"; echo "${WEBHOOK_URL:+webhook configured}"'
```

Test Discord manually:

```bash
curl -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"paintest webhook test"}'
```

Or test through Paintest:

```bash
./paintest.sh --test-webhook
```

If the scanner prints `HTTP 000`, it means curl did not receive an HTTP response. Increase timeouts in `~/.recon.conf`:

```bash
WEBHOOK_CONNECT_TIMEOUT=20
WEBHOOK_TIMEOUT=30
WEBHOOK_RETRIES=3
```

Debug webhook loading:

```bash
bash -x ./paintest.sh example.com 2>&1 | grep -i webhook
```

## `nuclei` Templates Not Updating

```bash
nuclei -update-templates
```

If that fails:

```bash
rm -rf ~/nuclei-templates
nuclei -update-templates
```

## `crt.sh` Timeout

This is common. The framework limits external API calls and continues with other sources.

## Resume Does Not Skip Phases

Check for a state file in the output directory:

```bash
ls -la recon_*_*/.phase_state
```

If `.phase_state` is missing or empty, the previous run stopped before a phase completed.

## SecLists Permission Error

Either run installer with sudo or skip SecLists and configure your own path:

```bash
./install.sh --skip-seclists
```

Then set:

```bash
SECLISTS="$HOME/seclists"
```

## macOS `timeout` Missing

```bash
brew install coreutils
alias timeout=gtimeout
```

## Debug Mode

```bash
bash -x ./paintest.sh -sd target.com 2>&1 | tee debug.log
```

## Deep Mode

Use only against targets you own or are explicitly authorized to test:

```bash
./paintest.sh --deep http://127.0.0.1:3000
./paintest.sh --deep https://target.example
```

Deep findings are written under `vulns/deep/` and included in the final report.

## AI Mode

AI is disabled unless you pass `-ai` or `--ai-active`.

For OpenAI-compatible triage:

```bash
export OPENAI_API_KEY="sk-..."
./paintest.sh -ai target.com
```

For Anthropic/Claude:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
AI_PROVIDER=anthropic ./paintest.sh -ai target.com
```

If AI mode warns that no token is configured, set `AI_API_TOKEN`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`.

`--ai-active` generates bounded payload candidates and validates them with the scanner. Start with a low cap:

```bash
AI_ACTIVE_MAX_TESTS=10 ./paintest.sh --ai-active target.com
```

AI outputs are written under `reports/` and active validation evidence is written under `vulns/ai_active/`.
