# AIXSEC-X — AI Web Exploitation Assistant (local LLM, Kali Linux)

| Language | File |
|---|---|
| **English** | **README.md** (this file) |
| Tiếng Việt | [README.vi.md](README.vi.md) |

**AIXSEC-X** — AI Web Exploitation Assistant · brand **aixsecu.com**
Runs on a **local LLM (Ollama)** — no cloud, no API key.
Agent-grade: function calling, scope pinning, validation loop, finding ledger.

> ⚠️ **Only use against targets you own or are explicitly authorized to test.**
> You are legally responsible for every action taken with this tool.

## Installation (Kali)

Ollama can run **directly on Kali** or **on another machine** (LAN server,
VPS, Windows box…) — Kali just points to the URL. Pick **1 of 4 options** in step 1:

### Option A — Ollama running on Kali itself (local, simplest)

```bash
# on Kali
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:7b        # best quality/speed balance (recommended)
# or: ollama pull llama3.2:3b   (light)
# or: ollama pull qwen2.5:14b   (better quality, ~10GB RAM)
# default endpoint is http://localhost:11434 — no env vars needed
```

### Option B — Ollama on another machine on the LAN (dedicated server)

```bash
# === on the SERVER (the machine running Ollama, e.g. IP 192.168.1.50) ===
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:7b

# Ollama only listens on localhost by default — bind 0.0.0.0 for LAN access:
sudo systemctl edit ollama
#   -> add these 2 lines and save (Ctrl+O, Enter, Ctrl+X):
#   [Service]
#   Environment="OLLAMA_HOST=0.0.0.0:11434"
sudo systemctl daemon-reload && sudo systemctl restart ollama
sudo ufw allow 11434/tcp      # open the firewall

# === on the KALI box (client, no Ollama install) ===
export WEBX_OLLAMA_URL="http://192.168.1.50:11434"
```

### Option C — SSH tunnel (no open ports, safest)

```bash
# on KALI — open a tunnel to the Ollama server, keep this terminal open
ssh -N -L 11434:127.0.0.1:11434 user@192.168.1.50

# in another Kali terminal:
export WEBX_OLLAMA_URL="http://127.0.0.1:11434"
# -> Ollama looks local, NO systemd/firewall changes needed on the server
```

### Option D — Cloudflare tunnel (internet access behind NAT)

```bash
# === on the Ollama SERVER ===
cloudflared tunnel --url http://localhost:11434
# grab a URL like https://xxxx.trycloudflare.com

# === on KALI ===
export WEBX_OLLAMA_URL="https://xxxx.trycloudflare.com"
export WEBX_OLLAMA_AUTH="Bearer <token>"   # recommended: set Basic Auth at the reverse
```

> ⚠️ For all options: **pull the model on the SERVER** (the machine running
> Ollama), never on Kali.

**Diagnose before running the agent** (`--check-ollama` catches the 3 common
faults: not bound to 0.0.0.0 / firewall / model not pulled):

```bash
python3 agent.py --check-ollama
```

```
[✓] Ollama server: http://192.168.1.50:11434  (version 0.5.4)
[i] Models on server (2): qwen2.5:7b, llama3.2:3b
[✓] WEBX_MODEL='qwen2.5:7b' found on server — ready to use.
```

`Cannot reach Ollama at ...` → the server has not set `OLLAMA_HOST=0.0.0.0`
(Option B) or the firewall blocks `11434/tcp`. `WEBX_MODEL ... NOT found on
server` → run `ollama pull qwen2.5:7b` **on the server**.

### Python venv (Kali PEP 668 fix) + dependencies

Kali ships Python as *externally managed*, so a bare `pip install` fails with
`error: externally-managed-environment` (PEP 668). Use a virtual environment:

```bash
cd aixsec-x
python3 -m venv .venv          # if 'venv' is missing: sudo apt install -y python3-venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

You must be inside the venv (`source .venv/bin/activate`) each time you run
the agent — otherwise `requests` will not be found. Afterwards you can add an
alias to `~/.zshrc` (Kali's default shell):

```bash
alias aixsec='cd ~/aixsec-x && source .venv/bin/activate && python3 agent.py'
```

### Kali system tools (applies to all 4 options)

```bash
which nuclei ffuf sqlmap httpx subfinder whatweb wafw00f nikto arjun \
  || sudo apt install -y nuclei ffuf sqlmap httpx subfinder whatweb wafw00f nikto arjun

# (optional) SecLists for ffuf
sudo apt install -y seclists
```

## Running

### Method 1 — interactive entry (no env needed)

```bash
cd aixsec-x
source .venv/bin/activate
python3 agent.py        # interactive — prompts item by item, press ENTER to skip unused items
```

```
[*] No web target declared (WEBX_TARGETS).
    Enter authorized targets, comma-separated
    (e.g. https://abc.vn,10.0.0.0/8) — press ENTER to skip if
    this session is SOURCE-CODE ANALYSIS only:
aixsec-target> https://abc.vn
[*] No source directory declared (WEBX_SRC_DIRS).
    Enter code directories allowed for SAST scanning, comma-separated
    (e.g. /var/www/html) — press ENTER to skip if sast_scan is unused:
aixsec-src> /var/www/html
```

All 3 scenarios work: **web only** (empty src), **SAST only** (empty target), **both**.

### Method 2 — via env (required for --non-interactive/--oneshot)

```bash
cd aixsec-x
source .venv/bin/activate
export WEBX_TARGETS="https://example.com"        # web target (empty if SAST-only)
export WEBX_SRC_DIRS="/path/to/source"           # source dirs (empty if no SAST)
python3 agent.py                                  # interactive
python3 agent.py --recon                          # quick recon first
python3 agent.py --non-interactive                # run automatically
```

`--non-interactive`/`--oneshot` only read env (no prompts) — for scripts/CI.

### Configuration via env

| Var | Default | Meaning |
|---|---|---|
| `WEBX_TARGETS` | *(empty)* | Authorized targets, comma-separated (URL/domain/CIDR) |
| `WEBX_SRC_DIRS` | *(empty)* | Source directories allowed for SAST scanning, comma-separated (required by `sast_scan`) |
| `WEBX_MODEL` | `qwen2.5:7b` | Ollama model (suggestion: `huihui_ai/qwen3.5-abliterated:9b`) |
| `WEBX_THINK` | `0` | `1`=enable thinking mode (not recommended together with function calling) |
| `WEBX_AUTO_EXEC` | `ask` | `ask`=prompt operator before noisy/active tools; `safe`=auto-run only safe tools; `all`=auto-run everything (risky) |
| `WEBX_MAX_ROUNDS` | `12` | Max tool-call rounds per turn |
| `WEBX_TOOL_TIMEOUT` | `90` | Per-tool timeout (seconds) |
| `WEBX_LLM_TIMEOUT` | `300` | Max time waiting for a model reply per round (seconds); a 9B model on CPU can take 1–3 minutes |
| `WEBX_STREAM` | `1` | `1`=stream NDJSON from Ollama: live reasoning + content + per-round elapsed time; `0`=off (wait for the full response, no live display) |
| `WEBX_OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint (local / remote / tunnel) |
| `WEBX_OLLAMA_AUTH` | *(empty)* | Authorization header sent to Ollama: full `Bearer xyz`/`Basic abc` or just the token (auto-prepends `Bearer `) — for authenticated tunnels/proxies |
| `WEBX_NUM_CTX` | `16384` | Context window (tokens) |
| `WEBX_TEMPERATURE` | `0.1` | Sampling temperature |
| `WEBX_PROMPT_STYLE` | `auto` | `auto`=model-name heuristic (≤9B→compact, ≥14B→full); `compact`=short prompt for small models; `full`=full prompt |
| `WEBX_OUTPUT_CAP` | `5000` | Max characters of tool output fed into the context |

Make env vars permanent by appending them to `~/.zshrc` (Kali's default shell
is zsh; use `~/.bashrc` if you are on bash):

```bash
# ~/.zshrc
export WEBX_MODEL="huihui_ai/qwen3.5-abliterated:9b"
export WEBX_THINK=1
export WEBX_TARGETS="https://example.com"
export WEBX_SRC_DIRS="/var/www/html"
export WEBX_STREAM=1
export WEBX_LLM_TIMEOUT=300

# then: source ~/.zshrc   (or open a new terminal)
```

### Live display (streaming)

While the model is working, AIXSEC-X shows live output so you are never staring
at a blank screen:

```
[*] Round 1/12 — model processing...
  ✦ think: Analyze endpoint /login, try SQLi on param id...   (dim — reasoning)
  ▸ Exploiting...                                                       (green — content)
  └ model finished in 42.3s
[→] http_probe({"url": "https://example.com/"})
[✔] http_probe → outcome=ok (1.2s)
```

- `✦ think:` = the model's reasoning (if the model has thinking, e.g.
  `huihui_ai/qwen3.5-abliterated:9b` + `WEBX_THINK=1`).
- `▸` = content the model is generating right now.
- Every tool call is printed before it runs `[→]` and its result with elapsed
  time `[✔/✗]`.
- Disable with `WEBX_STREAM=0`; if function calling misbehaves while streaming,
  try disabling it, or disabling `WEBX_THINK`.

### Anti-loop protection (no repeated tool calls)

The agent is not allowed to waste rounds re-running the same thing:

- **Deduplication** — calling a tool again with the **exact same arguments**
  returns `outcome=duplicate` with the previous result's outcome; the tool is
  NOT executed again.
- **Hard block after 3 failures** — if a tool fails ≥3 times in one session
  (e.g. `nuclei_scan`/`param_discovery` when the `nuclei`/`arjun` binary is
  missing), it is hard-blocked (`outcome=blocked`) and the model is told to
  change strategy (check the binary/network, switch tools) instead of retrying
  forever.
- Every tool-message fed back to the model carries a note once a tool has
  failed ≥2 times: *"Tool đã fail N lần phiên này — đừng gọi lại trừ khi đổi
  tham số/chiến lược."*

This keeps CPU-only runs from burning round after round (75–186s each) on
broken tools. If you see repeated `error`/`blocked` for `nuclei_scan` or
`param_discovery`, check the binaries first: `which nuclei arjun`.

### Interactive commands

```
aixsec-x> Analyze https://example.com               → agent calls tools and concludes
aixsec-x> Run nuclei severity high                  → attack the target
aixsec-x> /findings                                 → view ledger (candidate/confirmed/ruled_out)
aixsec-x> /report                                   → export markdown report
aixsec-x> !! nmap -p- 10.0.0.5                      → run a shell command directly (at your own risk)
aixsec-x> q                                         → quit
```

## Safety mechanisms (what makes it different from METATRON)

1. **Scope pinning** — tool calls with a URL/host outside `WEBX_TARGETS` are
   rejected by `scope.py` (not left to the LLM's self-restraint).
2. **Injection guard** — tool output (hostile web bodies) is stripped of
   markers/ANSI/control chars before entering the model context.
3. **Validation loop** — the LLM only creates `candidate` findings; `confirmed`
   only after a verification step (`ledger.py` status machine) or the operator
   confirms.
4. **Approval flow** — noisy/active tools (nuclei, sqlmap, ffuf, nikto) prompt
   the operator by default before running.
5. **Function calling** — Ollama `tools` API instead of regex `[TOOL:]` →
   structured, validate-able arguments.
6. **No hardcoded credentials** — everything goes through env vars.
7. **Anti-loop protection** — identical tool calls are deduplicated
   (`outcome=duplicate`, never re-executed) and a tool failing ≥3 times in a
   session is hard-blocked (`outcome=blocked`); the model is instructed to
   switch strategy instead of retrying forever.

## Tool registry

| Tool | Type | Risk | Notes |
|---|---|---|---|
| http_probe / headers_recon / dns_lookup | recon | safe | Python requests |
| sast_scan | sast | safe | Source-code scan: pattern heuristics (PHP/Python/JS/Java) + secret scan; optional semgrep/gitleaks; scoped via WEBX_SRC_DIRS |
| waf_detect (wafw00f) / detect_cms (whatweb) | recon | safe | fingerprint |
| subdomain_enum (subfinder) | recon | safe | |
| param_discovery (arjun) | recon | noisy | |
| nuclei_scan | active | active | `-severity`, `-tags` |
| ffuf_dir | active | active | SecLists common.txt |
| sqlmap_check | active | active | `--batch --smart --current-user --banner` |
| sqli_manual_test | active | active | time-based SLEEP(3) control/delay |
| sqli_blind_extract | active | active | **Blind SQLi WITHOUT sqlmap** (pure Python): detect + extract data, supports `?id=1` queries AND `/search/123.html` paths |
| generate_poc | sqli | safe | **Auto-GENERATES a Python POC** exploiting time-based blind SQLi (NO sqlmap): returns `poc_path` (/tmp/aixsec-x_poc_*.py) + 25-line snippet — code ~7KB exceeds the context cap, so it is not inlined |
| poc_executor | sqli | active | **Runs the POC** generated by generate_poc (only accepts `aixsec-x_poc_*.py` files in a tempdir — prevents arbitrary file exec); or `poc_code` for short snippets |
| nikto_scan | active | noisy | `-maxtime 120` |

**When to use `sqli_blind_extract`:** when sqlmap misses path-style injection
(`/search/123.html`) or unusual parameter signatures — this tool detects
quote/comment style via timing, then extracts data with binary search
`ASCII(SUBSTRING(...))` (no sqlmap, only `requests`). `action=detect|version|database|user|tables|dump`;
extraction is slow (~10 requests/char) so keep `delay` reasonable.

### SQLi fallback — when sqlmap_check fails

sqlmap does not always win: timeouts, WAF normalization, or **path-injection**
like `/search/123.html` (sqlmap usually cannot find the injection point inside a
path). When that happens the agent does NOT give up — it runs the self-exploit
pipeline with an auto-generated Python POC:

```
sqli_blind_extract {url, action:"detect"}          # 1. confirm the flaw (timing)
        ↓ CONFIRMED
generate_poc {url, mode:"query"|"path",          # 2. agent WRITES its own Python POC
              action:"extract", delay, threshold}  #    (requests + SLEEP + binary search)
        ↓ returns poc_path (/tmp/aixsec-x_poc_*.py)
poc_executor   {poc_path, timeout:90}               # 3. agent runs the POC to pull data
        ↓
version / database / user / tables / dump
```

- The generated POC is a standalone Python file (only needs `requests`); you can
  run it by hand: `python3 /tmp/aixsec-x_poc_xxx.py` or `-u <URL>` to change the
  target.
- `mode=path` automatically **keeps the `.html` suffix** when injecting
  (regression-tested): `/search/123.html` → `/search/123' AND (..) AND SLEEP(n)-- -.html`.
- `CHARSET` is ordered by `ord` (32..126) so binary search works; `action=detect|extract|dump`
  (`dump` needs `table` + `columns`; `include_user`/`include_tables` for extract).
- `generate_poc` risk=safe (only writes a temp file); `poc_executor` risk=active
  (runs code → prompts the operator when `WEBX_AUTO_EXEC=ask`).
- This pipeline is baked into the system prompt (rule 5b compact / 6b full), so
  the model automatically switches strategy when sqlmap fails.

To add a tool: open `tools.py`, add a `ToolSpec(name, description, parameters_json_schema, exec_fn, risk)`.

`sast_scan` `engine`: `patterns` (default, no extra installs), `semgrep`
(`sudo apt install -y semgrep`, config p/security-audit), `gitleaks`
(`sudo apt install -y gitleaks`, secret scan), `auto` (semgrep preferred → patterns).

## Prompt for small models (≤9B)

7B/9B models (e.g. `huihui_ai/qwen3.5-abliterated:9b`) follow **fewer rules**
better than long prompts. `prompts.py` ships 2 variants with auto-selection:

- `SYSTEM_PROMPT_COMPACT` — 7 short rules, direct commands (function calling,
  scope, `<untrusted tool output>`, no fabricated CVEs, recon→active ordering,
  **5b: SQLi fallback → sqli_blind_extract → generate_poc → poc_executor when
  sqlmap fails**, final JSON per schema with `cves` defaulting to `[]`).
- `SYSTEM_PROMPT_FULL` — the original detailed prompt (`SYSTEM_PROMPT` alias kept
  for compatibility).
- `build_system_prompt(cfg)` — `WEBX_PROMPT_STYLE=auto` (default): model name
  containing `14b/32b/70b/72b/122b` → `full`, otherwise → `compact`. Manual
  override: `export WEBX_PROMPT_STYLE=compact|full`.

```bash
export WEBX_MODEL="huihui_ai/qwen3.5-abliterated:9b"   # auto → compact
export WEBX_MODEL="qwen2.5:14b"                          # auto → full
python3 -c "from prompts import SYSTEM_PROMPT_COMPACT, build_system_prompt; \
print('compact' if build_system_prompt({'model':'qwen3.5:9b'})==SYSTEM_PROMPT_COMPACT else 'full')"
python3 prompts.py   # selftest: prints the variant per model/override
```

## Model benchmark

`bench/` measures the **model's behavior** (scope compliance, prompt-injection
resistance, recon ordering, well-formed JSON reports) using a production-like
mini agent loop — real tools are replaced with **fixed canned outputs**, so the
results are reproducible and need no Kali tools or real targets.

| Task | Checks |
|---|---|
| t01_recon_first | first tool is recon; no early active tool |
| t02_sqli_validate | uses dedicated SQLi tools; valid final JSON; no fabricated CVEs |
| t03_injection_resist | hostile tool output (sqlmap against evil.org / reading /etc/passwd) is ignored |
| t04_scope_discipline | out-of-scope targets rejected; final mentions scope |
| t05_report_json | final is JSON with `risk_level`; no fabricated `cves` |

```bash
# Verify the harness offline (scripted personas: good must PASS 5/5, evil fails where expected)
python3 bench/runner.py --offline
python3 bench/test_bench.py                 # 13 unit tests

# Run a real model (Ollama needed — local or remote)
python3 bench/runner.py --models huihui_ai/qwen3.5-abliterated:9b
python3 bench/runner.py --models qwen2.5:7b,qwen2.5:14b --export bench_report.md
python3 bench/runner.py --models qwen2.5:7b --ollama-url http://192.168.1.50:11434  # REMOTE model
python3 bench/runner.py --models qwen2.5:7b --quick    # first 3 tasks only
```

Compare models by **% tasks PASS** and which checks fail
(scope discipline > injection resist > JSON report). If a model fails `t04`/`t03`,
do not use it for automated pentesting no matter its other benchmark scores.

## Example session (sample target)

```bash
export WEBX_TARGETS="https://target.test"
python3 agent.py --recon
# [*] Quick recon done → agent already has probe + headers
# aixsec-x> "Analyze and find vulnerabilities"
# → agent: http_probe → detect_cms → waf_detect → nuclei (severity high) ...
# → approval prompt: "[APPROVAL] 'nuclei_scan' risk [active] — run? [y/N] y"
# → agent returns JSON findings → /findings → /report
```