# AIXSEC-X 4.2 — Baseline-first ZAP and evidence pipeline

The default `run()` path now executes a configured baseline before consulting
Ollama. The model chooses follow-up actions; it cannot insert arbitrary findings,
set severity, or mark an alert confirmed in the final report.

```text
Baseline → Evidence Store → Inventory / Knowledge Graph → AI Planner
                    ↑                                  ↓
                    └──── policy-aware executors ───────┘
Evidence Store → deterministic validators → Finding Ledger → Report
```

## Starting a scan

Install ZAP on the same machine that runs AIXSEC-X. Point to its executable,
not a shell command or a daemon URL. The distribution must include Automation
Framework, Spider, Passive Scan Rules, Report Generation and Import/Export.
AJAX Spider additionally needs the AJAX/Selenium add-ons and a supported headless
browser. OpenAPI import needs the OpenAPI add-on. Active rules must be installed.

```bash
export WEBX_TARGETS="https://your-authorized-target.example"
export WEBX_SCAN_BACKEND=zap
export WEBX_ZAP_EXECUTABLE=zaproxy  # Kali Linux
export WEBX_AUTO_EXEC=ask
export WEBX_ZAP_TIMEOUT=300
export WEBX_PIPELINE_MAX_SECONDS=900
python3 agent.py
```

On Kali Linux, install the package with `sudo apt install zaproxy` and check
`zaproxy -version`. With `WEBX_ZAP_EXECUTABLE` unset, Linux discovery tries
`zaproxy`, then `zap.sh` on PATH, then `/usr/bin/zaproxy` and
`/usr/share/zaproxy/zap.sh`. Custom executable overrides are respected; remove
any old macOS override before running on Kali. The Linux launcher runs with
`-cmd -dir <private-home> -autorun <plan>` and needs no desktop display for the
baseline scan. AJAX Spider separately requires a working headless browser.
For an upstream archive, set `WEBX_ZAP_EXECUTABLE=/opt/ZAP/zap.sh` to its actual
installation path. See the [Kali ZAP package documentation](https://www.kali.org/tools/zaproxy/).

On macOS, the default launcher also discovers `/Applications/ZAP.app` or
`~/Applications/ZAP.app`. You can explicitly select the app-bundle launcher:

```bash
export WEBX_ZAP_EXECUTABLE="/Applications/ZAP.app/Contents/MacOS/ZAP.sh"
```

For the macOS app bundle, the adapter invokes its bundled Java and ZAP JAR
in headless CLI mode (512 MB heap), with a separate home directory for each scan.
It does not depend on the app launcher script, and an open GUI session is not
interrupted. Other/custom launchers keep their normal command line. The adapter
does not remove quarantine or change Gatekeeper settings. If macOS blocks the
Java runtime itself, resolve the installation/OS approval before scanning.

Choose an existing executable path for your installation. A scan gets a fresh
ZAP home/session and a private artifact directory. Add-ons installed only in a
user's old ZAP home are not inherited; provision the required add-ons in the
ZAP distribution. This release does not download ZAP/add-ons or provision Docker.
For batch operation, `WEBX_AUTO_EXEC=all` replaces per-tool approval; the separate
active-scan, sqlmap and extraction policies still apply.

`WEBX_SCAN_BACKEND`:

| Value | Behavior |
|---|---|
| `auto` (default) | ZAP if executable is available, otherwise a single HTTP observation per configured target; fallback coverage stays partial |
| `zap` | ZAP spider and passive scan; missing executable is an error, no silent alternate scan |
| `wapiti` | Optional Wapiti baseline before the model, automatic exploitation disabled |
| `http` | GET observation without following redirects; not a full vulnerability scan |
| `none` | No baseline; coverage explicitly says not_run |
| `legacy` | Explicit compatibility mode for the old Wapiti-gated agent loop |

Use `WEBX_PLANNER_ENABLED=0` to collect the baseline, validate supported facts and
produce a report without making any Ollama request. Existing Ollama model and
phase timeout variables remain in effect when the planner is enabled. A model
failure preserves evidence and coverage; it never turns a scan summary into a
vulnerability. Each new `run()` starts a separate evidence/ledger session.
The `--recon` preflight output is not reused as evidence in that new session.

## Additional discovery and targeted active scanning

```bash
export WEBX_ZAP_AJAX=1
export WEBX_ZAP_OPENAPI_FILE=/absolute/path/to/bundled-openapi.json
export WEBX_ALLOW_ACTIVE_SCAN=1
export WEBX_ZAP_ALLOWED_RULES=40018
```

The OpenAPI file must be local JSON, with bundled internal references. External
`$ref`s and cross-origin servers are rejected before launching ZAP. The target
origin is fixed by the dispatcher and plan; auth URLs must use the same origin.
AJAX is opt-in because it starts a browser and can exercise application actions.

The planner may call `zap_active_scan(url, rule_ids, auth_context)` only with rule
IDs allowed by the operator. The generated policy turns every rule off and then
enables the requested IDs at low strength. Select installed rule IDs from the
[ZAP alert catalog](https://www.zaproxy.org/docs/alerts/). A broad category such as
XSS can require several different rules/add-ons; the adapter does not claim
complete category coverage simply because the scan ran.

The baseline does not run active scan. Both baseline and active scan pass through
existing scope and auto-exec approval checks. ZAP context limits scope; browser
subresources/redirect behavior is not a network egress firewall.

## Authentication

Set `WEBX_ZAP_AUTH_FILE` to an operator-owned JSON profile map and
`WEBX_ZAP_AUTH_CONTEXT=user_A`. See `examples/zap/auth-profiles.json`.
Profiles bind identities to an origin and contain ZAP AF authentication/session
settings. Credentials are read from named environment variables, never from model
arguments. Profiles require both logged-in and logged-out regexes. Supported
methods: form, JSON, HTTP and browser. Cross-origin login/SSO and script auth are
not supported by this adapter.

The plan exists with mode 0600 while ZAP runs and is removed in `finally`. Reports,
ZAP logs and home/session artifacts remain in a directory created with mode 0700;
these raw artifacts may contain credentials or application data. Protect them.
Public evidence metadata omits raw headers/bodies; it contains hashes and artifact
references. The artifact directory is excluded from Git.

A requested user identity is not proof of authenticated coverage. The adapter uses
ZAP authentication statistics: absent logged-in evidence, or any logged-out
observations, makes auth coverage unverified and the scan partial. Test regexes
and the profile in ZAP before using them here. This conservative aggregate check
does not assert that every request was authenticated.

ZAP profiles and AIXSEC HTTP auth contexts are separate sessions linked by name
and origin. Replay under `user_A` requires configuring and logging in an AIXSEC
`user_A` context as well. ZAP cookies are never silently copied between identities.

## Evidence and findings

New tools:

- `zap_baseline`: spider, optional AJAX/OpenAPI, passive queue wait and artifacts.
- `zap_active_scan`: bounded selected-rule scan.
- `evidence_status`: public evidence, coverage and validation states.
- `evidence_validate(evidence_id)`: run a deterministic validator using stored facts.
- `evidence_replay(evidence_id)`: send the captured request using an isolated
  anonymous session or same-named AIXSEC auth context. Redirects are disabled.
  Returns response status/body hash comparison, not an exploitability verdict.

ZAP alert instances normalize to rule/category, URL, method, parameter, requested
auth context, scanner severity/confidence, scan ID, request/response hashes and
artifact reference. Wapiti structured results, manual SQLi positives and sqlmap
injection-point blocks also create candidates. ffuf/HTTP/auth/workflow/SAST outputs
remain observations or hypotheses unless a supported validator confirms them.
All tool results have private raw artifacts and an observation record.

Deduplication includes category, URL, method, parameter and identity. Repeating an
alert does not increase confidence or confirm it. Graph nodes retain evidence
references and validation state so planning can follow unresolved candidates.

The first validator set confirms only narrowly defined missing-header facts:
CSP on successful HTML responses (ZAP 10038) and HSTS on successful HTTPS responses
(ZAP 10035), with captured request/response headers under anonymous context.
SQLi, XSS, authorization, CORS and business-logic alerts remain candidates needing
rule-specific verification. Scanner confidence, reflection alone, identical bodies,
HTTP 200 or an LLM assertion cannot confirm these vulnerabilities. Authenticated
header alerts remain unconfirmed until identity-specific validation is available.
A replay with identical content still does not prove an authorization violation.

`risk_level` is derived only from confirmed findings. `candidate_risk_level`
reports the strongest scanner candidate separately. `UNKNOWN` with zero confirmed
findings is not a safety verdict. `coverage` reports complete/partial/timeout/error,
auth state, discovered URL count, requested active rules and artifact locations.
`complete` refers to the configured AF execution, not exhaustive site coverage.
Warnings, malformed reports and incomplete authentication cannot report complete.

## Policy and budgets

| Setting | Default | Meaning |
|---|---:|---|
| `WEBX_ALLOW_ACTIVE_SCAN` | 0 | Permit targeted ZAP active scan and evidence replay |
| `WEBX_ALLOW_SQLMAP` | 0 | Permit sqlmap only for an existing SQLi candidate on that endpoint |
| `WEBX_ALLOW_CONTENT_DISCOVERY` | 1 | Permit ffuf discovery, still subject to normal approval |
| `WEBX_ALLOW_EXTRACTION` | 0 | Separate permission for blind SQLi data extraction |
| `WEBX_FFUF_RATE` / `WEBX_FFUF_THREADS` | 5 / 2 | ffuf request rate and concurrency |
| `WEBX_PIPELINE_MAX_ACTIONS` | 30 | Session action cap |
| `WEBX_PIPELINE_MAX_SECONDS` | 900 | Session scheduling deadline; remaining time clamps tool/LLM timeouts |
| `WEBX_PIPELINE_MAX_REQUESTS` | 5000 | Estimated request budget for scheduling, **not** a strict network request counter |
| `WEBX_ZAP_TIMEOUT` | 300 | Process wall-clock budget; stop owned process group on expiry |
| `WEBX_ZAP_PHASE_MINUTES` | 2 | Per-phase ZAP limit |
| `WEBX_ZAP_MAX_URLS` | 200 | Planning cost estimate only; does not cap OpenAPI imports or spider URLs (compatible with older bundled OpenAPI add-ons) |
| `WEBX_ZAP_DELAY_MS` | 200 | Delay for active scanner, one thread per host |
| `WEBX_EVIDENCE_DIR` | .aixsec-evidence | Private run artifacts |

Tools that make multiple requests may exceed cost estimates. Existing Python
multi-request executors and blocked socket operations are not a hard real-time
scheduler; process termination has a short cleanup grace. ZAP reports requested
rules, not a fabricated list of rules proven to have tested every endpoint.
Credential brute force is not introduced in this release and is not enabled by
content-discovery permission. Wapiti auto-exploitation is disabled in the new path.

The Phase 4 `/autonomy` runtime remains a separate goal/checkpoint runner. Its tool
execution uses the same dispatcher policy and records evidence, but its old
journal replay reconstructs state without sending HTTP. Use `evidence_replay` for
an actual HTTP replay. The new baseline-first loop uses evidence artifacts rather
than claiming to resume a running ZAP process from an old Phase 4 checkpoint.

## Validation

Run `python3 -m unittest discover`. Tests include generated AF plans, report parsing,
scope/auth checks, explicit active-rule policies, process timeout cleanup,
evidence provenance/deduplication, deterministic validation, and baseline-before-LLM
integration. They use fixtures/fake scanner processes; they do not replace testing
against an installed ZAP and an authorized test application.

References: [Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/),
[report template](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/),
[authentication](https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/).
