# AIXSEC-X 4.2 — Baseline-first ZAP and evidence pipeline

The default `run()` path now executes a configured baseline before consulting
Ollama. A deterministic active scheduler then tests captured request families; the model chooses further follow-up actions; it cannot insert arbitrary findings,
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
export WEBX_ZAP_TIMEOUT=600
# No session-wide deadline; configure per-tool timeouts instead.
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
export WEBX_ZAP_ALLOWED_RULES=all
```

The OpenAPI file must be local JSON, with bundled internal references. External
`$ref`s and cross-origin servers are rejected before launching ZAP. The target
origin is fixed by the dispatcher and plan; auth URLs must use the same origin.
AJAX is opt-in because it starts a browser and can exercise application actions.

The scheduler and planner may call `zap_active_scan(url, rule_ids, auth_context, request_id)` only with rule
IDs allowed by the operator. `all` resolves to the installed rule catalog exported by ZAP; a comma-separated list restricts the policy. The generated policy turns every rule off and then
enables the requested IDs at configurable strength (Medium by default). Select installed rule IDs from the
[ZAP alert catalog](https://www.zaproxy.org/docs/alerts/). A broad category such as
XSS can require several different rules/add-ons; the adapter does not claim
complete category coverage simply because the scan ran.

The baseline itself does not run active scan; the scheduler runs afterward, before the LLM. Both baseline and active scan pass through
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

## Policy and per-tool limits

| Setting | Default | Meaning |
|---|---:|---|
| `WEBX_ALLOW_ACTIVE_SCAN` | 1 | Permit targeted ZAP active scan and evidence replay |
| `WEBX_ALLOW_SQLMAP` | 0 | Permit sqlmap only for an existing SQLi candidate on that endpoint |
| `WEBX_ALLOW_CONTENT_DISCOVERY` | 1 | Permit ffuf discovery, still subject to normal approval |
| `WEBX_ALLOW_EXTRACTION` | 0 | Separate permission for blind SQLi data extraction |
| `WEBX_FFUF_RATE` / `WEBX_FFUF_THREADS` | 5 / 2 | ffuf request rate and concurrency |
| `WEBX_PIPELINE_MAX_ACTIONS` | retired | Ignored by the sequential pipeline |
| `WEBX_PIPELINE_MAX_SECONDS` | retired | Ignored; stages do not share a deadline |
| `WEBX_PIPELINE_MAX_REQUESTS` | retired | Estimates are reporting metrics only |
| `WEBX_ZAP_TIMEOUT` | 600 | Process wall-clock budget; stop owned process group on expiry |
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


## Form and AJAX discovery

The default baseline now runs both the traditional Spider and AJAX Spider.
`WEBX_ZAP_AJAX=0` opts out of browser interaction. AJAX crawling fills inputs and
clicks elements (including span/div tabs); it can submit forms and change state.
Use the authorized test environment and configured exclusions. It is not a
complete workflow test and does not guarantee every keyup, hover or custom widget
has been exercised. Missing browser/driver support is reported as partial coverage.

```bash
# Kali, with Firefox and compatible ZAP Selenium/WebDriver add-ons installed
export WEBX_ZAP_AJAX=1
export WEBX_ZAP_BROWSER=firefox-headless
export WEBX_ZAP_TIMEOUT=600
export WEBX_ZAP_PHASE_MINUTES=2
export WEBX_ZAP_SPIDER_DEPTH=10
export WEBX_ZAP_SPIDER_CHILDREN=50
export WEBX_ZAP_AJAX_STATES=100
export WEBX_ZAP_AJAX_ELEMENTS=a,button,input,span,div
```

`WEBX_ZAP_BROWSER=chrome-headless` selects Chrome instead; its ChromeDriver must
match the installed browser. Browser binaries/drivers are not installed by AIXSEC-X.
Each scan's time budget must accommodate discovery, browser startup, passive queue
processing and export; the session deadline still takes precedence.

Each scan writes `traffic.har` (private raw HTTP capture) and `inventory.json`
(redacted metadata), in addition to `report.json`, `urls.txt` and `zap.log`.
The final AIXSEC-X JSON includes a `discovery` array even when there are no alerts:

- `forms`: actions, methods and field names, with observed request/test state.
- `inputs`: controls inside and outside forms, without their values.
- `endpoints`: method, parameter names, authentication context and discovery source.
- `state=discovered`: only a reference was found; no matching captured request.
- `state=requested`: a matching request with a response exists in HAR.
- `state=tested`: a captured request is attributed to an allowed active rule using
  the scanner-injected header and an executor-owned HTTP sender observer. This is not proof of vulnerability or full rule coverage.

Static JavaScript extraction handles common literal jQuery/fetch/XHR patterns;
computed URLs and method options that cannot be resolved remain unknown. Relative
URLs in external scripts are resolved against known including documents.
`report.json` alone contains alert samples, so offline extraction from it cannot
establish full request coverage. The inventory never executes extracted JavaScript.
Raw HAR may contain credentials and personal data; it stays in the private scan
directory and is not placed in the planner context.

The planner now receives parameterized discovery leads and coverage gaps. Active
scans still require `WEBX_ALLOW_ACTIVE_SCAN=1` and `WEBX_ZAP_ALLOWED_RULES`.
For a selected endpoint, the adapter imports matching captures from the same
session/authentication context without replay, preserving POST bodies for ZAP.
Automatic active scheduling is now enabled; it operates on one captured representative per request family, without a session-wide budget. Captured request counters in a seeded
scan can include imported history, not just newly sent requests.

`coverage.status` describes job execution, not application-wide completion.
`phases`, `gaps`, `captured_requests` and `active_test_requests` expose what ran
and what remains unverified. A browser startup failure cannot be marked complete,
even if Automation Framework returns exit code zero. An active job with zero
attributed test requests is partial.

Active request attribution requires the ZAP Script Console and GraalVM JavaScript
add-ons (bundled in the tested ZAP distribution). An AIXSEC-owned HTTP sender
observer writes `active-requests.jsonl`: endpoint, method, parameter names, rule
ID and response status, without values/bodies. This also captures active messages
that ZAP omits from HAR. The planner cannot supply or edit the observer script.
If the observer cannot run, active coverage remains unverified/partial.

To verify your Kali browser/driver setup against a local form/AJAX fixture:

```bash
WEBX_TEST_LIVE_ZAP=1 python3 -m unittest test_zap_live -v
```

The opt-in test starts only a localhost server and checks an AJAX click, POST
form submission, and a targeted active scan seeded with the recorded POST body.
Ordinary unit-test runs skip this browser-dependent test.


## Automatic multi-rule scheduling and persistent deduplication

Defaults now select all installed ZAP active rules and schedule them after the
baseline, even when the LLM is unavailable. ZAP passive rules still analyze the
baseline traffic. This covers the checks implemented by installed add-ons, not
all possible vulnerabilities: business logic and multi-user authorization require
separate workflow/identity tests. Missing add-ons are not silently substituted.
Script Console and GraalVM JavaScript are required to export the installed rule
catalog as well as to record active-request evidence.

```bash
export WEBX_SCAN_BACKEND=zap
export WEBX_ZAP_AUTO_ACTIVE=1
export WEBX_ALLOW_ACTIVE_SCAN=1
export WEBX_ZAP_ALLOWED_RULES=all
# To restrict rules, for example: WEBX_ZAP_ALLOWED_RULES=40012,40018
# To remain discovery/passive-only: WEBX_ALLOW_ACTIVE_SCAN=0
```

Existing `WEBX_AUTO_EXEC` approvals, scope checks and action/time/request estimates
remain in effect. The defaults changed from passive-only: set the opt-out above
when active testing is not wanted. An existing explicit `WEBX_ZAP_ALLOWED_RULES=40018`
continues to restrict scans to that rule until changed to `all`.

A family includes normalized origin/port, path, HTTP method, query parameter
names (including multiplicity), body media type/schema and authentication context.
Numeric path segments and UUIDs are generalized. Values of routing keys such as
`action`, `act`, `type`, `view`, `route`, `controller`, `task`, `operation` and `op`
are preserved. Unknown slugs remain distinct to avoid merging unrelated handlers.

Examples: `/users/12?q=a` and `/users/34?q=b` share a family; GET and POST do not.
`/api?act=search` and `/api?act=delete` do not share a family. JSON fields and
query fields are distinct. Opaque bodies are hashed rather than guessed.
Static asset extensions are omitted from active scheduling; passive analysis still
covers their captured responses. Endpoint headers, cookies and the original body
are retained privately for the selected representative; values are not invented.

The active plan imports exactly one captured request, without replay, and skips
re-crawling/OpenAPI import. It uses a context restricted to that endpoint. Each
family/rule pair is reserved atomically in `WEBX_EVIDENCE_DIR/scan-history.sqlite3`.
This applies to automatic and planner-requested ZAP active actions and persists
across runs. One scan per rule means one test campaign, not one HTTP request;
a rule may need multiple payloads/control requests.

The final report and `active-schedule.json` list every eligible family and rule.
`artifact_ref` links an earlier attempt to its scanner report; historical findings
are not silently treated as newly verified findings in the current session:

- `not_run`: not scheduled, for example because no eligible request or allowed rule exists.
- `reserved`: a run claimed it; an interrupted process may leave this state.
- `attempted_unverified`: execution was attempted, but no rule-attributed request
  was observed. It must not be interpreted as a completed vulnerability test.
- `requests_observed`: at least one attributed request was captured; not proof
  of either vulnerability or safety.

Denied/blocked actions release reservations. Other attempts are not automatically
repeated, including failures/timeouts, to respect the no-repeat policy. Review
unverified attempts and the `stop_reason`; per-tool timeouts can leave checks incomplete.
Use explicit checkpoint resume/retry for interrupted or failed tasks; see [sequential pipeline](SEQUENTIAL_PIPELINE.md).

To intentionally retest a new application deployment or previously unverified
attempts, choose a new `WEBX_ZAP_HISTORY_NAMESPACE` (default `default`). This does
not erase old history. Reuse the same evidence directory and namespace to retain
deduplication; deleting them or moving to a new directory starts fresh history.


## Active response evidence

`WEBX_ZAP_STRENGTH` accepts Low, Medium (default), High or Insane. Higher strength
can reach per-tool timeouts sooner; it does not guarantee detection.
All selected active rules retain the existing metadata observer and additionally write
`active-evidence.jsonl` inside the private scan directory. This file stores URL/payload,
response body, body hashes and elapsed milliseconds; it is not included in model context.
Headers are omitted, common sensitive query/form/JSON fields are masked, unsupported
request bodies are omitted. Response bodies can still contain application secrets:
treat this artifact as private, like the existing seed HAR. The directory is mode 0700;
the adapter sets the artifact to 0600 after execution.

Limits: 16,384 characters per request body, 65,536 per response body, 16 MiB per scan.
Truncation flags and a byte-limit marker expose incomplete retention. The separate
metadata stream continues after the response capture limit. Hashes describe original
unredacted input/body; stored text is not necessarily hash-equivalent.

The offline SQL error comparator handles query parameters, URL-encoded forms and nested JSON for ZAP rule 40018. It requires the same origin/path/method as a successful
captured control, unchanged parameter names/order, exactly one changed value, and a
recognized SQL error absent from the control. It recognizes custom `syntax error: select`
responses as well as MySQL syntax errors and SQLSTATE class 42. It does not infer
injection from HTTP 200, a generic error, or a database technology name. Nested JSON fields are attributed by JSON Pointer; opaque bodies remain unsupported.
The control can be stale: results remain candidates needing repeated paired validation,
not confirmed SQLi. This adds no extra network requests and does not extract data.

`responses_recorded` means an attributed response was retained; `requests_observed`
means only request metadata was available. Neither proves rule completion or safety.
Previously attempted families remain suppressed. For an intentional rerun after this
update use a new fixed `WEBX_ZAP_HISTORY_NAMESPACE=evidence-v2`; do not change it on
every run if you want deduplication across runs. Internal requests made by a ZAP rule
are not individual scheduler campaigns and can include related URLs.

Local integration check without a browser or external target:
`WEBX_TEST_LIVE_EVIDENCE=1 python3 -m unittest test_zap_live.LiveEvidenceTests -v`.
