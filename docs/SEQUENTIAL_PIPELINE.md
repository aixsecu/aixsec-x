# Sequential scanner pipeline

The modern pipeline (`WEBX_SCAN_BACKEND` other than `legacy`) executes discovery,
ZAP active campaigns, Nuclei template campaigns, candidate verification, Planner,
and report in order. ZAP is the default discovered backend. Wapiti/HTTP backends
can also precede Nuclei; `none` disables automatic scanner stages.

There is no session-wide time, action or estimated-request cap. The old
`WEBX_PIPELINE_MAX_*` settings are ignored. Metrics remain in `budget` with
`mode=sequential` and null limits. Local executor limits remain: ZAP phase/process
timeouts, Nuclei batch timeout, HTTP request timeout, rate limits and LLM timeouts.
The Planner retains `WEBX_MAX_ROUNDS`, stops after two model failures or when it
returns no actions or adds no new observed endpoint, evidence, auth or validation facts. Fresh scan IDs and changing response hashes alone are not progress. A scanner's completion
means execution finished, not that every vulnerability has been excluded.

## Kali configuration

```bash
export WEBX_SCAN_BACKEND=zap
export WEBX_ZAP_EXECUTABLE=zaproxy
export WEBX_NUCLEI_ENABLED=1
export WEBX_NUCLEI_EXECUTABLE=nuclei
export WEBX_NUCLEI_RATE=5
export WEBX_NUCLEI_TIMEOUT=600
# Optional operator-owned local templates/directories, comma separated:
# export WEBX_NUCLEI_TEMPLATES=/path/to/nuclei-templates/http
# Optional filters:
# export WEBX_NUCLEI_TAGS=cve,misconfig,exposure
# export WEBX_NUCLEI_SEVERITY=info,low,medium,high,critical
```

Install the binary and templates separately before scanning. Scans disable update
checks and do not generate templates or enable dashboard uploads. The adapter uses
Nuclei's [documented CLI](https://github.com/projectdiscovery/nuclei#command-line-flags)
for local template listing and JSONL output. Existing scope checks and operator
approval still apply. `WEBX_ALLOW_ACTIVE_SCAN=0` disables both automatic ZAP active
and Nuclei. `WEBX_NUCLEI_ENABLED=0` disables Nuclei alone.

## Supported Nuclei coverage

`adapters/nuclei.py` lists local templates with operator filters. Supported HTTP
requests include path templates rooted at `{{BaseURL}}`/`{{RootURL}}` and ordinary
raw HTTP with a relative path and exactly `Host: {{Hostname}}`. Raw framing/proxy
overrides, unsafe/race/fuzzing, flow/code, headless and OAST remain excluded. Each
rejected template path and reason is recorded in `nuclei-catalog.json`; binding gaps
are recorded in `nuclei-bindings.json`. These paths are linked in the final report.

RootURL/literal raw paths group by origin. BaseURL paths group by request family.
Captured GET/POST/PUT/PATCH bodies can be used with an operator-selected single-raw
request template whose request URI is `{{AIXSECPath}}` and body is `{{AIXSECBody}}`.
The template method must match the captured method. These variables preserve the
captured query/body; ordinary templates are not rewritten into POST tests. Example
binding (an observation template, not proof of a vulnerability):

```yaml
id: captured-json-observation
info:
  name: Authenticated JSON response observed
  author: operator
  severity: info
http:
  - raw:
      - |
        POST {{AIXSECPath}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {{AIXSECBody}}
    matchers:
      - type: word
        words: [YOUR_AUTHENTICATED_RESPONSE_MARKER]
```

Non-hop-by-hop captured headers, including cookies, authorization and custom CSRF
headers, are written to a private Nuclei configuration file, not command-line
arguments. A named context must pass a fresh control using the existing
`WEBX_ZAP_AUTH_FILE` origin and logged-in/logged-out markers before credentials
are reused. Expired/ambiguous auth stops the campaign with an explicit error.
Anonymous captures carrying cookies are marked `captured_unverified`; this is not
proof of a logged-in identity. No authenticated capture is relabelled as anonymous.

Templates are batched up to 64 per representative. Hashes are checked before launch.
`coverage.templates` distinguishes campaign completion from unverified attempts;
it does not claim that every internal request succeeded. Flow/headless/OAST need
separate scope, browser-session and callback evidence handling before enablement.

Private `report.jsonl` stores original scanner evidence; `nuclei.log` stores runtime
output. Only normalized metadata/hashes are exposed to the model and Evidence
Engine. Missing binaries/templates, malformed JSONL, nonzero exit, timeout and
unproven template loading are explicit, not zero-finding success. Result URLs
outside the target origin are rejected. Scanner findings remain candidates.

## History and checkpoints

Existing ZAP history is retained in `scan-history.sqlite3`. Other scanner and
verification history is in `scanner-history.sqlite3`, keyed by namespace, scanner,
request family/auth context and rule/template revision. A ZAP attempt never
suppresses a Nuclei template. Neither a timeout nor an observed request proves
completion. Internal payload requests within a rule are not separate campaigns.

Each private session directory now contains atomic `progress.json` and
`checkpoint-<hash>.json` records. The progress file lists pending/running/complete/
partial/error/timeout/skipped/duplicate tasks and stage reasons. A namespace lock
prevents concurrent pipeline runs from racing over the same history.

```bash
export WEBX_RESUME_SESSION=/absolute/path/to/.aixsec-evidence/session-XXXX
# To explicitly retry prior failed/partial/denied tasks:
export WEBX_RETRY_INCOMPLETE=1
```

Resume requires the original configuration, evidence root and namespace. It loads
completed observations into the same session and only dispatches missing work.
Restored coverage is labelled `restored_not_revalidated`. Auth profile changes reject
resume and require a new discovery session. Remaining authenticated actions perform
a fresh control; old findings are not automatically revalidated. Changed/missing
Nuclei template revisions are listed in `nuclei-resume-check.json` and make coverage
partial; old templates are not silently substituted. An interrupted in-flight task is retried:
exactly-once network execution across a crash cannot be guaranteed. Without the
retry flag, recorded failures are retained rather than automatically repeated.
To scan a new deployment, unset resume and choose a new history namespace. Do not
change namespace every run if cross-run deduplication is desired. Keep raw artifacts
private because HARs, checkpoint arguments and response bodies can contain secrets.

## SQLi verification

SQL candidates support query parameters, URL-encoded forms and nested JSON
(GET/POST/PUT/PATCH). JSON locations accept JSON Pointer, a unique field name or
common dotted/indexed paths. Duplicate query/form names are tested one occurrence
at a time; duplicate JSON object keys are rejected rather than silently collapsed.
Unchanged query/form bytes and captured headers are retained. Each location gets
two fresh control/apostrophe-payload pairs within the per-tool timeout. Only pairs
with successful controls and repeated new SQL errors create an observation.
Named auth contexts additionally require fresh authentication markers on controls.
Artifacts record the exact input selector. Reproduced SQL errors remain candidates,
not proof of exploitability or extraction. The offline ZAP comparator also recognizes
one changed nested JSON field and records its JSON Pointer.

When `WEBX_ALLOW_SQLMAP=1`, the scheduled verifier supplies the captured request to
sqlmap with only boolean/error checks, a bounded runtime and a single named
parameter. Ambiguous duplicate names stay with the paired verifier rather than being
passed ambiguously to sqlmap. JSON Pointer selectors resolve to a unique sqlmap
field name. Authentication is checked before launch. It does not request database enumeration or data dumping. Raw request
credentials stay in a private request file. SQLmap observations also remain
candidates pending independent validation. Generic ffuf, workflow/auth testing,
SAST correlation and HTTP exploration still depend on Planner decisions.

## Tests

Offline tests mock external scanners. Local opt-in integration runs ZAP and Nuclei
against a synthetic localhost fixture, verifies candidate ingestion and resumes
without invoking completed tools:

```bash
python3 -m unittest test_sequential_pipeline test_nuclei_adapter test_verification
WEBX_TEST_LIVE_SEQUENTIAL=1 python3 -m unittest test_sequential_pipeline.LiveSequentialTests -v
```


## Expanded local/Kali checks

```bash
# Offline regression tests (external scanners disabled/mocked):
WEBX_NUCLEI_ENABLED=0 python3 -m unittest discover
# Actual local scanners only; synthetic localhost, not an external target:
WEBX_TEST_LIVE_CAPTURE=1 python3 -m unittest test_capture_expansion.LiveCaptureTests -v
WEBX_TEST_LIVE_SEQUENTIAL=1 python3 -m unittest test_sequential_pipeline.LiveSequentialTests -v
```

The capture fixture verifies raw POST JSON, cookie and CSRF propagation, named auth,
and SQL error pairs. It is portable to Kali with the Python requirements and Nuclei
installed. Browser/AJAX compatibility is a separate optional test in `test_zap_live`.
These commands do not package a ZIP. The latest expansion was verified on macOS;
a native Kali run is still required to establish environment-specific compatibility.

Raw HTTP syntax reference: [ProjectDiscovery documentation](https://docs.projectdiscovery.io/templates/protocols/http/raw-http).
