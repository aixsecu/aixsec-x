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
returns no actions or makes no successful new action. A scanner's completion
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

`adapters/nuclei.py` lists local templates with operator filters. It selects HTTP
path templates rooted at `{{BaseURL}}` or `{{RootURL}}`. Raw requests, flow/code,
headless/browser, network protocols, unsafe/race/fuzzing and redirects are excluded;
OAST is disabled and dos/fuzz/bruteforce tags are excluded. The catalog records
eligible/excluded counts. This is intentionally a subset of Nuclei templates, not
an assertion that every installed template ran. No match is not a safety verdict.

RootURL-only templates are grouped by origin; BaseURL templates use captured GET
request families. Configured targets are also included. Authenticated/POST captures
are not silently converted to public GET tests. Nuclei findings are anonymous
observations and are not evidence of authenticated coverage. Templates are batched
(up to 64) per representative, with one batch running at a time. Hashes are checked
before launching to reject templates changed since cataloging.

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
Authentication setup can be refreshed; a resume is not a claim that old sessions or
findings have been freshly revalidated. An interrupted in-flight task is retried:
exactly-once network execution across a crash cannot be guaranteed. Without the
retry flag, recorded failures are retained rather than automatically repeated.
To scan a new deployment, unset resume and choose a new history namespace. Do not
change namespace every run if cross-run deduplication is desired. Keep raw artifacts
private because HARs, checkpoint arguments and response bodies can contain secrets.

## SQLi verification

SQL candidates with a named parameter and matching captured GET or URL-encoded
POST request receive two fresh control/apostrophe-payload pairs. A new SQL error
must recur in both payload responses and be absent from both successful controls.
Artifacts retain the pair facts. Reproduced SQL errors remain candidates: they are
not proof of exploitability or data extraction. Unsupported/ambiguous inputs are
reported as incomplete rather than synthesized.

When `WEBX_ALLOW_SQLMAP=1`, the scheduled verifier supplies the captured request to
sqlmap with only boolean/error checks, a bounded runtime and a single named
parameter. It does not request database enumeration or data dumping. Raw request
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
