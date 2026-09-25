# ZAP worker scheduling

The active stage uses a bounded pool (default two workers, maximum eight). Discovery finishes first; Nuclei and verification still follow the active stage. Parameterized groups are scheduled first. Each task receives an isolated seed/configuration, a distinct localhost proxy port and a ZAP process. Some ZAP versions treat `-port 0` as the configured default; the adapter now allocates explicit ports to avoid worker startup collisions. Evidence ingestion, checkpoint writes and scan-history updates happen on the owner thread. The scheduler atomically claims family/rule pairs before dispatch.

```bash
export WEBX_ZAP_WORKERS=2
export WEBX_ZAP_DELAY_MS=200
export WEBX_ZAP_ROUTE_GROUPS_FILE=/absolute/path/routes.json
```

Start with two workers and measure memory, CPU and server latency. `WEBX_ZAP_WORKERS=1` restores serial dispatch. Concurrency reduces waiting between independent jobs; it does not guarantee a twofold speedup. Each task still launches its own JVM and exports its own artifacts; persistent JVM reuse is not implemented.

Within a pipeline session, active scanner request starts share a private per-origin file lock across JVMs, enforcing the configured delay between worker requests. ZAP's own delay also remains enabled. This pacing applies to active scanner traffic, not every authentication/add-on request. Keep the same rate when increasing workers. A hung process retains its per-tool timeout; cancellation stops its process group and leaves unfinished checkpoints resumable.

Anonymous GET/HEAD requests without Cookie, Authorization, X-API-Key, X-CSRF-Token or X-XSRF-Token can overlap. Without an explicit concurrency policy, named authentication contexts, these credential headers and other methods run as serial barriers within their origin. This is a conservative scheduling heuristic, not proof that a GET has no side effects; use one worker for workflows with additional shared state or custom authentication schemes.

## Explicit slug grouping

An operator-owned JSON file declares origin-specific groups. [The example file](../examples/zap/route-groups.example.json) groups only the two product URLs supplied in the discussion; it is inactive until selected with `WEBX_ZAP_ROUTE_GROUPS_FILE`. Example for a site whose cooler product slugs are known to use the same handler:

```json
[
  {
    "origin": "https://example.com",
    "group": "cooler-product-detail",
    "paths": ["/tan-nhiet-khi-*"]
  }
]
```

`paths` uses case-sensitive shell-style globs on the URL path (not query). `*` can match slashes; choose narrow patterns. Do not declare `/*` merely because all routes have one segment. Overlapping matching entries are rejected, instead of choosing an arbitrary group. No hostname/route mapping is enabled by default.

Only the path grouping changes. Origin, method, query names/multiplicity, routing parameter values, body structure and authentication label still distinguish families. Rule IDs still have separate history entries. A route policy fingerprint is part of the family key; changing the policy requires new coverage. The route file content is also checked when resuming a session.

One captured request represents a group. `equivalent_requests` records how many captures were grouped. This is sampling by declared route, not proof that all products behave identically or were individually tested. Findings retain the actual tested URL. Leave the file unset for conservative built-in numeric/UUID normalization.

## Progress and verification

The console prints group/rule/worker counts, completed groups and a heartbeat while waiting. Private `progress.json` tasks include start/end timestamps and execution duration. Existing `WEBX_RESUME_SESSION`, `WEBX_RETRY_INCOMPLETE` and history namespace behavior remain in effect; do not change namespace simply to resume.

Offline concurrency, serial barrier, seed isolation, cancellation, route deduplication and resume tests:

```bash
python3 -m unittest test_zap_workers test_sequential_pipeline test_zap_schedule
```

Optional real localhost ZAP/Nuclei integration (requires installed binaries/templates):

```bash
WEBX_TEST_LIVE_SEQUENTIAL=1 python3 -m unittest test_sequential_pipeline.LiveSequentialTests
```

The two-JVM regression also checks that both scans produce rule evidence and share request pacing:

```bash
WEBX_TEST_LIVE_ZAP_WORKERS=1 python3 -m unittest test_zap_workers.LiveWorkerTests
```

## Another scan is using this history namespace

A pipeline holds an OS file lock for its evidence directory/history namespace. This is separate from the internal ZAP worker pool: increasing workers does not require starting another agent. A competing launch returns `status=busy` with the lock path and owner PID/host when available; it does not start scanners or export the previous run's findings. The interactive CLI remains available.

On Kali, inspect lock holders from the project directory (adjust the path if using a custom evidence root):

```bash
fuser -v .aixsec-evidence/run-*.lock
```

Wait for the existing scan or stop it in its original terminal. A job suspended with Ctrl+Z still holds its lock; resume it with `fg` in that shell before stopping it with Ctrl+C. Do not delete the lock file or change history namespace to bypass a running scan. An existing lock file alone does not block execution: the kernel releases the lock when the owner closes it or exits. Owner metadata can remain in the file after exit and is informational; lock acquisition is authoritative. Older running versions may have no PID metadata.

## Cookie-aware concurrency diagnostics

The console now prints `parallel eligible`, `serial`, and counts for each serial reason before dispatch. A group can have multiple reasons, so reason counts may exceed the serial group count. Private `zap-scheduling.json` contains request IDs and decisions without cookie/header values. Aggregate scheduling counts remain in the `zap_active` stage of `progress.json`. Eligibility counts describe the discovered schedule; they do not imply every group needs rerunning (history/resume still apply), or that every eligible worker is currently occupied.

`WEBX_ZAP_COOKIE_PARALLEL=auto` is now the default; `strict` remains available as an explicit override. Cookies in either the Cookie header or the structured HAR cookie list require serial execution. `anonymous` is only a configured label and does not establish that a cookie is unauthenticated.

After verifying the captured cookies are guest sessions and the requests can execute independently, opt in for a **new session**:

```bash
export WEBX_ZAP_COOKIE_PARALLEL=guest
export WEBX_ZAP_WORKERS=2
```

This mode changes only the cookie scheduling constraint. It does not remove, rewrite, or automatically classify cookies. Without an explicit concurrency policy, named authentication contexts and credential headers remain serial barriers. CSRF headers, sensitive query parameter names, request bodies and non-GET/HEAD methods remain serial even with a parallel policy. Custom authentication or state-changing GET endpoints may not be detectable from these fields; retain strict mode/one worker for such workflows. Rate pacing and history claims are unchanged. Raising the worker count alone cannot overcome serial constraints. Existing checkpoints require their original configuration; changing cookie mode requires a new session, retaining the same history namespace to preserve deduplication.

### Empty HAR body metadata

An exported GET can include `postData` containing only `mimeType`, empty `text` and empty `params`. This metadata alone no longer produces a `request_body` serial constraint. Nonempty payloads (including whitespace), form parameters, positive body sizes/content lengths and transfer-encoded bodies still produce the constraint. Cookie mode remains independent: an empty-body GET carrying cookies still needs guest opt-in to overlap.

## Explicit request independence policy

`WEBX_ZAP_CONCURRENCY_FILE` optionally selects an operator-owned JSON policy. The default is empty: automatic classification applies, or strict/guest if explicitly configured. This policy is separate from route grouping: it changes concurrency eligibility, not which URLs or rules are tested.

Start from [concurrency.example.json](../examples/zap/concurrency.example.json), replacing the origin, exact authentication context label and paths with the routes you have verified can be actively tested concurrently:

```bash
export WEBX_ZAP_CONCURRENCY_FILE="$PWD/examples/zap/concurrency.example.json"
export WEBX_ZAP_WORKERS=2
```

The supplied example uses `https://example.com` and `member`; it does not automatically match your target. A `parallel_read` rule can permit captured GET/HEAD requests with a named authentication context, Cookie or Authorization header. You can use `auth_context: "anonymous"` to allow specific guest routes while keeping cookie mode strict elsewhere. Authentication labels must match exactly for parallel rules; only serial rules permit `"*"`.

A matching `serial` rule wins over every parallel rule, regardless of order. Non-GET/HEAD methods, actual request bodies, CSRF headers and sensitive query names remain serial regardless of policy. Unmatched requests use the configured auto/strict/guest fallback; therefore declare explicit serial routes for workflows even when they have no cookie. Paths are case-sensitive shell-style globs (`*` also spans `/`); origin includes scheme and port. Ambiguous parallel matches are rejected before active dispatch.

Serial constraints now apply to the origin rather than the entire pool. A serial task excludes every other active task for that origin, including other accounts; unrelated origins can continue. Dispatch order within an origin is preserved, so later reads cannot jump ahead of a queued stateful task. This is concurrency ordering, not automatic construction or validation of a business workflow. Cross-origin shared sessions/data are not inferred; use one worker for such workflows.

The policy declares independence; the tool does not prove it from GET or cookie names. Consider the whole active test, including mutations made by enabled scanner rules and authentication/login side effects, not merely whether the original GET is read-only. Requests and captured credentials are preserved. Separate ZAP processes do **not** create independent server sessions or accounts: this feature does not provision per-worker logins, rotate sessions, or isolate shared application data. Do not mark dependent operations parallel merely to occupy workers.

`zap-scheduling.json` records the matching policy rule ID and remaining serial reasons without cookie/header values. The console and progress show counts per policy rule. Policy file content is fingerprinted for resume; change it only for a new session, keeping scan history for deduplication.

Tests:

```bash
python3 -m unittest test_zap_concurrency test_zap_workers test_sequential_pipeline test_scan_lock test_zap_schedule
```

## Automatic concurrency (default)

A new session now defaults to `WEBX_ZAP_COOKIE_PARALLEL=auto`; no policy file is required. Previously exported values retain precedence. Start a new session with the env variable unset (or set to `auto`); do not change an existing checkpoint's configuration. Explicit concurrency policy matches bypass automatic trials and retain their declared behavior.

Automatic classification excludes non-GET/HEAD methods, actual bodies, CSRF/sensitive query fields, common account/payment/state-changing route/action names, and captures without a successful response. Named authentication requires an existing profile with login/logout verification markers. Unlabelled credential headers and HAR-only cookies without a replayable Cookie header remain serial. Cookie presence alone does not prohibit a trial; it is not classified as a guest cookie.

For a new, approved and in-scope eligible task, the coordinator sends two sequential controls preserving captured headers, with redirects disabled, 10-second request timeouts and a 1 MiB response limit. Both must succeed, match authentication markers when applicable, have identical body hashes/status/content type, finish within five seconds each and show no cookie setting, redirect, password-field or CSRF signals. These control requests share the active-scan per-origin pacing file. Controls add up to two read requests per assessed group; failures cause serial execution, not a skipped scan. Probe metadata/hashes are stored without bodies or credential values.

Each origin starts with one active worker. After a stable control pair and a successful scan with observed active requests, that origin may use up to two workers (also bounded by `WEBX_ZAP_WORKERS`). Auto mode deliberately does not jump to four simply because four workers are configured; other origins can occupy spare workers. Missing observer evidence does not promote concurrency.

Scanner error/partial/timeout, unverified named auth, observed 401/403/429/5xx, Set-Cookie/Location or slow active responses cause sticky backoff to one worker for the rest of that session. Queued tasks wait for existing same-origin scans before serial dispatch; already running scans finish under their existing timeouts. Feedback is applied at task completion, not continuously during a ZAP process. Scanner payloads can themselves cause these signals, so backoff is conservative, not a diagnosis of server overload or a vulnerability verdict.

`auto-concurrency.json` records control decisions and per-origin promotion/backoff. Progress includes an automatic summary. Resume restores backoff and completed tasks without replaying controls for completed work; new tasks receive fresh checks. Initial `parallel eligible` counts mean candidates for trial, not immediate concurrent execution. The manual `strict`, `guest` and policy file settings remain available for exceptions.

This is evidence-based scheduling, not proof of independence. It does not create separate server sessions/accounts, infer cross-origin shared data, automatically merge unknown slug routes, or reuse ZAP JVMs. Dynamic pages and unknown workflows may remain serial; the tool continues scanning them with existing rule coverage.

Optional localhost validation:

```bash
WEBX_TEST_LIVE_AUTO=1 python3 -m unittest test_zap_auto
```
