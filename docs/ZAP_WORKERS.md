# ZAP worker scheduling

The active stage uses a bounded pool (default two workers, maximum eight). Discovery finishes first; Nuclei and verification still follow the active stage. Parameterized groups are scheduled first. Each task receives an isolated seed/configuration, a distinct localhost proxy port and a ZAP process. Some ZAP versions treat `-port 0` as the configured default; the adapter now allocates explicit ports to avoid worker startup collisions. Evidence ingestion, checkpoint writes and scan-history updates happen on the owner thread. The scheduler atomically claims family/rule pairs before dispatch.

```bash
export WEBX_ZAP_WORKERS=2
export WEBX_ZAP_DELAY_MS=200
export WEBX_ZAP_ROUTE_GROUPS_FILE=/absolute/path/routes.json
```

Start with two workers and measure memory, CPU and server latency. `WEBX_ZAP_WORKERS=1` restores serial dispatch. Concurrency reduces waiting between independent jobs; it does not guarantee a twofold speedup. Each task still launches its own JVM and exports its own artifacts; persistent JVM reuse is not implemented.

Within a pipeline session, active scanner request starts share a private per-origin file lock across JVMs, enforcing the configured delay between worker requests. ZAP's own delay also remains enabled. This pacing applies to active scanner traffic, not every authentication/add-on request. Keep the same rate when increasing workers. A hung process retains its per-tool timeout; cancellation stops its process group and leaves unfinished checkpoints resumable.

Anonymous GET/HEAD requests without Cookie, Authorization, X-API-Key, X-CSRF-Token or X-XSRF-Token can overlap. Named authentication contexts, these credential headers and other methods run as serial barriers. This is a conservative scheduling heuristic, not proof that a GET has no side effects; use one worker for workflows with additional shared state or custom authentication schemes.

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

`WEBX_ZAP_COOKIE_PARALLEL=strict` is the default. Cookies in either the Cookie header or the structured HAR cookie list require serial execution. `anonymous` is only a configured label and does not establish that a cookie is unauthenticated.

After verifying the captured cookies are guest sessions and the requests can execute independently, opt in for a **new session**:

```bash
export WEBX_ZAP_COOKIE_PARALLEL=guest
export WEBX_ZAP_WORKERS=2
```

This mode changes only the cookie scheduling constraint. It does not remove, rewrite, or automatically classify cookies. Named authentication contexts, credential/CSRF headers, sensitive query parameter names, request bodies and non-GET/HEAD methods remain serial barriers. Custom authentication or state-changing GET endpoints may not be detectable from these fields; retain strict mode/one worker for such workflows. Rate pacing and history claims are unchanged. Raising the worker count alone cannot overcome serial constraints. Existing checkpoints require their original configuration; changing cookie mode requires a new session, retaining the same history namespace to preserve deduplication.
