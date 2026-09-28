# Terminal output

Normal scans have three output levels:

1. Progress uses a single updating line on a terminal. Redirected output prints stage changes as plain lines, without ANSI control sequences. Stages are Discovery, Route Family, Active Scan, Validation, and Reporting.
2. A newly confirmed ledger finding prints immediately, once per finding per scan. Candidates are not presented as confirmed vulnerabilities. Progress clears only its current line; it never clears finding lines.
3. A fresh final summary follows scan cleanup and all existing report/inventory writes. It is the last scan output, including in verbose mode. Interrupted and failed scans also receive a summary when the agent has been initialized; fatal exception tracebacks can follow on stderr. In an interactive session, the next command prompt is on stderr; a user command starts a new output cycle.

All captured stdout/stderr diagnostics are retained in a unique, mode-0600 log under `.aixsec-evidence/logs/`. Set `WEBX_LOG_DIR` to choose another directory. Existing scanner artifact logs remain unchanged. `--verbose`, `--debug`, or `WEBX_VERBOSE=1` also displays diagnostics during execution. These include scheduler, worker, concurrency, bootstrap, batching, route-family, benchmark, instrumentation, JVM, queue, and model output. Operator approval prompts remain visible in normal mode.

The final summary counts existing confirmed ledger findings. Pending candidates are listed separately. Active job counts come from existing active-stage checkpoint tasks; skipped, duplicate, blocked, and partial jobs are not counted as successes or failures. Unavailable metrics display N/A. Coverage groups existing coverage records by status; it does not infer that an application is safe. Output paths reference the original artifacts; no report content or finding verdict is transformed.

## Before (representative terminal excerpt)

```text
[stage] discovery: running
[→] zap_discover (baseline)
[i] zap_discover: ok ...
[zap:families] Original groups: 120
[zap:families] Families: 24
[zap] 36 request groups; 8 rules; 4 workers
[zap] 1/36 groups finished; 3 running
[zap] 2/36 groups finished; 3 running
...
ACTIVE SCAN PERFORMANCE
Workers: 4
...
ZAP LIFECYCLE
STARTUP
...
{ ... large final result JSON ... }
AIXSEC-X FINDINGS LEDGER
...
[*] Report: report.json
[*] Attack surface: inventory.json
```

## After (illustrative values, not a live scan)

The progress line updates in place on a terminal. Confirmed findings occupy permanent lines:

```text
[Discovery]
[Route Family]
[Active Scan]
[CRITICAL] SQL Injection
[HIGH] Authentication Bypass
[Validation]
[MEDIUM] Missing CSP
[Reporting]

==================================================
AIXSEC-X Scan Summary
==================================================
Target: https://example.test
Duration: 84.2s
Status: complete

Discovery
  URLs: 120
  Route Families: 24
  Representatives: 36

Active Scan
  Jobs: 36
  Success: 35
  Failed: 1

Findings (confirmed)
  Critical: 1
  High: 1
  Medium: 1
  Low: 0
  Info: 0
  Awaiting validation: 2

Coverage
  complete: 35
  timeout: 1

Output Files
  Report: report.json
  Attack surface: inventory.json
  Diagnostic log: .aixsec-evidence/logs/cli-example.log
==================================================
```

Library APIs retain their existing output unless called inside the CLI presentation context. Scan dispatch, validation, scheduling, report generation, and report schemas are unchanged.
