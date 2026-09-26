# Persistent ZAP worker pool

## Architecture

The pipeline owns one `WorkerPool`. Each worker starts one ZAP daemon and owns a
private port, workspace, home/session database, API endpoint, context state,
policy cache, and process. Scheduled jobs acquire a worker, reset job-specific
state, submit an Automation Framework plan through the local API, collect the
existing raw artifacts, and release the worker without stopping its JVM.

Direct calls to the public `run_scan()` API use a process-wide persistent pool
and are closed at interpreter exit. There is no per-job JVM execution path.

Workers never share a port, workspace, process, session database, or in-memory
authentication state. Before a job, the worker clears alerts, active HTTP
sessions, Sites tree, and history. Raw job artifacts remain in their existing
per-scan evidence directory. Identical scan policies are retained; a changed
policy is rebuilt by its Automation Framework job.

## Health and recycling

States are `healthy`, `busy`, `recovering`, and `dead`. Acquisition verifies API
health. A failed worker is removed, shut down independently, and replaced; one
job is retried once on its replacement. Other workers and queued jobs continue.

Recycling triggers:

- `WEBX_ZAP_WORKER_MAX_JOBS` (default 100),
- `WEBX_ZAP_WORKER_MEMORY_MB` (default 0, disabled),
- process/API failure,
- explicit `request_recycle(worker_id)`.

`WEBX_ZAP_WORKERS` remains the pool-size setting and defaults to 2. Public APIs,
CLI arguments, evidence, validation, ledger, findings, and report schemas are
unchanged. AutoConcurrency and scheduler policy are unchanged.

## Metrics

Pool metrics include JVMs created, jobs, reused jobs, recycle/crash counts,
acquisition wait, worker busy time, average job/startup/shutdown/lifetime,
reuse ratio, RSS memory, CPU percentage, throughput, and healthy worker count.
They are included in the pipeline result and Active Scan performance artifact.

## Real benchmark

Local controlled workload: ZAP 2.17.0, one worker, two sequential active jobs,
one SQL injection rule, identical target server.

| Metric | Per-job JVM baseline | Persistent worker |
|---|---:|---:|
| Total for two jobs | approximately 26.3 s | 15.72 s |
| JVMs created | 2 | 1 |
| Reused jobs | 0 | 1 |
| Reuse ratio | 0% | 50% |
| Per-job JVM startup | approximately 2.63 s | 0 ms after pool startup |
| Per-job JVM shutdown | approximately 6.84 s | 0 ms |
| Persistent job busy mean | n/a | 4.79 s |
| Worker lifetime at snapshot | n/a | 12.01 s |
| Worker RSS at snapshot | n/a | 496.9 MiB |

Observed end-to-end improvement is approximately 40%. The two-job result is
conservative because initial pool startup is included and only one reuse occurs;
reuse ratio approaches 100% for longer scans. Target latency, passive waits,
active rule execution, report export, and evidence parsing remain.

Benchmark command:

```sh
python3 bench/zap_performance_benchmark.py --jobs 2 --workers 1 \
  --evidence-dir /private/tmp/aixsec-zap-pool
```

## Verification

- Real ZAP test: two jobs completed through one daemon; second job reused its
  worker and cached policy, with raw evidence produced for both jobs.
- Automated tests cover lifecycle, reuse, recycling, crash replacement,
  isolation, acquisition/release, shutdown, exhaustion, and parallel leases.
- Full regression suite: 591 passed, 6 skipped.
