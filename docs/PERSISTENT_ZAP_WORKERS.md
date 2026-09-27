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
sessions, Sites tree, and history. Session clearing is fail-closed: if the
installed add-on cannot clear authentication state, that JVM is discarded
instead of being reused. Raw job artifacts remain in their existing per-scan
evidence directory. Identical scan policies are retained; a changed policy is
rebuilt by its Automation Framework job.

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

Local controlled workload: installed ZAP, one worker, three sequential active
jobs, one SQL injection rule, and the same local target implementation. The
baseline creates and closes a fresh isolated worker for every job. The optimized
run shares one worker. Both modes use the same production adapter, scheduler,
report parser, and evidence path.

| Metric | Per-job JVM baseline | Persistent worker |
|---|---:|---:|
| Total wall time | 59.840 s | 43.551 s |
| Throughput | 0.0501 jobs/s | 0.0689 jobs/s |
| JVMs created | 3 | 1 |
| Reuse ratio | 0% | 66.67% |
| Lifecycle share | 79.80% | 75.36% (one cold start included) |
| Child CPU time | 43.988 s | 25.527 s |
| Peak worker RSS | 572.2 MiB | 665.5 MiB |
| Finding signature | identical | identical |

Observed wall-time reduction was 27.22%, throughput improved 37.52%, and child
CPU time fell 18.46 seconds. The retained worker used 93.3 MiB more peak RSS in
this run. The initial pool startup is included; reuse ratio approaches 100% for
longer scans. Target latency, passive waits, active rule execution, per-job
context/import work, report export, and evidence parsing remain.

Benchmark command:

```sh
python3 bench/zap_performance_benchmark.py --compare --jobs 3 --workers 1 \
  --output /private/tmp/aixsec-zap-worker-comparison.json
```

## Verification

- Real ZAP test: three jobs completed through one daemon; later jobs reused its
  worker and cached policy, with raw evidence produced for every job.
- Automated tests cover lifecycle, reuse, recycling, crash replacement,
  isolation, acquisition/release, shutdown, exhaustion, and parallel leases.
- The benchmark compares normalized finding signatures and reports whether they
  are equal. Automated regression tests remain the authoritative behavior check.
