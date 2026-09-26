# ZAP lifecycle investigation

This report is measurement-only. It does not change the scheduler, AutoConcurrency,
worker behaviour, scan policy, evidence, or report semantics.

## Method

- ZAP 2.17.0, macOS, three independent JVMs.
- One local HTTP target, one representative GET group per job, SQL injection rule
  40018 at Low strength, one worker.
- Values are per-job means. Lifecycle percentages use executing-job time
  (13,178.6 ms), excluding scheduler queue residence.
- Automation-job durations come from timestamped `started`/`finished` events.
  Process spawn, waits, log flush, and plan cleanup use `perf_counter_ns()`.
- A zero means the operation did not run only where stated below. Missing ZAP
  markers are explicitly labelled and are not estimated.

The machine-readable report for this run is
`/private/tmp/aixsec-zap-life-final.g1Dw2z/lifecycle-instrumented.json`.
That path is benchmark evidence, not a repository artifact.

## Startup

| Phase | Mean |
|---|---:|
| Process spawn | 3.018 ms |
| Java boot | 255.528 ms |
| Add-on discovery/load/initialization | 1,891.667 ms |
| Network setup (new root CA) | 419.333 ms |
| Unattributed between emitted milestones | 63.667 ms |
| **Startup total** | **2,633.212 ms** |

`proxy_bind_ms` cannot be isolated because cmd mode emits no bind-complete
marker. `api_ready_ms` is not applicable: this adapter does not poll or drive the
HTTP API. ZAP does not emit a distinct context-created marker for this plan, so
`context_create_ms` is intentionally zero/unobserved rather than inferred from
unrelated log lines.

The following plan setup jobs execute after ZAP startup and are timed separately:
context import 35.667 ms, policy load 10.000 ms, scan configuration 1.000 ms,
and observer script load 1.333 ms. The anonymous benchmark has no authentication
setup job.

## Active phase

| Phase | Mean |
|---|---:|
| Spider wait | 0 ms (not requested) |
| Passive wait before active scan | 3,023.000 ms |
| Active scan | 511.667 ms |
| Alert download | 0 ms (not used; local report is parsed) |
| HAR/URL export | 17.333 ms |
| Evidence parse | 12.265 ms |

## Shutdown

| Phase | Mean |
|---|---:|
| Stop scan | 0 ms (normal completion) |
| Passive flush after active scan | 0 ms (queue already empty) |
| Report finalization | 90.667 ms |
| API shutdown | 0 ms (no API shutdown call exists) |
| JVM completion after final automation job | 6,835.227 ms |
| Workspace cleanup | 0 ms (raw evidence is retained) |
| Temporary plan cleanup | 0.257 ms |
| **Shutdown total** | **6,835.484 ms** |

The dominant shutdown interval starts when the final Automation Framework job
finishes and ends when the child process exits. The ZAP log records
`Automation plan succeeded`, then records `ZAP ... terminated` roughly six
seconds later. There is no adapter sleep or API shutdown request in that gap.

## Blocking operations

The production scheduled path supplies a cancellation event, so it calls
`process.wait(timeout=min(1, remaining))` repeatedly. Per job it made 13.667
timed wait calls and 12.667 calls reached their one-second polling timeout. This is
13,160.925 ms of blocking wait covering the whole child lifetime; it overlaps
startup, scan, and shutdown and therefore is not added to phase totals.

- HTTP polling: 0 calls / 0 ms.
- API retries: 0 calls / 0 ms.
- `sleep()`: 0 calls / 0 ms.
- Passive scanner polling: internal to the 3,023.000 ms Automation Framework job.
- Export wait: 2 jobs / 17.333 ms.
- File flush: 1 call / 0.019 ms.
- Disk sync: 0 calls / 0 ms.
- Explicit timeout/cancellation stop: not taken in the benchmark.

## Ranked internal phases

Percentages use executing-job time and are upper bounds on the gain from fully
removing that phase.

| Rank | Phase | Time | Share | Root cause | Complexity | Regression risk |
|---:|---|---:|---:|---|---|---|
| 1 | JVM completion/process wait | 6,835.227 ms | 51.87% | ZAP teardown after plan completion | Medium | Medium |
| 2 | Passive wait | 3,023.000 ms | 22.94% | Passive queue drain | Medium | High |
| 3 | Add-on loading | 1,891.667 ms | 14.35% | Extension discovery/load/init | High | High |
| 4 | Active scan | 511.667 ms | 3.88% | Rule execution and target latency | High | High |
| 5 | Network setup | 419.333 ms | 3.18% | Per-home root CA generation | Medium | Medium |
| 6 | Java boot | 255.528 ms | 1.94% | Launcher/JVM/ZAP bootstrap | High | High |
| 7 | Report finalization | 90.667 ms | 0.69% | JSON report generation | Medium | Medium |
| 8 | Unattributed startup | 63.667 ms | 0.48% | No distinct ZAP marker | Unknown | Unknown |
| 9 | Context import | 35.667 ms | 0.27% | HAR seed import | Medium | Medium |
| 10 | Report export | 17.333 ms | 0.13% | HAR and URL exports | Low | Low |
| 11 | Evidence parse | 12.265 ms | 0.09% | Local artifact parsing | Low | Low |
| 12 | Policy load | 10.000 ms | 0.08% | Policy automation job | Medium | Medium |
| 13 | Process spawn | 3.018 ms | 0.02% | OS process creation | High | High |
| 14 | Script load | 1.333 ms | 0.01% | Observer registration | Low | Medium |
| 15 | Scan configuration | 1.000 ms | 0.01% | Passive scan configuration | Low | Low |
| 16 | Temporary cleanup | 0.257 ms | <0.01% | Secret plan removal | Low | High |

## Decision

1. **Persistent Worker: YES.** Known per-process startup plus post-plan process
   completion is 9,404.773 ms, or 71.36% of executing-job time in this workload.
2. Of startup, 2,569.546 ms (97.58%) is directly attributable to spawn, Java
   boot, add-on initialization, and network setup and is reusable in principle.
   The remaining 63.667 ms lacks a distinct marker.
3. The measured removable shutdown interval is 6,835.227 ms (99.996% of the
   shutdown total). This is an upper bound, because a persistent-worker protocol
   may still need per-job reset/flush work.
4. At least 28.64% remains unchanged under that upper-bound model.
5. Persistent workers still require scan configuration, context/seed import,
   optional authentication setup, policy setup, script registration, passive
   waiting/flushing, active scanning, exports, report finalization, evidence
   parsing, and credential-plan cleanup. Context creation remains unquantified
   until ZAP emits or the adapter introduces a direct boundary around it.
6. **Highest-ROI first implementation: persistent workers**, specifically because
   the measured lifecycle envelope is 71.36%. Passive wait is second (22.94%) but
   has higher evidence-quality risk; it should be investigated independently,
   not shortened based on this benchmark alone.

These gains are controlled-workload upper bounds, not a production speedup
guarantee. No optimization was implemented as part of this investigation.
