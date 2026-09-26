# Active Scan Performance Baseline

Measured on 2026-09-26 with the installed macOS ZAP application, two isolated
Active Scan jobs, two workers, one explicitly allowed low-strength rule, and a
temporary localhost HTTP target. This is a controlled adapter/scheduler baseline,
not a claim about every production target. Re-run the benchmark against an
authorized representative application before committing to architecture work.

```bash
python3 bench/zap_performance_benchmark.py --jobs 2 --workers 2
```

## Measurements

| Metric | Result |
|---|---:|
| Representative requests | 2 |
| Request groups | 2 |
| Scan jobs | 2 |
| JVMs started | 2 |
| Contexts created | 2 |
| Policies created | 2 |
| Average total job | 14,923.843 ms |
| Average startup | 2,606.750 ms |
| Average add-on loading | 884.000 ms |
| Average context creation | 106.500 ms |
| Average policy loading | 4.500 ms |
| Average context import | 42.000 ms |
| Average passive wait | 3,029.000 ms |
| Average active scan | 760.500 ms |
| Average evidence parsing | 8.517 ms |
| Average report generation | 198.500 ms |
| Average shutdown | 7,276.364 ms |
| Worker utilization | 99.97% |
| Scheduler queue/dispatch | 0.059 ms/job |
| Scheduler barrier/AutoConcurrency/bootstrap wait | 0 ms |

## Percentage breakdown

```text
Shutdown ................ 48.76%
Passive Wait ............ 20.30%
Startup ................. 17.47%
Add-on loading ..........  5.92%
Active Scan .............  5.10%
Report ..................  1.33%
Context/policy/import ...  1.03%
Evidence Parse ..........  0.06%
Unattributed ZAP ........  0.04%
Scheduler/Preparation ...  0.00%
```

The timestamp coverage was 99.96%; 0.04% remained unattributed rather than being
assigned to a guessed phase.

## Ranked bottlenecks

| Rank | Phase | Share | Root cause | Plausible upper-bound gain | Complexity | Regression risk |
|---:|---|---:|---|---:|---|---|
| 1 | Shutdown | 48.76% | One JVM terminates after every small job | 34.1% | Medium | Medium |
| 2 | Passive wait | 20.30% | Passive scanner is drained twice per job plan | 14.2% | Medium | Medium |
| 3 | Startup | 17.47% | A new JVM initializes for every job | 12.2% | High | High |
| 4 | Add-on loading | 5.92% | Add-ons initialize in each JVM | 4.1% | High | High |
| 5 | Active scan | 5.10% | Rule execution and target response time | 3.6% | High | High |
| 6 | Report | 1.33% | HAR/URL export and JSON report per job | 0.9% | Medium | Medium |
| 7 | Context/policy/import | 1.03% | Per-job context, policy and seed import | 0.7% | Medium | Medium |
| 8 | Evidence parsing | 0.06% | Local artifact parsing | negligible | Low | Low |

These gains are conservative planning estimates (70% of the measured phase), not
promised end-to-end improvements. Startup, add-on loading and shutdown are related;
their gains must not be added independently when one change removes several phases.

## Decisions

1. **Persistent ZAP Workers: YES.** Startup, add-on loading and shutdown account
   for 72.15% of measured time. If persistence removes 80% of that combined cost,
   the estimated end-to-end reduction is about 57.7% (roughly 2.36x throughput in
   this overhead-dominated workload). Complexity and isolation regression risk are high.

2. **Context Reuse: NO, not as a standalone priority.** Context creation, policy
   loading and import total only 1.03%. Even eliminating them entirely cannot materially
   change this baseline. Re-evaluate after persistent workers change the denominator.

3. **Route Clustering: YES, after worker lifecycle work and only for proven-compatible
   groups.** The measured average batch size was 1.0, so all lifecycle, passive-wait and
   reporting costs were repeated. A conservative initial estimate is 20–35% for compatible
   small-job workloads; validate isolation and evidence attribution before implementation.

4. **Scheduler redesign: NO.** Scheduler time rounded to 0.00%, worker utilization was
   99.97%, and barrier/bootstrap/AutoConcurrency waits were zero. This benchmark provides
   no evidence that scheduler architecture is the bottleneck.

## Recommended order

1. Investigate persistent worker lifecycle and shutdown accounting: estimated 40–58% reduction.
2. Reduce repeated passive drains/report lifecycle where semantics permit: estimated 10–20%.
3. Add conservative compatible-route clustering: estimated 20–35% on small-job workloads,
   measured again after steps 1–2 because gains overlap.
4. Re-measure context reuse; current standalone estimate is at most 1.03%.
5. Do not redesign the scheduler without a representative run showing low utilization or
   material scheduler/barrier wait.

