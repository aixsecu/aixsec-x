# Deterministic Route Family Builder

## Architecture

The Active Scan flow is now:

```text
Discovery → Inventory/HAR request groups → Route Family Builder → Scheduler → Active Scan
```

`RouteFamilyBuilder` consumes the captured request groups already accepted by
`ScanSchedule.collect()`. It does not discover URLs, synthesize requests,
alter request IDs, or change scheduler ordering/concurrency.
It annotates each in-memory group with `route_family_id` and writes
`family.json` into the scan evidence directory before Active Scan scheduling.

`RepresentativeSelector` then scores every member and uses deterministic greedy
set coverage to choose the smallest configured number of request groups. The
scheduler still receives ordinary, unmodified request-group dictionaries; only
non-selected family members are filtered from that input list.

The implementation is pure Python and deterministic. It uses no AI, LLM,
embedding, model call, network call, or learned state.

## Structural fingerprint

The canonical JSON fingerprint includes:

- HTTP method and request content type;
- path depth and ordered path tokens;
- query/body parameter names, locations, and structural JSON paths;
- literal values only for routing keys such as `action`, `route`, and
  `controller`, preserving application semantics;
- form and input signatures;
- DOM tag/attribute-name structure;
- normalized response-template hash;
- response content type, status, and ETag presence;
- authentication context.

The SHA-256 of that canonical structure is the fingerprint. Family IDs are the
stable `rf-` prefix plus its first 20 hexadecimal characters.

Normalization is deliberately narrow: UUIDs, numeric resource IDs, Unix/ISO
timestamps, high-entropy IDs, CSRF/XSRF/nonce/ETag values, and known generated
element IDs. Literal route words and slugs are retained. Consequently `/login`,
`/logout`, `/register`, and `/search` cannot collapse into one family. There is
no catch-all `/{slug}` or `/[a-z0-9-]+/` route normalization.

## Artifact contract

`family.json` contains:

- `family_id`;
- full `fingerprint`;
- structural fingerprint document;
- `members` with request ID, redacted URL, method, and auth context;
- `representative_candidates`, containing the selected request-group IDs.

Raw bodies, cookies, credentials, and parameter values are not copied into the
artifact.

`representatives.json` records every member's numeric score, score breakdown,
non-sensitive measurements, selected IDs, configured limits, scans before and
after selection, and a structural coverage estimate. Scores use log-scaled
response size, form count, input count, parameter count, response complexity,
unique parameter names, DOM complexity, and URL depth. Greedy selection first
maximizes newly covered structural features, then score, with request ID as the
stable tie-breaker. No random choice is involved.

## Configuration and migration

`WEBX_ZAP_ROUTE_FAMILY_MODE=1` enables the builder and is the default. Set it to
`0` to restore the prior pipeline exactly: no builder invocation, no entry
annotations, no filtering, and no family or representative artifact.

Representative limits default to 1 for families of 1–5 members, 2 for 6–30,
3 for 31–100, and 4 for larger families. They can be changed with:

- `WEBX_ZAP_ROUTE_FAMILY_REPRESENTATIVES_SMALL`;
- `WEBX_ZAP_ROUTE_FAMILY_REPRESENTATIVES_MEDIUM`;
- `WEBX_ZAP_ROUTE_FAMILY_REPRESENTATIVES_LARGE`;
- `WEBX_ZAP_ROUTE_FAMILY_REPRESENTATIVES_EXTRA_LARGE`.

The scheduler continues to consume request groups from `ScanSchedule.entries`.
The selected entries retain their complete captured request and metadata. Existing
history keys, batching, AutoConcurrency, barriers, request isolation, evidence,
and reports remain unchanged.

`WEBX_FAMILY_SCAN=on` (the default) replaces the scheduler input with the
selected request groups. `WEBX_FAMILY_SCAN=off` keeps family construction and
artifacts for observation but passes every original request group to the
scheduler. AutoConcurrency and worker scheduling do not inspect this setting.

Each scheduled representative carries `family_id`, `representative_id`, and
`member_count`. These fields are copied into ZAP coverage and normalized finding
evidence. Batched jobs also carry a family-reference list so evidence is matched
to the appropriate representative by redacted URL and HTTP method.

## Family evidence

After representative Active Scan completes, `family-evidence.json` is written
in the session evidence directory. It contains only ZAP Active Scan candidate
findings produced by representatives. Every entry includes the family ID,
representative ID and redacted URL, member URLs and count, rule IDs, and raw
evidence references (raw tool result, ZAP report, request, and response).

The artifact's policy is `candidate_only_no_validation`. Family-derived records
are excluded from automatic validation and the existing evidence validator
returns them unchanged as candidates. No family replay or validation mechanism
is performed by the evidence store itself.

## Divergence detection

After candidate storage, the deterministic divergence detector selects up to
`WEBX_FAMILY_DIVERGENCE_SAMPLES` additional non-representative members per
affected family (default 2). It replays the captured member through the same ZAP
Active Scan adapter using only the finding's rule IDs. No AI is involved.

For every candidate, replay evidence is compared against the representative's
HTTP status/content type/header-name structure, vulnerability category and
evidence text, affected parameter, HTTP method, and rule ID. All sampled members
must match for `family_confirmed`; otherwise each mismatching sampled member is
moved into a deterministic `rf-div-*` family and the finding is marked
`split_family` in `divergence.json`.

`divergence.json` also reports extra scans, avoided scans, and family
confirmation rate. This phase does not convert the underlying candidate finding
to a confirmed security finding; `family_confirmed` describes only whether the
representative evidence generalized across the sampled family members.

### Dynamic recursive split

When a sampled member diverges, representatives are rebuilt immediately for
both the remaining parent and each new child family. Already replayed members
are tracked by `(family_id, request_id)` and are not selected again in the same
family. The detector then continues with untested members and newly created
families until a generation has no divergence, no eligible replay remains, or
`WEBX_FAMILY_SPLIT_MAX_DEPTH` is reached (default 4).

`family-history.json` preserves every generation, parent/child split mapping,
family and representative counts before and after the split, tested-member
count, and deterministic coverage percentage. Family IDs are never reused, so
the complete lineage remains auditable after `family.json` is rebuilt.

### Family confidence

`confidence.json` contains a deterministic confidence record for every current
family: coverage score, confidence, validated member IDs, representative ratio,
and whether another replay is required. Representatives and successfully
attempted divergence members count as validated members.

Confidence is `0.8 × validated-member ratio + 0.2 × representative ratio`.
Additional replay is planned only while unvalidated members remain and the
score is below `WEBX_FAMILY_CONFIDENCE_THRESHOLD` (default `0.6`). The score is
recomputed before every recursive generation and after the final split. This
artifact is intentionally not included in user-facing reporting yet.

### Optional AI assistance

`WEBX_FAMILY_AI_ASSISTANCE=1` enables one constrained model call only when the
final confidence artifact still contains families requiring replay. It is
disabled by default, and `WEBX_FAMILY_AI_MAX_FAMILIES` limits metadata sent in
one invocation (default 20).

The model receives classification metadata, never authority over findings. It
may return only `suggest_merge`, `suggest_split`, or
`suggest_additional_replay`. Outputs are schema-filtered, stored as unapplied
`hypothesis` records in `family-ai-hypotheses.json`, and never mutate families,
findings, confidence, or scheduling. Unknown members/actions and finding-like
instructions are discarded. Evidence always wins.

The AI accounting benchmark reports the percentage of families sent for
assistance and the percentage of low-confidence cases subsequently resolved by
evidence. The latter is not an AI verdict and remains zero in the live artifact
until a separate evidence-backed workflow resolves a hypothesis.

Before scheduling, the pipeline logs original group count, family count,
effective representative/scheduler-input count, and percentage reduction. The
same values are persisted in `representatives.json` as `scheduler_input_groups`,
`family_scan`, and `reduction_ratio`.

## Benchmark impact

The benchmark now reports `scans_before`, `scans_after`, and structural
`coverage_estimate_percent` in addition to builder/selection runtime. It remains
CPU-only and performs no target requests.

- request groups / scans before selection: 10,000;
- semantic families: 8;
- scans after selection: 32 (four per 100+ family at the default limit);
- total scan reduction: 9,968 (99.68%);
- structural coverage estimate: 100%;
- combined build and selection elapsed: approximately 942 ms;
- approximately 94 microseconds per group;
- approximately 10,600 groups/second.

This is a linear pre-scheduling pass. It performs bounded parsing and hashing
and does not add target requests. Run it with:

```sh
python3 bench/route_family_benchmark.py --groups 10000
```
