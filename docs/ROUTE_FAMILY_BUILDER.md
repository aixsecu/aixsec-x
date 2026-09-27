# Deterministic Route Family Builder

## Architecture

The Active Scan flow is now:

```text
Discovery → Inventory/HAR request groups → Route Family Builder → Scheduler → Active Scan
```

`RouteFamilyBuilder` consumes the captured request groups already accepted by
`ScanSchedule.collect()`. It does not discover URLs, synthesize requests, choose
representatives, alter request IDs, or change scheduler ordering/concurrency.
It annotates each in-memory group with `route_family_id` and writes
`family.json` into the scan evidence directory before Active Scan scheduling.

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
- `representative_candidates`, currently always an empty array.

Raw bodies, cookies, credentials, and parameter values are not copied into the
artifact.

## Configuration and migration

`WEBX_ZAP_ROUTE_FAMILY_MODE=1` enables the builder and is the default. Set it to
`0` to restore the prior pipeline exactly: no builder invocation, no entry
annotations, and no `family.json`.

The scheduler continues to consume the same `ScanSchedule.entries`. Existing
history keys, batching, AutoConcurrency, barriers, request isolation, evidence,
and reports remain unchanged. No representative selection is implemented in
this phase. Consumers should treat `representative_candidates` as reserved and
must not infer scheduling decisions from it.

## Benchmark impact

CPU-only benchmark on 10,000 captured request groups:

- elapsed: 525.319 ms;
- 52.532 microseconds per group;
- 19,036 groups/second;
- eight expected semantic families.

This is a linear pre-scheduling pass. It performs bounded parsing and hashing
and does not add target requests. Run it with:

```sh
python3 bench/route_family_benchmark.py --groups 10000
```
