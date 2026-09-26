# AIXSEC-X 2.1.4 — API Discovery

This document describes the four Phase 2.1 milestones: discovery foundation,
API metadata, operation merge/provenance, and GraphQL/JSON hints. Phase 2.2/2.3
is now implemented in 2.2.0; see [Phase 2 auth and differential testing](PHASE_2.md).

## Run without an LLM

```sh
python3 -m pip install -r requirements.txt
python3 -m api_discovery --url https://example.test/openapi.yaml \
  --document examples/openapi.yaml --output /tmp/api-inventory.json
```

The command above is offline. To explicitly request bounded GET discovery:

```sh
python3 -m api_discovery --url http://127.0.0.1:8000/ \
  --discover --max-requests 24 --output /tmp/api-inventory.json
```

The agent also exposes `api_discovery(url, max_requests)` and
`api_import(url, document)` through its existing ToolSpec/scope/structured-result
pipeline. `document` is JSON/YAML text, not a filesystem path. CLI `--url` is an
explicit scope origin; CLI discovery does not read WEBX_TARGETS. Agent calls use
its normal scope policy before execution. All derived network destinations stay
on the start URL's scheme, host and port.

## Coverage

- Swagger 2.0 and OpenAPI 3.0/3.1 JSON/YAML: paths, methods, server/basePath,
  relative server URLs, server-variable defaults and operation/path overrides.
- Path/query/header/cookie/body/form parameters; operation overrides by name and
  location. Request bodies, response schemas, required/nullable/enum/format,
  compositions, tags, summary, description, operationId, consumes/produces.
- Security requirements preserve OR alternatives, AND scheme groups, scopes and
  explicit anonymous overrides. Security scheme metadata covers Basic/Bearer,
  API key (header/query/cookie), OAuth2 and OpenID Connect.
- Local JSON-pointer references are expanded within bounds. Recursive, missing
  and external references remain explicit `$ref` values with warnings. External
  references are never downloaded. This is an inventory importer, not a complete
  OpenAPI validator; 3.1 JSON Schema dialect evaluation and `$ref` sibling semantics
  are not implemented. Callbacks/webhooks are not traversed.
- Common spec/UI paths, literal Swagger `url:` / ReDoc `spec-url` references,
  inline JS hints through the existing crawler parser. Dynamic JS is not run;
  external JS bundles and Swagger configUrl files are not fetched specially.
- Postman collection 2.x: nested folders, collection variables in raw URLs,
  methods, parameter names, raw JSON body shape and inherited auth type. Script
  execution, environment files, dynamic variables and request execution are not
  supported. Unresolved/foreign URLs are skipped with warnings.
- Observed JSON shape inference stores types/property names without values or
  guessed required fields. GraphiQL/Apollo/Yoga/Hasura markers and GraphQL error
  hints create **candidates**, not confirmed GraphQL services. No introspection.

## Inventory and evidence

`Inventory.api_inventory()` returns one record per canonical URL + method;
query values and fragments are excluded, query names are parameters. Trailing
slashes and different methods remain distinct. It does not guess that `/users/1`
matches `/users/{id}`. `UNKNOWN` is preserved without inventing GET.

Each operation keeps sources, maximum source confidence and deduplicated
observations. Conflicting declarations are retained rather than overwritten.
Confidence 1.0 means declared by a spec/Postman document or directly observed;
0.8 means JS hint and 0.6 means HTML/GraphQL hint. This is not a probability of a
vulnerability or of successful authenticated execution.

Existing URL/query inventory views remain for compatibility. New consumers
should use `api_inventory()`; legacy views may additionally contain old query
shapes. Save/load keeps `api_operations`, while old inventories without that
field continue to load. The existing on-disk schema remains additive version 1.

Evidence includes document source URL and SHA-256 of canonical parsed content;
HTTP discovery also records response status and SHA-256 of received bytes.
These hashes have different meanings. Discovery stores no raw response bodies,
credentials or replay records. Retain source specs separately if later audit
requires the full document. API observations from `http_request` retain its
existing redacted evidence and optionally a response shape. Schema examples,
defaults and Postman values are omitted, while property names remain available.
Free-text descriptions and enums from specs are still untrusted document content;
this is not a general-purpose secret scanner for arbitrary prose.

## Bounds and limitations

Discovery defaults to 24 GET requests, a 90-second scheduling budget and
15-second request timeouts. Redirects consume the same budget, are handled
manually and cannot leave the origin. Response downloads are capped at 2 MB
of decoded content; parser trees/references have depth/node limits. A request
already in progress can outlive the scheduling deadline (requests timeout is
an inactivity timeout). Shared Session Engine cookies/proxies are reused.
Foreign declared API servers are skipped, not silently remapped to the target.
No network test was performed against a third-party target.

## Validation

```sh
python3 -m unittest tests.test_agent tests.test_api_discovery bench.test_bench -q
```

Tests require permission to bind ephemeral localhost ports. They cover parser
semantics, secret-value omission, malformed/cyclic inputs, provenance merge,
persistence, scope/redirect bounds and a real Session Engine cookie/redirect/spec
flow. See `RELEASE_NOTES.md` for the final test count.

Implementation references: [OpenAPI 3.0.3](https://spec.openapis.org/oas/v3.0.3.html)
and [Swagger 2.0](https://swagger.io/specification/v2/).
