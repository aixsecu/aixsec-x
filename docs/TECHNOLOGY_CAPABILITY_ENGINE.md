# Technology Capability Engine

The engine is an optional deterministic planning layer between the existing
Inventory and scanner scheduling code. It consumes technology observations and
discovered endpoints already stored in `Inventory`; it does not detect
technologies, crawl targets, call a model, or alter findings and reports.

Enable it with:

```sh
export WEBX_TECHNOLOGY_CAPABILITY_ENGINE=on
export WEBX_PLANNER_MODE=balanced
```

`WEBX_PLANNER_MODE` accepts:

- `aggressive`: execute `LIKELY` payload families.
- `balanced`: execute `LIKELY` and `POSSIBLE` payload families.
- `thorough`: execute every family, including `UNLIKELY` families.

The engine defaults to `off`. When off, ZAP rule and Nuclei template selection
uses the original code path. Unmapped scanner rules/templates are also retained
when the engine is on because the engine has no evidence-based basis to remove
them.

Profiles live in `technology_capability.py`. Technology profiles declare
aliases, parents, and capabilities. Payload profiles declare supported
technologies, application features, required attack-surface facts, confidence
thresholds, and scanner selectors. The generic evaluation algorithm is shared
by every profile. Multiple observed stacks are accumulated rather than reduced
to one backend.

The engine writes three private artifacts into the scan evidence directory:

- `technology-capabilities.json` contains observed technologies, confidence,
  capabilities, supported/unsupported families, and observation provenance.
- `planner-capabilities.json` contains observed attack-surface evidence and the
  selected/available payload families.
- `planner-decisions.json` contains the decision level, evidence, profile,
  prioritization/skip reason, scanner-item skips, and benchmark data for every
  payload family.

Attack-surface signals come only from stored endpoint URLs, methods,
parameters, API-operation metadata, and authentication observations. Missing
upload, XML, template, serialization, authentication, GraphQL, or WebSocket
evidence lowers the relevant family. Missing evidence never permanently
disables a family because thorough mode always retains it.

The final CLI summary reports family counts before and after optimization,
skipped and executed families, deterministic planning time, total scan duration,
and percentage reduction.
