# Phase 4 — Knowledge and Autonomous Runtime

Phase 4 reorganizes facts and coordinates existing tools. It does not add a
scanner or payload library. All execution continues through `WebXAgent._dispatch`,
so scope checks, risk approval and tool timeouts remain authoritative.

## Modules

| Module | Responsibility |
|---|---|
| `autonomy/knowledge_graph.py` | Typed nodes, deterministic edges, queries and JSON serialization |
| `autonomy/goal_planner.py` | Knowledge-gap discovery and information-gain/cost action selection |
| `autonomy/planner_memory.py` | Separate success/failure strategy memory without evidence or secrets |
| `autonomy/workflow_model.py` | Observed transition inference and path navigation |
| `autonomy/cost_model.py` | Estimated action cost and consumable execution budgets |
| `autonomy/runtime.py` | Observe → Reason → Plan → Execute → Learn → Replan loop |

The graph represents endpoints, parameters, auth contexts, observations,
evidence, test results, business rules, hypotheses and SAST findings. IDs are
content-derived. Graph serialization is sorted, which makes snapshots stable.
Evidence nodes are append-only: adding different content under an existing
evidence ID fails. Query results are defensive copies.

Planner memory is deliberately outside the graph and evidence store. It saves
only a hashed strategy identity, tool name, counters, aggregate gain/cost and a
bounded failure reason. Credential values and response evidence are excluded.
An identical strategy that failed is blocked until the caller explicitly
chooses a retry policy.

## Goal-driven planning

`GoalDrivenPlanner` supports `coverage`, `authorization`, `business_logic`,
`sast_dast`, `workflow`, and custom objectives. Each cycle:

1. queries the graph and workflow model;
2. identifies missing observations or reasoning;
3. maps a gap to an existing tool action;
4. checks capabilities, prior failures and execution budget;
5. ranks executable actions by expected information gain per weighted cost.

The legacy `security_analysis.manager().plan(...)` API remains available. It
now incorporates this goal planner while retaining the Phase 3 response fields
and validation candidates used by existing integrations.

## Runtime and checkpoints

Applications can call `WebXAgent.run_autonomous(goal, max_cycles,
checkpoint_path)`. The method creates or resumes an `AutonomousRuntime`, then
routes every selected action through the normal dispatcher. The runtime saves
checkpoints with an atomic replace and includes graph, memory, workflow,
budget consumption, state and a deterministic result journal.

Replay verifies every result hash and applies stored results without invoking
the executor. Checkpoints never mutate Phase 1–3 evidence. Long runs can stop
at a cycle limit, budget boundary or interruption callback and resume later.

Environment controls:

```text
WEBX_AUTONOMY=1
WEBX_AUTONOMY_CHECKPOINT=/path/to/aixsec.checkpoint.json
WEBX_AUTONOMY_RESUME=1
WEBX_AUTONOMY_MAX_ACTIONS=100
WEBX_AUTONOMY_MAX_REQUESTS=500
WEBX_AUTONOMY_MAX_SECONDS=3600
WEBX_AUTONOMY_MAX_RISK=20
```

Phase 4 is opt-in, preserving the interactive loop and all Phase 1–3 APIs.
Budget request counts are estimates from tool profiles; target-side redirects
or tool internals can consume more network activity. Scope policy and operator
approval remain the hard execution controls.
