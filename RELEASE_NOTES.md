## Form/API discovery and browser coverage

- Enable bounded AJAX Spider by default, with configurable browser, clickable tags,
  depth and crawl states; raise the default process timeout to 600 seconds.
- Export HAR plus an independent form/input/API inventory, retaining parameter names
  and separate discovered/requested/tested states even without scanner alerts.
- Feed discovery gaps to the planner and retain matching captured POST bodies for
  endpoint-scoped active scans across methods.
- Attribute active requests with an executor-owned HTTP sender observer because
  HAR export may omit active scanner traffic; no finding is confirmed by this alone.
- Detect browser startup failures from the engine log even when ZAP exits zero.
- Add an opt-in localhost browser/form/POST integration test (`test_zap_live`).

# AIXSEC-X 4.2.0 — ZAP and evidence pipeline

- Baseline-before-LLM execution with ZAP AF, optional Wapiti or HTTP observation.
- Isolated ZAP sessions, bounded spider/AJAX/OpenAPI/passive and selected active rules.
- Structured evidence, private artifacts, graph links and candidate/confirmed separation.
- Deterministic missing-header validators and isolated HTTP evidence replay.
- Separate active scan, sqlmap, content discovery and data extraction policies.
- Timeout/error/partial/auth-unverified coverage survives model failure.
- Old agent behavior is explicitly available through WEBX_SCAN_BACKEND=legacy.
- See docs/ZAP_PIPELINE.md for setup, current validator coverage and budget limits.

# AIXSEC-X 4.1.0 — Context optimization

- Added bounded, ranked subgraph, evidence and planner-memory retrieval.
- Added modular system/planner/tool/policy/reasoning prompt composition and a
  deterministic token budget with protected current-action fields.
- Added fact-only history summarization and action-relevant tool schema selection.
- Added first-token, completion and overall Ollama timeout policies.
- Added prompt/retrieval/build/latency runtime metrics and comprehensive tests.

# AIXSEC-X 4.0.0 — Phase 4 autonomous intelligence

- Added a typed, serializable knowledge graph covering all required Phase 4
  entities with deterministic IDs, graph queries and immutable evidence nodes.
- Added knowledge-gap goal planning, separate adaptive planner memory,
  workflow transition inference and configurable cost/risk budgets.
- Added a checkpointable Observe → Reason → Plan → Execute → Learn → Replan
  runtime with atomic resume checkpoints and hash-verified deterministic replay.
- Added `WebXAgent.run_autonomous()` through the existing scope/risk dispatcher;
  Phase 1–3 APIs and the default interactive behavior remain compatible.
- Added focused unit tests and Phase 4 architecture documentation.

# AIXSEC-X 3.0.0 — Phase 3

## Dynamic Planner + Business/Authorization Reasoning + SAST→DAST

- `dynamic_plan` đọc trực tiếp live Inventory, TestHistory, Ledger và tool
  capabilities; re-plan thành action `planned/blocked/completed` có prerequisite.
- `authorization_reason` tạo hypothesis từ structured auth observations với
  owner/policy khai báo, evidence gaps và không tự tạo verdict.
- Business rules cho order, replay count, numeric bounds và state transitions;
  workflow executor chạy request thật qua auth context rồi reasoner so với rule.
- `sast_scan` trả structured findings không chứa source snippet; correlation
  ghép route/parameter/category với API inventory và tạo validation lead.
- Secret findings không đi vào DAST correlation. SAST pattern không được xem là
  bằng chứng exploitability.
- Plan, rules, workflow evidence, hypotheses và correlations persist trong
  `Inventory.analysis` cho Phase 4.

Chi tiết: [docs/PHASE_3.md](docs/PHASE_3.md).

Validation cuối:

```text
python3 -B -m unittest test_agent test_api_discovery test_auth_context test_security_analysis bench.test_bench -q
Ran 405 tests in 19.873s
OK
```

## AIXSEC-X 2.2.0 — Phase 2 complete

## Phase 2.2/2.3 — Auth và differential testing

- Auth Context Manager giới hạn 16 context; mỗi context có Session Engine và
  cookie jar riêng, khóa theo origin.
- Anonymous, static Basic/Bearer/API-key/cookie/header/query và login-based
  contexts. Secret có thể lấy từ `${ENV:TEN_BIEN}`.
- Login tối đa 12 bước, hỗ trợ form/JSON/raw request, status expectation và
  trích cookie/header/JSON path/body regex vào biến cho bước kế tiếp.
- Logout lifecycle xóa session, cookie jar và toàn bộ biến trích xuất kể cả khi
  request logout lỗi.
- `auth_compare` gửi cùng request qua 2–8 context và ghi status, redirect,
  content type, JSON shape, body hash, length delta và similarity. Output là
  facts-only, không tự gán nhãn IDOR/BOLA.
- Structured auth observations được lưu theo endpoint trong Attack Surface
  Inventory và giữ được qua save/load.
- Response body và secret không được lưu trong auth evidence; chỉ hash/shape và
  request evidence đã redaction. Response tải tối đa 2 MB.
- Tool mới: `auth_context_set`, `auth_context_list`, `auth_login`, `auth_logout`,
  `auth_context_remove`, `auth_compare`.

Hướng dẫn: [docs/PHASE_2.md](docs/PHASE_2.md).

Validation cuối dùng lệnh:

```text
python3 -B -m unittest test_agent test_api_discovery test_auth_context bench.test_bench -q
Ran 394 tests in 19.304s
OK
```

## Phase 2.1 — API Discovery

## Kết quả review nền 1.9.1

Source có Session Engine, crawler, ToolSpec adapter, evidence/redactor và
inventory dạng object trong bộ nhớ, lưu snapshot JSON. Không phải một source
không thể phát triển tiếp. Trước thay đổi, 339 regression test pass.

Khoảng trống Phase 2.1 xác nhận từ code: chưa có importer/discovery spec,
metadata riêng theo method, hợp nhất nguồn API có confidence, hoặc GraphQL
observations. Endpoint cũ chỉ giữ các tập method/param/auth/source.

## Đã bổ sung

- OpenAPI/Swagger JSON/YAML discovery và import; Postman collection import.
- Metadata theo operation: parameters, schema, responses, security, tags,
  operationId và nguồn tài liệu.
- API inventory canonical URL + method, hợp nhất crawler/JS/spec/HTTP,
  giữ observations khác nhau và lưu/load tương thích dữ liệu cũ.
- JSON response shape, GraphQL/GraphiQL/Apollo/Yoga/Hasura candidate hints.
- Hai tool `api_discovery`, `api_import`; CLI offline/network độc lập với LLM.
- Discovery dùng chung Session Engine, chặn redirect khác origin, giới hạn
  request/time, tải response tối đa 2 MB, giới hạn parser và reference expansion.
- README, tài liệu phạm vi/giới hạn, spec ví dụ và bộ test mới.

## Kiểm thử

Môi trường: Python 3.13 trên macOS; không cần gọi LLM, tool scanner ngoài hay
mục tiêu bên thứ ba. Integration tests mở cổng localhost tạm thời.

```text
python3 -B -m unittest test_agent test_api_discovery bench.test_bench -q
Ran 383 tests in 18.675s
OK
```

Gồm 339 test gốc, 31 test Phase 2.1 và 13 benchmark test. `git diff --check`
pass; CLI import `examples/openapi.yaml` xuất 2 operations thành công.

## Ranh giới với Phase 3

Phase 2 đã có đủ primitive Discover → Authenticate → Execute → Compare → Record.
AI dynamic planner, suy luận business logic/authorization, kết luận IDOR/BOLA,
SAST→DAST correlation và GraphQL introspection chủ động thuộc Phase 3.

Đây là importer/discovery theo phạm vi mô tả, không phải bộ validator bao phủ
mọi chi tiết OpenAPI/Postman. Xem [hướng dẫn và giới hạn](docs/PHASE_2_1.md),
đặc biệt external `$ref`, JSON Schema 3.1, Postman variables và JS động.
