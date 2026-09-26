# AIXSEC-X 3.0.0 — Phase 3

Phase 3 bổ sung ba primitive trên dữ liệu Phase 1/2:

```text
Inventory + TestHistory + Capabilities
                 │
                 ▼
          Dynamic re-planner
                 │
      ┌──────────┴──────────┐
      ▼                     ▼
Authorization /        SAST → DAST
business hypotheses    validation leads
```

Mọi output Phase 3 là kế hoạch, hypothesis hoặc correlation. Không primitive nào
tự chuyển thành confirmed finding. Finding vẫn phải qua request/response thật và
evidence guard hiện có.

## Dynamic planner

`dynamic_plan` đọc trực tiếp `Inventory`, `TestHistory`, `Ledger`, tool
capabilities và correlations của phiên agent. Model không truyền bản sao
inventory vào planner. Mỗi action có:

- `action_id`, priority, tool và arguments;
- reason và hypothesis/correlation liên quan;
- state `planned`, `blocked` hoặc `completed`;
- `blocked_by` cụ thể như thiếu auth context, control body hoặc path value thật.

Gọi lại planner sau tool result sẽ tạo plan mới. Action đã có record cùng
endpoint/parameter/vulnerability class trong TestHistory chuyển thành
`completed`. Tool không khả dụng chuyển thành `blocked`. Planner không tự chạy
action, không tự thay `{id}`, không tự chế body hay payload.

## Authorization reasoning

`authorization_reason` chỉ đọc structured output của `auth_compare`. Nó có thể
tạo các hypothesis:

- anonymous nhận response thành công ở endpoint có thể cần auth;
- context ngoài policy khai báo nhận response thành công;
- context khác owner khai báo nhận response thành công;
- hai user context nhận body thành công giống nhau.

`resource_owner` và `expected_allowed_contexts` là policy do operator khai báo,
không phải fact tự suy ra. Mỗi hypothesis giữ evidence, confidence và
`evidence_gaps`; `verdict` luôn false. Response giống nhau có thể chỉ là envelope
hoặc dữ liệu công khai, nên cần control object và kiểm tra nội dung/state thật.

## Business logic reasoning

Khai báo invariant trước bằng `business_rule_set`:

- `required_before`: action B chỉ được thành công sau action A;
- `max_successes`: giới hạn số lần action thành công trong một run;
- `numeric_bound`: min/max cho input field;
- `state_transition`: danh sách cặp trạng thái được phép.

`business_workflow_test` chạy 1–20 request thật, tuần tự, qua một auth context
đã cấu hình. Mỗi step có action, request và tùy chọn resource/inputs/from_state/
to_state. URL vẫn bị khóa theo origin của context; response tối đa 2 MB và
redirect ngoài origin bị chặn như Phase 2. Inputs/evidence được redaction trước
khi persist.

`business_reason` so observations với rules rồi tạo hypothesis nếu server trả
2xx cho hành vi lệch invariant. HTTP 2xx chưa chứng minh server-side state đã
thay đổi; evidence gap này luôn được giữ để bước xác minh đọc lại resource hoặc
database/API state.

## SAST → DAST correlation

`sast_scan` giờ trả structured data bên cạnh text:

- finding id, category, severity, file tương đối và line;
- route/parameter hint khi pattern trên cùng dòng cho phép trích;
- SHA-256 snippet, không đưa source snippet vào structured inventory;
- secret findings được đánh dấu và không đưa vào DAST correlation.

`sast_dast_correlate` chấm điểm route, parameter và filename/path hint với API
operations đã discover. Kết quả là validation lead. SQLi có route+parameter cụ
thể có thể tạo action `sqli_manual_test`; các category còn lại chỉ tạo
`http_request` control lead bị block bởi `manual_payload_and_control_required`.
Điều này tránh biến pattern heuristic không có dataflow thành exploit claim.

## Persistence và tools

Phase 3 state không chứa credential. Plans, rules, workflow observations,
hypotheses, structured SAST findings và correlations được lưu trong
`Inventory.analysis`, nên Phase 4 có thể đọc lại. Auth sessions vẫn chỉ tồn tại
trong memory và được reset mỗi agent run.

Tools mới:

- `dynamic_plan`, `phase3_status`;
- `authorization_reason`;
- `business_rule_set`, `business_workflow_test`, `business_reason`;
- `sast_dast_correlate`.

## Kiểm thử

```sh
python3 -B -m unittest tests.test_agent tests.test_api_discovery tests.test_auth_context tests.test_security_analysis bench.test_bench -q
```

Integration tests dùng localhost, không gửi traffic tới bên thứ ba. Chúng kiểm
tra re-planning, completed/blocked state, ownership reasoning, workflow order,
numeric bound, replay, state transition, SAST correlation, secret exclusion và
persistence.
