# AIXSEC-X 2.2.0 — Phase 2

Phase 2 cung cấp primitive có cấu trúc theo chuỗi:

```text
Discover → Authenticate → Execute → Compare → Record evidence
```

Nó không tự kết luận lỗ hổng authorization. Phase 3 sẽ đọc observations để lập
giả thuyết, lên kế hoạch kiểm thử và xác minh IDOR/BOLA/business logic.

## Auth context

Mỗi context được khóa vào một HTTP origin và có Session Engine/cookie jar riêng.
Do đó cookie của `user_A` không thể đi vào request của `user_B` hoặc `anonymous`.
Một phiên agent mới sẽ xóa toàn bộ context trong bộ nhớ.

Ví dụ cấu hình trực tiếp qua tool call:

```json
{
  "name": "user_A",
  "origin": "https://target.example",
  "transport": {
    "headers": {"X-CSRF-Token": "{{csrf}}"}
  },
  "login_steps": [
    {
      "method": "POST",
      "url": "https://target.example/login",
      "form": {
        "username": "${ENV:AIXSEC_USER_A}",
        "password": "${ENV:AIXSEC_PASS_A}"
      },
      "expected_status": [200, 302],
      "extract": {
        "csrf": {"from": "cookie", "name": "csrf_token"}
      }
    }
  ],
  "logout_step": {
    "method": "POST",
    "url": "https://target.example/logout"
  }
}
```

Secret hỗ trợ `env:NAME` khi toàn bộ giá trị là secret, hoặc `${ENV:NAME}` khi
nằm trong chuỗi như `bearer:${ENV:AIXSEC_TOKEN}`. Secret chỉ tồn tại trong bộ
nhớ process. Không lưu credential config vào inventory.

`transport` hỗ trợ:

- `auth`: `basic:user:pass`, `bearer:token`, `api_key:name:value`,
  `apiquery:name:value`;
- `headers`, `cookies`, `params` dạng object;
- biến `{{name}}` được lấy từ login extractor.

Login step hỗ trợ `method`, `url`, `headers`, `params`, `cookies`, `form`,
`json`, `body`, `follow_redirects`, `timeout`, `expected_status` và `extract`.
Extractor hỗ trợ `cookie`, `header`, `json` (dot path) và `body_regex`. Tối đa
12 bước/context, 16 context/process.

## Differential execution

`auth_compare` nhận 2–8 context và một request chung. Nó chạy tuần tự qua từng
session cô lập rồi ghi:

- status và final URL/redirect chain;
- content type, độ dài và SHA-256 body;
- tên header/cookie, không lưu giá trị cookie;
- JSON shape chỉ gồm tên field và type;
- pairwise status/redirect/shape/hash equality, length delta và body similarity.

Response body không được lưu trong auth observation. Request evidence dùng
redactor của HTTP Engine và bỏ body trước khi đưa vào observation. Raw body vẫn
có thể chứa dữ liệu nhạy cảm trong runtime, vì vậy ưu tiên form/JSON với tên field
rõ ràng và environment references.

Comparator không thay object ID, không sinh payload và không diễn giải khác biệt
thành vulnerability. Để kiểm thử ownership, caller phải cung cấp URL/object cụ
thể đã được phép kiểm tra, ví dụ cùng `/api/orders/42` dưới anonymous, user A,
user B và admin.

## Inventory

Kết quả `auth_compare` outcome `ok` được ingest vào `Endpoint.auth_observations`.
Mỗi observation giữ contexts, per-context response facts, pairwise comparisons
và `interpretation=facts_only`. Save/load tương thích inventory cũ không có field
này. `Inventory.api_inventory()` tiếp tục cung cấp operation inventory Phase 2.1.

## Scope và giới hạn

- Context chỉ gọi URL cùng scheme/host/port với origin đã cấu hình. Tool tạo
  context đi qua scope policy của agent; login step và comparator kiểm tra lại
  origin ở runtime.
- Redirect được theo thủ công tối đa 10 hop và bị chặn nếu đổi
  scheme/host/port, tránh làm rò custom auth header. Khi cần quan sát chính xác
  Location đầu tiên, đặt `follow_redirects=false`.
- Request timeout tối đa 60 giây; response tối đa 2 MB.
- Context là in-memory, không persist credential/session và không tự refresh
  token. Có thể gọi `auth_login` lại để tạo session mới.
- OAuth browser/device flows, MFA có tương tác, CAPTCHA và WebAuthn không được
  tự động hóa. Có thể dùng static token/cookie hợp lệ được cấp cho phiên test.
- Không chạy JavaScript login, không thực thi Postman scripts, không introspect
  GraphQL và không tự suy luận authorization vulnerability.

## Kiểm thử

```sh
python3 -B -m unittest tests.test_agent tests.test_api_discovery tests.test_auth_context bench.test_bench -q
```

Integration tests dùng HTTP server localhost để kiểm tra login cookie, token
extraction, session isolation, logout, anonymous/user/admin comparison, evidence
redaction, response bound và inventory persistence.
