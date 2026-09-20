# AIXSEC-X — AI Web Exploitation Assistant (local LLM, Kali Linux)

| Ngôn ngữ | Tệp |
|---|---|
| **Tiếng Việt** | **README.vi.md** (tệp này) |
| English | [README.md](README.md) |

**AIXSEC-X** — AI Web Exploitation Assistant · thương hiệu **aixsecu.com**
Dùng **local LLM (Ollama)** — không cần cloud, không API key.
Agent-grade: function calling, scope pinning, validation loop, finding ledger.

> ⚠️ **Chỉ dùng trên target bạn sở hữu hoặc có ủy quyền rõ ràng.**
> Bạn chịu trách nhiệm pháp lý cho mọi hành động với tool này.

## Cài đặt (Kali)

Ollama có thể chạy **ngay trên Kali** hoặc **trên máy khác** (máy chủ trong LAN,
VPS, máy Windows…) — máy Kali chỉ trỏ URL sang. Chọn **1 trong 4 cách** ở bước 1:

### Cách A — Ollama chạy ngay trên Kali (local, đơn giản nhất)

```bash
# trên Kali
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:7b        # cân bằng chất lượng/tốc độ (khuyên dùng)
# hoặc: ollama pull llama3.2:3b   (nhẹ)
# hoặc: ollama pull qwen2.5:14b   (chất lượng hơn, RAM ~10GB)
# mặc định là http://localhost:11434 — không cần set biến gì thêm
```

### Cách B — Ollama trên máy khác trong LAN (server riêng)

```bash
# === trên MÁY CHỦ (máy cài Ollama, ví dụ IP 192.168.1.50) ===
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:7b

# mặc định Ollama chỉ nghe localhost — phải bind 0.0.0.0 để LAN truy cập:
sudo systemctl edit ollama
#   -> thêm 2 dòng rồi lưu (Ctrl+O, Enter, Ctrl+X):
#   [Service]
#   Environment="OLLAMA_HOST=0.0.0.0:11434"
sudo systemctl daemon-reload && sudo systemctl restart ollama
sudo ufw allow 11434/tcp      # mở firewall

# === trên máy KALI (client, không cài Ollama) ===
export WEBX_OLLAMA_URL="http://192.168.1.50:11434"
```

### Cách C — SSH tunnel (không mở port, an toàn nhất)

```bash
# trên máy KALI — mở tunnel tới máy chủ Ollama, giữ terminal này mở
ssh -N -L 11434:127.0.0.1:11434 user@192.168.1.50

# trên terminal Kali khác:
export WEBX_OLLAMA_URL="http://127.0.0.1:11434"
# -> Ollama nhìn như local, KHÔNG cần sửa systemd/firewall trên máy chủ
```

### Cách D — Cloudflare tunnel (truy cập từ internet sau NAT)

```bash
# === trên MÁY CHỦ Ollama ===
cloudflared tunnel --url http://localhost:11434
# lấy URL dạng https://xxxx.trycloudflare.com

# === trên máy KALI ===
export WEBX_OLLAMA_URL="https://xxxx.trycloudflare.com"
export WEBX_OLLAMA_AUTH="Bearer <token>"   # khuyến nghị đặt Basic Auth ở reverse proxy
```

> ⚠️ Mọi cách: **pull model trên MÁY CHỦ** (máy chạy Ollama), không pull trên Kali.

**Kiểm tra trước khi chạy agent** (`--check-ollama` bắt được 3 lỗi: chưa bind
0.0.0.0 / firewall / model chưa pull):

```bash
python3 agent.py --check-ollama
```

```
[✓] Ollama server: http://192.168.1.50:11434  (version 0.5.4)
[i] Models on server (2): qwen2.5:7b, llama3.2:3b
[✓] WEBX_MODEL='qwen2.5:7b' found on server — ready to use.
```

Lỗi `Cannot reach Ollama at ...` → máy chủ chưa set `OLLAMA_HOST=0.0.0.0`
(Cách B) hoặc firewall chưa mở `11434/tcp`. Lỗi
`WEBX_MODEL ... NOT found on server` → chạy `ollama pull qwen2.5:7b` trên MÁY CHỦ.

### Python venv (sửa lỗi PEP 668 trên Kali) + dependencies

Kali quản lý Python theo chế độ *externally managed*, nên `pip install` trần sẽ
báo lỗi `error: externally-managed-environment` (PEP 668). Giải pháp là dùng
virtual environment:

```bash
cd aixsec-x
python3 -m venv .venv          # nếu thiếu 'venv': sudo apt install -y python3-venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Mỗi lần chạy agent bạn phải `source .venv/bin/activate` trước — nếu không sẽ
báo thiếu `requests`. Để tiện, thêm alias vào `~/.zshrc` (shell mặc định của
Kali là zsh; dùng `~/.bashrc` nếu bạn dùng bash):

```bash
alias aixsec='cd ~/aixsec-x && source .venv/bin/activate && python3 agent.py'
```

### System tools trên Kali (áp dụng cho cả 4 cách)

```bash
which nuclei ffuf sqlmap httpx subfinder whatweb wafw00f nikto arjun wapiti \
  || sudo apt install -y nuclei ffuf sqlmap httpx subfinder whatweb wafw00f nikto arjun wapiti

# (tùy chọn) SecLists cho ffuf
sudo apt install -y seclists
```

## Chạy

### Cách 1 — nhập trực tiếp trên màn hình (không cần env)

```bash
cd aixsec-x
source .venv/bin/activate
python3 agent.py        # interactive — hỏi từng mục, để TRỐNG mục không dùng
```

```
[*] No web target declared (WEBX_TARGETS).
    Enter authorized targets, comma-separated
    (e.g. https://abc.vn,10.0.0.0/8) — press ENTER to skip if
    this session is SOURCE-CODE ANALYSIS only:
aixsec-target> https://abc.vn
[*] No source directory declared (WEBX_SRC_DIRS).
    Enter code directories allowed for SAST scanning, comma-separated
    (e.g. /var/www/html) — press ENTER to skip if sast_scan is unused:
aixsec-src> /var/www/html
```

3 kịch bản đều OK: **chỉ web** (src để trống), **chỉ SAST** (target để trống),
**cả 2**. (Chương trình hiển thị hướng dẫn bằng tiếng Anh — phần trên là đầu ra
thực tế.)

### Cách 2 — qua env (bắt buộc cho --non-interactive/--oneshot)

```bash
cd aixsec-x
source .venv/bin/activate
export WEBX_TARGETS="https://example.com"        # target web (để trống nếu chỉ SAST)
export WEBX_SRC_DIRS="/path/to/source"           # thư mục source (để trống nếu không dùng SAST)
python3 agent.py                                  # interactive
python3 agent.py --recon                          # recon sơ bộ trước
python3 agent.py --non-interactive                # tự động chạy
```

Chế độ `--non-interactive`/`--oneshot` chỉ đọc env (không hỏi) — dùng cho script/CI.

### Cấu hình qua env

| Var | Mặc định | Ý nghĩa |
|---|---|---|
| `WEBX_TARGETS` | *(trống)* | Target được ủy quyền, phân tách bằng dấu phẩy (URL/domain/CIDR) |
| `WEBX_SRC_DIRS` | *(trống)* | Thư mục source code được phép quét SAST, phân tách bằng dấu phẩy (bắt buộc khi dùng `sast_scan`) |
| `WEBX_MODEL` | `qwen2.5:7b` | Model Ollama (gợi ý: `huihui_ai/qwen3.5-abliterated:9b`) |
| `WEBX_THINK` | `0` | `1`=bật thinking mode (không khuyến nghị khi dùng function calling) |
| `WEBX_AUTO_EXEC` | `ask` | `ask`=hỏi operator với tool noisy/active; `safe`=chỉ tự chạy tool an toàn; `all`=tự chạy hết (rủi ro) |
| `WEBX_MAX_ROUNDS` | `8` | Số vòng tool-call tối đa mỗi lượt (thấp hơn = nhanh/rẻ hơn; model 9B trên máy 4 vCPU có thể mất 20–30 phút/vòng) |
| `WEBX_TOOL_TIMEOUT` | `90` | Timeout mỗi tool (giây) |
| `WEBX_LLM_TIMEOUT` | `300` | Timeout tối đa chờ model trả lời mỗi lượt (giây); model 9B trên CPU có thể mất 1–3 phút |
| `WEBX_STREAM` | `1` | `1`=stream NDJSON từ Ollama, agent hiển thị live reasoning + nội dung đang sinh + thời gian mỗi lượt; `0`=tắt (chờ response đầy đủ, không có hiển thị live) |
| `WEBX_OLLAMA_URL` | `http://localhost:11434` | Endpoint Ollama (local / máy khác / tunnel) |
| `WEBX_OLLAMA_AUTH` | *(trống)* | Header Authorization gửi tới Ollama: ghi đủ `Bearer xyz`/`Basic abc` hoặc chỉ token (tự thêm `Bearer `) — dùng cho tunnel/proxy có xác thực |
| `WEBX_NUM_CTX` | `16384` | Context window (token) |
| `WEBX_TEMPERATURE` | `0.1` | Nhiệt độ sampling |
| `WEBX_PROMPT_STYLE` | `auto` | `auto`=heuristic theo tên model (≤9B→compact, ≥14B→full); `compact`=prompt ngắn cho model nhỏ; `full`=prompt đầy đủ |
| `WEBX_OUTPUT_CAP` | `5000` | Giới hạn ký tự output tool đưa vào context |
| `WEBX_NUM_PREDICT` | `0` | **v1.4.2** giới hạn cứng số token model sinh mỗi lượt. `0`=không giới hạn (mặc định). Đặt `512-2048` nếu model viết essay dài làm chậm từng round — rủi ro: final JSON có thể bị cắt cụt nếu đặt quá thấp |

Để env chạy vĩnh viễn, thêm vào `~/.zshrc` (shell mặc định của Kali là zsh;
dùng `~/.bashrc` nếu bạn ở bash):

```bash
# ~/.zshrc
export WEBX_MODEL="huihui_ai/qwen3.5-abliterated:9b"
export WEBX_THINK=1
export WEBX_TARGETS="https://example.com"
export WEBX_SRC_DIRS="/var/www/html"
export WEBX_STREAM=1
export WEBX_LLM_TIMEOUT=300

# sau đó: source ~/.zshrc   (hoặc mở terminal mới)
```

### Màn hình live (streaming)

Khi model đang xử lý, AIXSEC-X hiển thị ngay trên màn hình để bạn không phải
chờ mù:

```
[*] Round 1/8 — model processing...
  ✦ think: Phân tích endpoint /login, thử SQLi ở param id...   (dim — reasoning)
  ▸ Khai thác...                                                       (xanh — nội dung)
  └ model finished in 42.3s
[→] http_probe({"url": "https://example.com/"})
[✔] http_probe → outcome=ok (1.2s)
```

- `✦ think:` = reasoning của model (nếu model có thinking, vd `huihui_ai/qwen3.5-abliterated:9b` + `WEBX_THINK=1`).
- `▸` = nội dung model đang sinh ra. Token được **buffer và wrap** theo độ rộng
  terminal (dòng nối `↳`) thay vì in 1 token/dòng — nên report JSON dài cuối
  phiên không còn làm ngập màn hình (~700 dòng → <50 dòng); giới hạn cứng 200
  dòng nội dung mỗi lượt.
- Mỗi lệnh tool được in trước khi chạy `[→]` và kết quả kèm thời gian thực thi `[✔/✗]`.
- Tắt bằng `WEBX_STREAM=0`; nếu thấy function-calling bị lỗi khi stream, thử tắt hoặc tắt `WEBX_THINK`.

### Tên wordlist cho `ffuf_dir` (hết lỗi đường dẫn)

`ffuf_dir` tự phân giải tên wordlist ngắn/mơ hồ thành file thật, nên tham số sai
không còn đốt timeout 120s:

- **Alias:** `common`, `big`, `top500`, `raft`, `raft-medium`, `raft-small`,
  `raft-large`, `dirbuster` / `dirbuster-small|medium|big`, `combined`.
- **Tên trần / đường dẫn SecLists:** `common.txt`, `big.txt`, `SecLists/common-words.txt`,
  `raft-medium-directories/2.3medium.txt` … được tìm trong
  `/usr/share/seclists/Discovery/Web-Content` (+ thư mục wordlist của `ffuf`/`dirb`).
- Không khớp gì → tool trả **lỗi thân thiện liệt kê thư mục/alias hợp lệ** để
  model sửa lại lệnh ở lượt sau thay vì đoán mò. (Cần gói `seclists`/`ffuf`, tùy chọn.)

### Bộ chống lặp lại tool-call

Agent không được phép đốt rounds để gọi lại đúng thứ đã chạy:

- **Dedup (chống trùng)** — gọi tool lại với **đúng tham số cũ** sẽ trả
  `outcome=duplicate` kèm outcome của lần chạy trước; tool KHÔNG bị thực thi lại.
- **Chặn cứng sau 3 lần fail** — tool fail ≥3 lần trong phiên (vd
  `nuclei_scan`/`param_discovery` khi máy thiếu binary `nuclei`/`arjun`) sẽ bị
  chặn (`outcome=blocked`) và model được chỉ dẫn đổi chiến lược (kiểm tra
  binary/network, đổi tool khác) thay vì thử lại vô hạn.
- **Chặn theo URL** — một `(tool, URL)` từng fail trong phiên
  (`error`/`scope_rejected`) sẽ bị chặn (`outcome=blocked`) ngay cho cùng URL,
  *trước* bước xin phép operator, dù tham số khác có đổi. Chặn được chiêu model
  gọi lại `nuclei_scan` với `severity low→high` (hoặc đổi `tags`/`wordlist`)
  trên cùng target. URL nào chạy thành công lại thì được bỏ khỏi danh sách chặn.
- **Dừng sớm (early stop)** — nếu một round chỉ toàn `duplicate`/`blocked`
  (tức không tool nào sinh thông tin mới), phiên kết thúc ngay và model bị ép
  trả final JSON từ dữ liệu đã thu thập — không đốt nốt các round còn lại cho
  vòng lặp thoái hóa (vd model cứ stream "(calling tools...)" mà không chịu
  gọi tool nào).
- Mọi tool-message đưa lại cho model đều kèm ghi chú khi tool đã fail ≥2 lần:
  *"Tool đã fail N lần phiên này — đừng gọi lại trừ khi đổi tham số/chiến lược."*

Nhờ đó các phiên chạy CPU-only không đốt hết từng round (75–186s/round) cho
mấy tool đang hỏng. Nếu thấy `error`/`blocked` lặp lại ở `nuclei_scan` hoặc
`param_discovery`, hãy kiểm tra binary trước: `which nuclei arjun`.

### Lệnh interactive

```
root@aixsec-x:~# Phân tích https://example.com              → agent tự gọi tool + trả kết luận
root@aixsec-x:~# Quét nuclei severity high                  → tấn công mục tiêu
root@aixsec-x:~# /findings                                  → xem ledger (candidate/confirmed/ruled_out)
root@aixsec-x:~# /report                                    → xuất report markdown
root@aixsec-x:~# !! nmap -p- 10.0.0.5                       → chạy shell trực tiếp (tự chịu trách nhiệm)
root@aixsec-x:~# q                                          → thoát
```

## Cơ chế an toàn (làm khác METATRON)

1. **Scope pinning** — tool call có URL/host ngoài `WEBX_TARGETS` bị từ chối bởi `scope.py` (không phụ thuộc LLM tự kiềm chế).
2. **Injection guard** — output tool (body từ web thù địch) được strip marker/ANSI/control chars trước khi vào context model.
3. **Validation loop** — LLM chỉ tạo `candidate`; `confirmed` chỉ sau bước xác minh (`ledger.py` status machine) hoặc operator chốt.
4. **Approval flow** — tool noisy/active (nuclei, sqlmap, ffuf, nikto, wapiti_scan) mặc định hỏi operator trước khi chạy.
5. **Function calling** — Ollama `tools` API thay regex `[TOOL:]` → args có cấu trúc, validate được.
6. **Không credential hardcode** — mọi thứ qua env.
7. **Bộ chống lặp lại** — tool call giống hệt nhau bị dedup (`outcome=duplicate`,
   không thực thi lại) và tool fail ≥3 lần trong phiên bị chặn cứng
   (`outcome=blocked`); model được chỉ dẫn đổi chiến lược thay vì retry vô hạn.

## Tool registry

| Tool | Loại | Rủi ro | Ghi chú |
|---|---|---|---|
| http_probe / headers_recon / dns_lookup | recon | safe | Python requests |
| sast_scan | sast | safe | Source-code scan: pattern heuristic (PHP/Python/JS/Java) + secret scan; tùy chọn semgrep/gitleaks; scope qua WEBX_SRC_DIRS |
| waf_detect (wafw00f) / detect_cms (whatweb) | recon | safe | fingerprint |
| subdomain_enum (subfinder) | recon | safe | |
| param_discovery (arjun) | recon | noisy | |
| nuclei_scan | active | active | `-severity`, `-tags` |
| ffuf_dir | active | active | SecLists common.txt |
| sqlmap_check | active | active | `--batch --smart --current-user --banner` |
| sqlmap_runner | active | active | **v1.4.7:** sqlmap BOUNDED — bước khai thác ĐẦU TIÊN sau SQLi CONFIRMED. argv kỷ luật: `--batch`, `--technique` (dedupe + uppercase), `--dbms` chỉ khi != auto, `--data` cho form POST, `--threads 1 --level 1 --risk 1 --timeout 15 --retries 1 --flush-session`. `timeout` clamp 30–600 s; `run_cmd` timeout = min(clamp, cap TOOL_TIMEOUTS 300). technique/dbms không hợp lệ → `[!]` outcome=error, KHÔNG chạy sqlmap. Marker → `[✓] sqlmap XÁC NHẬN khai thác`; "no parameter(s) found" → `[-]` (outcome ok); không marker → `[-]` không thấy dấu hiệu khai thác. Output giới hạn 4000 ký tự |
| sqli_manual_test | active | active | **v1.4.4 v2:** quote-differential (`test'`/`test''`) trước — xác nhận chèn KHÔNG cần engine/SLEEP; fallback time-based SLEEP/WAITFOR DELAY theo `engine=mysql\|mssql\|auto` (auto đoán từ headers: ASP.NET/IIS → mssql, PHP → mysql). **v1.4.5:** khi CONFIRMED tự in khối `[→] BƯỚC TIẾP THEO` (sqli_blind_extract → generate_poc → poc_executor) — model không dừng ở verdict. **v1.4.6:** khối next-step khâu sẵn `known_confirmed:true` (bỏ qua lưới 9 probe — lỗi đã xác nhận); MỌI probe status-0 → nghi WAF chặn payload → in `sqlmap ... --technique=E --batch` (`--form` nếu POST). **v1.4.7:** khối next-step giờ = sqlmap_runner FIRST (bounded) sau CONFIRMED; sqli_blind_extract/generate_poc/poc_executor CHỈ fallback khi sqlmap_runner không ra dữ liệu |
| sqli_blind_extract | active | active | **SQLi blind KHÔNG sqlmap** (Python thuần): detect + extract dữ liệu, hỗ trợ query `?id=1` VÀ path `/search/123.html`; **v1.4.4:** `engine=mysql\|mssql` (mssql = `'; IF (..) WAITFOR DELAY '0:0:n'-- -`, version/user qua `DB_NAME()`/`SUSER_SNAME()`; tables/dump mssql chưa hỗ trợ → `sqlmap --dbms=mssql`). **v1.4.5:** khai thác FORM POST qua `method`/`param`/`data` (body form-encoded, mode=form) + oracle ERROR-BASED MSSQL (0 giây: lỗi conversion lộ @@VERSION/DB_NAME()/SUSER_SNAME()) ưu tiên TRƯỚC time-based; oracle không ăn mới fallback WAITFOR DELAY. **v1.4.6:** shape oracle SỬA theo ground-truth — chỉ quote-then-paren `') AND CONVERT(int,(..))-- -` / `')) AND ...` ăn (context LIKE có ngoặc; `' AND CONVERT` trần fail); WAF burst detection — ≥2/3 probe status-0 (kết nối bị reset ~0.02s) → dừng sau ĐÚNG 3 request oracle; `known_confirmed:true` (lỗi đã xác nhận phiên trước → bỏ lưới 9 probe); nghi WAF → hướng dẫn `sqlmap --technique=E` (kèm `--form` khi method=post). **v1.4.7:** oracle im lặng (không lỗi conversion) + time-based chết + action≠detect → `_has_data_channel()` fail-fast → outcome=error "Oracle trích xuất im lặng" + hướng sqlmap_runner/sqlmap_cmd (`--dbms=mssql --technique=BEUSTQ`); SỬA regression v1.4.6 trả `[+] version:` rỗng kiểu thành công |
| generate_poc | sqli | safe | **Tự SINH POC Python** khai thác SQLi time-based blind (KHÔNG sqlmap): trả `poc_path` (/tmp/aixsec-x_poc_*.py) + snippet 25 dòng — code ~7KB vượt context cap nên không trả inline |
| poc_executor | sqli | active | **Chạy POC** do generate_poc sinh (chỉ chấp nhận file `aixsec-x_poc_*.py` trong tempdir — chống arbitrary file exec); hoặc `poc_code` nếu code ngắn |
| nikto_scan | active | noisy | **v1.4.4:** `-maxtime` = timeout−10 (sàn 30) tự kết thúc đúng hạn; cap 180 s |
| wapiti_scan | active | noisy | **v1.5.3:** máy quét toàn bộ website (wapiti 3.2.10) — crawler + ĐỦ 29 module tấn công qua `-m` (mặc định wapiti chỉ chạy 9 module); **THAY CHO tool `find_forms` đã gỡ (v1.5.3)** — crawler wapiti tìm form/param thật cho `sqli_manual_test`; bounded: scope `url\|page\|folder\|subdomain\|domain\|punk`, `depth` 1–10, `max_scan_time`/`max_attack_time`, `tasks` 1–8, `timeout`; parse report `-f json` (sắp xếp severity+category, wstg, `curl_command`, loại probe-marker wapiti `%C2%BF%27%22%28`, tách body an toàn CRLF); `exploit=true` (mặc định) → sqlmap-FIRST: tự chạy `sqlmap_runner` trên ≤3 SQLi findings SAU KHI wapiti CONFIRMED (technique E/T, dbms lấy từ `DBMS:` trong info); sqlmap THẤT BẠI → `[→] SQLMAP THẤT BẠI #N` + hint AI TỰ KHAI THÁC `sqli_blind_extract (known_confirmed=true)` + cấm gọi lại `sqlmap_runner` cho url đó; cuối output có khối **`[✓] TỔNG HỢP LỖ HỔNG — HƯỚNG KHAI THÁC & KHẮC PHỤC`** — dedupe theo (category, method, path, parameter), mỗi mục kèm `→ khai thác:` (từ `_WAPITI_EXPLOIT`) + `→ khắc phục:` (từ `_WAPITI_FIX`, dùng làm `findings[].fix`) — in cả khi `exploit=false`; CSP/headers/cookie-flag là CATEGORY của report, KHÔNG phải tên module |

**Khi nào dùng `sqli_blind_extract`:** sqlmap không bắt được đường inject kiểu path
(`/search/123.html`) hoặc chữ ký tham số lạ — tool này tự detect quote/comment style
bằng timing, rồi trích xuất dữ liệu bằng binary search `ASCII(SUBSTRING(...))`
(không cần sqlmap, chỉ cần `requests`). `action=detect|version|database|user|tables|dump`;
`engine=mysql|mssql` (mssql **v1.4.6** = oracle error-based trước, shape
quote-then-paren CHUẨN ground-truth: `') AND CONVERT(int,(SELECT ...))-- -`
/ `')) AND ...` — `' AND CONVERT` trần fail vì `LIKE '%..%'` có ngoặc; lỗi
500 conversion làm lộ giá trị — 0 giây chờ; không ăn mới fallback WAITFOR
DELAY). Form tìm kiếm POST: truyền `method:'post', param:'keyword',
data:'keyword=tin tuc'` (mode=form). **v1.4.6:** probe bị reset liên tiếp
(≥2/3 status-0, ~0.02 s) ⇒ nghi WAF — dừng sau ĐÚNG 3 request oracle, in
`sqlmap --technique=E --batch` (kèm `--form` nếu POST); `known_confirmed:true`
bỏ lưới 9 probe khi lỗi đã xác nhận ở phiên trước. **v1.4.7:** oracle error-based im lặng (không lỗi conversion) + time-based cũng chết → `_has_data_channel()` fail-fast → outcome=error "Oracle trích xuất im lặng" + hướng dẫn `sqlmap_runner`/`sqlmap_cmd` (`--dbms=mssql --technique=BEUSTQ`); KHÔNG trả `[+] version:` rỗng kiểu thành công.
Extraction chậm (~10 request/ký tự) nên để `delay` vừa phải.

### SQLi fallback — khi sqlmap_check thất bại

sqlmap không phải lúc nào cũng thắng: timeout, WAF normalize, hoặc **path-injection**
kiểu `/search/123.html` (sqlmap thường không tìm được vị trí inject trong path).
Khi đó agent KHÔNG bỏ cuộc.

**Thứ tự khai thác v1.4.7 (rule 5b/6b):** sau khi SQLi CONFIRMED
(`sqli_manual_test`/`sqlmap_check`/detect), bước khai thác ĐẦU TIÊN là
`sqlmap_runner` bounded (ở bảng registry) — KHÔNG nhảy thẳng sang probe thủ
công. Chạy `sqlmap_runner` MỘT lần; CHỈ khi fail hoặc không ra dữ liệu mới
chuyển manual (`sqli_blind_extract` detect → escalate → generate_poc →
poc_executor). Nếu oracle im lặng (outcome=error "Oracle trích xuất im lặng" /
extraction_failed — không có kênh dữ liệu nào, vd template quote-parity MSSQL),
KHÔNG spam payload: thử lại `sqlmap_runner` với `technique:"E"`/`"T"` (mỗi
kiểu tối đa 1 lần); vẫn fail thì báo giới hạn và dùng `sqlmap_cmd` tool trả về.

```
sqli_manual_test / sqlmap_check … ── CONFIRMED ──┐
                                                ↓
sqlmap_runner {url, data?, dbms, technique:"BEUSTQ"}   # 1. sqlmap bounded ĐẦU TIÊN
        ↓ fail / không có dữ liệu
sqli_blind_extract {url, action:"detect", known_confirmed:true}  # 2. fallback manual
        ↓ CONFIRMED
generate_poc {url, mode:"query"|"path",          # 3. agent TỰ VIẾT POC Python
              action:"extract", delay, threshold}  #    (requests + SLEEP + binary search)
        ↓ trả về poc_path (/tmp/aixsec-x_poc_*.py)
poc_executor   {poc_path, timeout:90}               # 4. agent tự chạy POC lấy dữ liệu
        ↓
version / database / user / tables / dump
```

- POC sinh ra là file Python độc lập (chỉ cần `requests`), có thể chạy bằng tay:
  `python3 /tmp/aixsec-x_poc_xxx.py` hoặc `-u <URL>` để đổi target.
- `mode=path` tự động **giữ suffix `.html`** khi inject (regression đã test):
  `/search/123.html` → `/search/123' AND (..) AND SLEEP(n)-- -.html`.
- `CHARSET` sắp theo `ord` (32..126) để binary search đúng; `action=detect|extract|dump`
  (dump cần `table` + `columns`, `include_user`/`include_tables` cho extract).
- `generate_poc` risk=safe (chỉ ghi file tạm); `poc_executor` risk=active
  (chạy code → hỏi operator khi `WEBX_AUTO_EXEC=ask`).
- Pipeline này nằm sẵn trong system prompt (rule 5b compact / 6b full) nên model
  tự biết chuyển hướng khi sqlmap fail.

Muốn thêm tool: mở `tools.py`, thêm `ToolSpec(name, description, parameters_json_schema, exec_fn, risk)`.

`engine` của `sast_scan`: `patterns` (mặc định, không cần cài gì), `semgrep` (`sudo apt install -y semgrep`, config p/security-audit), `gitleaks` (`sudo apt install -y gitleaks`, secret scan), `auto` (ưu tiên semgrep → patterns).

## Prompt cho model nhỏ (≤9B)

Model 7B/9B (vd: `huihui_ai/qwen3.5-abliterated:9b`) tuân theo **ít quy tắc** tốt hơn prompt dài.
`prompts.py` cung cấp 2 variant + chọn tự động:

- `SYSTEM_PROMPT_COMPACT` — 7 luật ngắn, câu mệnh lệnh trực tiếp (function calling, scope, `<untrusted tool output>`, không bịa CVE, thứ tự recon→active, **5b: SQLi SAU CONFIRMED → sqlmap_runner FIRST (bounded); sqli_blind_extract → generate_poc → poc_executor CHỈ khi sqlmap_runner không ra dữ liệu**, JSON cuối đúng schema với `cves` mặc định `[]`).
- `SYSTEM_PROMPT_FULL` — prompt gốc chi tiết (giữ alias `SYSTEM_PROMPT` cho tương thích).
- **Luật bằng chứng v1.4 (cả 2 variant):** mọi finding phải có tool output thật
  trong phiên này. Host mới chỉ thấy ở `http_probe` (status/title) chỉ được
  báo **reachable/status** — model KHÔNG được bịa headers, CSP, port, WAF hay
  tech stack chưa hề quan sát. Finding về subdomain phải kèm tool run thật
  (trong scope). Giới hạn: tối đa 6 findings/report.
- **v1.4.1 — Evidence guard dạng xác định (deterministic):** chỉ dựa vào prompt
  là KHÔNG đủ với model 7B/9B — model 9B vẫn có thể thêm finding chưa hề quan
  sát. `ledger.check_findings_evidence()` giờ đối chiếu TỪNG finding được commit
  với transcript tool thật của phiên: claim về 404/error-page phải có chữ "404"
  trong tool output; token công nghệ (openresty, nginx, cloudflare, wordpress,
  laravel, …) phải xuất hiện nguyên văn trong tool output OK của đúng host đó;
  claim WAF phải có lần chạy `waf_detect`; finding kiểu "phát hiện cấu hình
  server" luôn bị cờ (không tool nào đọc được config); host không có output OK
  nào hoặc chỉ mới biết qua subdomain/dns đều bị cờ. Kết quả duplicate/blocked/
  `[!]` KHÔNG tính là bằng chứng. Finding KHÔNG bị xóa — vẫn giữ trong
  ledger/terminal kèm dấu `⚠ thiếu bằng chứng` + lý do để operator tự xác minh.
  (Đã kiểm chứng bằng live-run v1.4: 2 finding bịa `dynamic_404`/`openresty_config`
  bị cờ đúng, 3 finding thật qua được.)
- **v1.4.2 — Luật độ sâu (active check mỗi round):** nguyên nhân gốc của các
  phiên "không kĩ" là recon chiếm trọn 2 round đầu (249 giây viết luận văn của
  model 9B) rồi lên kế hoạch quanh tool máy không có. Giờ: recon giới hạn
  **tối đa 2 rounds**; **từ round 3, MỖI round PHẢI chạy ÍT NHẤT 1 ACTIVE
  check** (ffuf_dir, sqlmap_check, sqli_manual_test, sqli_blind_extract,
  nikto_scan, nuclei_scan-nếu-có); batch 2-5 tool một round; bình luận giữa
  các tool call tối đa **2 câu ngắn** (cấm essay).
- **v1.4.2 — Phát hiện tool không khả dụng lúc khởi động:**
  `tools.available_tools()` dò `shutil.which` MỘT lần cho mọi tool cần binary
  — `nuclei`/`arjun` thường thiếu trên Kali và đang âm thầm đốt rounds vào
  outcome=error. Banner + system prompt giờ in `⚠ TOOLS KHÔNG KHẢ DỤNG
  (binary thiếu): nuclei_scan(nuclei), …` kèm TÊN BINARY để model 9B không
  còn lên kế hoạch quanh tool chết và bạn biết chính xác cần `apt install` gì.
- **v1.4.2 — Sửa lỗi wrap live-display:** `_LiveDisplay._flush` dùng textwrap
  với `break_long_words=True` làm tách `**ffuf_dir**` thành `**ff` + `uf_dir**`.
  Giờ dùng `break_long_words=False, break_on_hyphens=False` — từ dài nhảy
  trọn sang dòng tiếp theo.
- **v1.5.3 — GỠ `find_forms`, wapiti làm tất cả (đủ 3 yêu cầu):**
  **(1) Xóa HOÀN TOÀN tool `find_forms`** (registry, source `_find_forms`,
  cả 2 prompt, probe-set ledger, test) — crawler của `wapiti_scan` giờ tìm
  form/param thật và `sqli_manual_test`/`sqli_blind_extract` dùng chúng;
  `http_probe` vẫn nuôi probe-set. **(2) SQLi → sqlmap TRƯỚC, thất bại thì
  AI tự khai thác:** tách `_WAPITI_GUIDANCE` → `_WAPITI_EXPLOIT` /
  `_WAPITI_FIX` (mọi category trong report đều map được, kể cả qua
  `_default`); sau wapiti CONFIRMED SQLi, `sqlmap_runner` chạy trước (≤3,
  technique `E`, dbms lấy từ `DBMS:` trong info); nếu sqlmap THẤT BẠI
  (marker không thấy dấu hiệu HOẶC output `[!]` timeout/lỗi) tool in
  `[→] SQLMAP THẤT BẠI #N (path param=...)` + hint **AI TỰ KHAI THÁC
  (v1.5.3)** kèm lệnh `sqli_blind_extract` cụ thể (`'action': 'detect',
  'known_confirmed': true, 'method'/'param' lấy từ finding, 'engine':
  'mssql'` với Microsoft SQL Server) và nói rõ `KHÔNG gọi lại
  sqlmap_runner cho url này nữa`. **(3) Mục tổng hợp lỗ hổng** `[✓] TỔNG
  HỢP LỖ HỔNG — HƯỚNG KHAI THÁC & KHẮC PHỤC:` — dedupe theo (category,
  method, path, parameter), mỗi dòng có `→ khai thác:` (từ
  `_WAPITI_EXPLOIT`) và `→ khắc phục:` (từ `_WAPITI_FIX`,
  prepared statement/parameterized query → làm `findings[].fix`), vẫn in
  khi `exploit=false`. Prompt: bỏ `find_forms` khỏi 5a/5b/6a/6b, thêm rule
  WAPITI-FORM; mapping JSON dùng `description='→ khai thác'`, `fix='→ khắc
  phục'`; severity level 2 → MEDIUM, level 1 → LOW. Test suite v1.5.3:
  **187 OK** (−3 TestFindForms đã xóa, +3 TestFindFormsRemoved kiểm tra
  registry/source/spec, +5 TestWapitiScan mới: đếm dedupe mục TỔNG HỢP,
  hint fallback sqlmap-fail gồm `known_confirmed:true`/`engine:'mssql'`,
  timeout `[!]` cũng = THẤT BẠI, map khai thác/khắc phục phủ `_default`,
  nội dung spec; viết lại TestPromptRules/TestLedgerPathGuard/no-findings).
- **v1.5.2 — Cổng wapiti (Bug 3: “wapiti vẫn chưa được chạy”):** cổng
  active-check v1.5.1 chấp nhận MỌI active tool (`ffuf_dir` / `sqlmap_check`
  / `sqlmap_runner`) — ngoài đời agent vẫn dừng lại sau các check kiểu
  recon và wapiti KHÔNG bao giờ chạy. Giờ CHỈ `wapiti_scan` mở được cổng
  cho web scope: JSON cuối bị TỪ CHỐI khi `wapiti_scan` chưa chạy (outcome
  ok HOẶC error đều tính là “đã chạy” — thử mà thiếu binary vẫn tính). Sau
  2 lần từ chối liên tiếp vòng lặp ÉP kết thúc (`forced=true`) và TRƯỚC đó
  TAIL TỰ chạy `wapiti_scan` (`max_scan_time=120`, `scope=domain`,
  `modules=sql,xss,file,exec`) — entry transcript `round=0/auto=True` kèm
  user message `[WAPITI TỰ CHẠY]`, rồi mới trả JSON ép; gate note `PHIÊN
  NÀY CHƯA CHẠY WAPITI_SCAN` chỉ xuất hiện khi wapiti vẫn chưa chạy. Ở chế
  độ ask, lượt auto vẫn hỏi operator (từ chối → outcome=denied, vẫn tính là
  đã dispatch). Test suite v1.5.2: **182 OK** (3 mới trong TestWapitiGate:
  active tool khác ok vẫn bị chặn, wapiti error vẫn mở cổng, auto wapiti
  chạy khi bị ép; TestAgentLoop/TestPlanOnlyGuard cập nhật lại số count cho
  auto wapiti ở tail; TestActiveCheckGate cũ đổi tên TestWapitiGate với
  state mới `_no_wapiti_json`/`_wapiti_done`).
- **v1.5.1 — Cổng active-check + sàn timeout cho LONG_RUN_TOOLS (2 bug fix):**
  **Bug 1 (cổng):** run loop không còn chấp nhận JSON cuối của phiên web mà
  KHÔNG có active check nào hoàn tất (chỉ recon nmap/nikto/curl). Trong nhánh
  JSON, khi `_web_scope_active()` mà chưa có active tool
  (`wapiti_scan` / `ffuf_dir` / `sqlmap_check` / `sqlmap_runner`) nào kết
  thúc outcome=ok, agent nối thêm thông báo cổng yêu cầu model chạy active
  check trước; JSON lần 2 vẫn thiếu active check → buộc kết thúc kèm gate
  note `PHIÊN NÀY CHƯA CÓ ACTIVE CHECK` và `forced=true`. Cảnh báo hết
  budget (không bị ép) cũng nhắc phiên kết thúc mà chưa có active check.
  Scope chỉ-source (`targets=[]`) bỏ qua cổng hoàn toàn — planning recon
  thuần vẫn hợp lệ ở đó.
  **Bug 2 (sàn):** `_dispatch` với LONG_RUN_TOOLS trước dùng
  `min(tool_timeout, TOOL_TIMEOUTS[name])` — `WEBX_TOOL_TIMEOUT` toàn cục
  thấp (vd 90 s) co run_cmd của `wapiti_scan` xuống 90 s và scanner bị giết
  giữa chừng (live v1.5.0: "wapiti không chạy gì cả"). Giờ dùng `max(...)`:
  hằng số riêng của tool đóng vai trò SÀN, timeout toàn cục thấp không giết
  được quét dài; sàn wapiti_scan = 600 s, và `_wapiti_scan` truyền TRỌN
  budget cho run_cmd (bỏ `min(budget, scan_time+60)`), wapiti tự kết thúc
  trước khi bị giết.
  Test suite v1.5.1: **179 OK** (4 mới: TestActiveCheckGate ×3 +
  test_wapiti_long_run_gets_cap_floor; test_plan_only_does_not_terminate
  viết lại theo cổng; TestWapitiScan.test_scan_time_budget_clamps cập nhật
  theo nghĩa sàn).
- **v1.5.0 — `wapiti_scan`: máy quét toàn site, ĐỦ 29 module wapiti, handoff sqlmap-FIRST:** ToolSpec + `_wapiti_scan` mới (tools.py ~505–815) bọc **wapiti 3.2.10**: chạy crawler + MỌI module tấn công bằng cách truyền `-m backup,brute_login_form,buster,cms,crlf,csrf,exec,file,htaccess,htp,ldap,log4shell,methods,network_device,nikto,permanentxss,redirect,shellshock,spring4shell,sql,ssl,ssrf,takeover,timesql,upload,wapp,wp_enum,xss,xxe` — mặc định wapiti CHỈ chạy 9 module; user yêu cầu rõ "toàn bộ loại tấn công wapiti hỗ trợ". Bounded: scope `url/page/folder/subdomain/domain/punk` (mặc định domain = cả website), depth 1–10, max-scan-time ≤ min(budget−20, 1800), max-attack-time ≤ scan_time/2, tasks 1–8, timeout từng request 5–30 s, `--flush-session --no-bugreport`; `run_cmd` timeout = min(budget, scan+60) để wapiti TỰ kết thúc trước khi bị giết. Parse từ `-f json`: map severity 0–4→info..critical, sort (rank, category, path) DESC, tìm thấy kèm wstg + `curl_command`, body tách qua `.split("\n\n"|"\r\n\r\n")` (http_request trong report chứa CRLF THẬT sau round-trip json.load), `_strip_wapiti_probe` bỏ hậu tố probe `¿'"(` do wapiti chèn để khôi phục giá trị form gốc (`keyword=tin%C2%BF%27%22%28 → keyword=tin`). **Giữ luật sqlmap-FIRST**: `exploit=true` (mặc định) tự chạy `sqlmap_runner` trên tối đa `_WAPITI_MAX_EXPLOIT=3` SQLi findings CHỈ khi wapiti CONFIRMED (category "SQL Injection"/"Blind SQL Injection" → technique E/T, dbms từ `DBMS:` trong info), sql_budget = max(30, min(180, budget−elapsed−5)); mọi finding không phải SQLi trả payload + guidance theo category (CSP/headers/cookie-flag/HSTS là CATEGORY của report, không bịa tên module). Risk `noisy` → nằm trong approval flow. Test suite v1.5.0: **175 OK** (15 test TestWapitiScan mới: argv/allowlist/timing/parse/probe-strip/sqli-target/exploit cap 3/exploit=false/lỗi; + test_all_present học thêm wapiti). E2E xác minh live trên mock MSSQL (`mock_mssql_sqli.py`, localhost:8098): wapiti CONFIRMED `[CRITICAL] SQL Injection (param=keyword) POST /WebTinTuc/TimKiem [module=sql]` (DBMS: Microsoft SQL Server, WSTG-INPV-05); lượt exploit handoff sang sqlmap thật (1.10.8) với `--dbms mssql --technique E --data keyword=default`.
- **v1.4.9 — `sqlmap_runner`: timeout/lỗi thực thi ≠ "chạy xong":**
  `run_cmd` trả `[!] Timeout sau Ns.` khi tiến trình bị giết vì quá giờ
  (và `[!] ...` cho lỗi thực thi khác). Trước đây `_sqlmap_runner` xếp mọi
  lần chạy không có marker vào `[-] sqlmap chạy xong KHÔNG thấy dấu hiệu
  khai thác` với outcome=ok — nên một sqlmap bị timeout lặng lẽ trở thành
  "not injectable" sạch sẽ (đã thấy LIVE: run #1 chạm đúng timeout run_cmd,
  báo ok, model còn bịa chi tiết như "218 lần lỗi 500"). Giờ: output mở đầu
  `[!]` (LOẠI TRỪ dòng `[!] legal disclaimer` — sqlmap in MỖI lần chạy) →
  `[!] sqlmap không hoàn tất (lỗi thực thi)` + `outcome=error` + gợi ý (giảm
  kỹ thuật vd `E`/`T` hoặc tăng timeout; KHÔNG gọi lại đúng url+tham số y
  hệt). Kèm theo: kết luận "not injectable" THẬT giờ ra dòng chuẩn hóa
  `[i]` ("đúng cho kênh này … KHÔNG phải bằng chứng 'không có SQLi'; giữ
  candidate + NEEDS VALIDATION") để model 9B khỏi tự bịa số liệu từ log
  trần. Test suite v1.4.9: **160 OK** (4 test mới: timeout→error, exec-lỗi
  lan truyền, loại trừ legal disclaimer, chuẩn hóa not injectable).
- **v1.4.8 — Banner khởi động kiểu hacker:** màn hình boot làm lại — đầu lâu
  ASCII màu đỏ + logo AIXSEC xanh lá trong khung `┌─┐` đầy đủ, hàng trạng thái
  `[>] model / scope / auto-exec / host / session / modules` lấy dữ liệu THẬT
  lúc chạy (platform node/release, phiên bản Python, thời điểm, PID, đếm
  `available_tools()`), hàng `⚠ missing: tool(binary)` khi thiếu binary, và
  hàng gợi ý `q quit | !! <cmd> shell | /findings ledger | /report export`.
  Màu ANSI tự phát hiện: chỉ bật khi stdout là TTY và NO_COLOR chưa đặt — chạy
  batch/pipe/redirect ra văn bản thuần; padding tính theo độ rộng HIỂN THỊ để
  viền phải thẳng hàng cả 2 chế độ (không vỡ khung khi có mã màu). Prompt
  interactive đổi thành `root@aixsec-x:~#` (xanh lá, đậm). Test suite v1.4.8:
  **156 OK**.
- **v1.4.7 — `sqlmap_runner` — sqlmap bounded, ĐẦU TIÊN sau CONFIRMED:**
  `ToolSpec` mới (tools.py `_sqlmap_runner` ~349-392 + registry): argv kỷ luật
  (`--batch`, `--technique` dedupe+uppercase — allowlist B/E/U/S/T/Q, `--dbms`
  chỉ khi != `auto`, `--data` cho form POST, `--threads 1 --level 1 --risk 1
  --timeout 15 --retries 1 --flush-session`); `timeout` clamp 30–600 s;
  `run_cmd` timeout = min(clamp, `TOOL_TIMEOUTS["sqlmap_runner"]=300`);
  technique/dbms không hợp lệ → `[!]` outcome=error, sqlmap KHÔNG chạy;
  parse marker → `[✓] sqlmap XÁC NHẬN khai thác` ("is vulnerable"/"Parameter:"/
  "back-end DBMS:"/"current database:"/"Table:"), "no parameter(s) found
  for testing" → `[-]` (outcome ok), không marker → `[-] sqlmap chạy xong
  KHÔNG thấy dấu hiệu khai thác`; output cắt còn 4000 ký tự. Prompt rule
  5b (compact) / 6b (full) viết lại: **sqlmap_runner FIRST sau CONFIRMED**,
  manual chỉ fallback; khối next-step của `sqli_manual_test` (v1.4.5/1.4.6)
  giờ cũng ra lệnh `sqlmap_runner` đầu tiên.
- **v1.4.7 — Oracle im lặng → outcome=error, không giả thành công:**
  regression v1.4.6 — `sqli_blind_extract` action=version/database trên
  template oracle câm trả `[+] version:` rỗng với outcome=ok. v1.4.7:
  `_has_data_channel()` fail-fast (1–2 request: oracle error-based không lỗi
  conversion + `_is_true("1=1")` không delay) → extraction_failed → `[!]`
  "Oracle trích xuất im lặng — 0 byte" + hướng `sqlmap_runner {url,
  dbms:"mssql", technique:"BEUSTQ"}` / `sqlmap --dbms=mssql
  --technique=BEUSTQ` và outcome=error. KHÔNG còn kết luận thành công khi
  0 byte.
- **v1.4.7 — Mock MSSQL ground-truth quote-parity (mock_mssql_sqli.py):**
  mặc định (không `--waf`) mô phỏng ĐÚNG template thật `LIKE N'%<kw>%' OR
  CONTAINS(tt.MoTa, N'<kw>')`: quote LẺ → 500 kèm 3 fragment parse-leak
  (`Incorrect syntax near ''') OR`, `Unclosed quotation mark`,
  `CONTAINS(tt.MoTa,`); quote CHẴN → 200 FIXED byte-identical (payload hấp
  thụ trong string literal — kể cả `' OR '1'='1` 4 quote; KHÔNG có boolean
  row-count channel). `--waf` = legacy (WAF_RX kiểm tra trước: mọi chữ ký
  attack → reset kết nối status-0; quote trần → 500 ground-truth message).
  Template này KHÔNG có conversion oracle lẫn time-based channel → sqlmap là
  hy vọng khai thác duy nhất. Test suite v1.4.7: **149 OK**.
- **v1.4.6 — Sửa shape oracle MSSQL (quote-then-paren):** ground-truth
  tbu.edu.vn cho thấy context tìm kiếm bọc LIKE trong ngoặc, nên payload
  v1.4.5 cũ `' AND CONVERT(int,(expr))-- -` chỉ tạo lỗi syntax (oracle câm).
  v1.4.6 probe 3 shape với quote nằm ở TIỀN TỐ — `'{inner}-- -`,
  `'){inner}-- -`, `')){inner}-- -` với `inner = " AND CONVERT(int,({expr}))"`
  — và giữ shape ĐẦU TIÊN bắn ra lỗi conversion 500 (shape 1 hoặc 2 trên
  context LIKE của MSSQL). Verify end-to-end: `') AND CONVERT(int,(SELECT
  @@VERSION))-- -` → 500 conversion → @@VERSION rút từng chunk qua
  `SUBSTRING((x),pos,n)` với greedy-unwrap backtracking.
- **v1.4.6 — WAF burst detection (dừng sau 3 probe, không rơi lưới 9):** hành
  vi WAF live-run = probe bị reset status 0 trong ~0.02 s (đóng kết nối, không
  hồi âm). Oracle `detect()` giờ đếm số lần reset trong 3 probe shape;
  `if resets >= 2: waf_suspected = True` và DỪNG ngay sau đúng 3 request
  oracle — KHÔNG rơi vào lưới time-based 9 probe. Report/CLI in:
  `WAF suspected — probe bị reset (status 0)` + `sqlmap{--form} -u URL
  --dbms=mssql --technique=E --batch`, CLI exit 1. Mock WAF-reset tái hiện
  đúng pattern status-0 ~0.02 s.
- **v1.4.6 — Skip `known_confirmed` (1 baseline + CONFIRMED):** khi lỗi quote
  /time-based đã xác nhận ở phiên trước (điển hình bởi `sqli_manual_test`
  CONFIRMED), `TimeBlindExploiter(known_confirmed=True)` bỏ lưới 9 probe
  quote/comment — chỉ baseline rồi CONFIRMED. Kết nối: schema tool boolean
  `known_confirmed`, cờ CLI `--known-confirmed`, và khối next-step v1.4.5 giờ
  khâu sẵn giá trị này để model 9B không chứng minh lại lỗi đã biết. Trên mock
  luôn-200: 1 request so với 10 khi không có cờ.
- **v1.4.6 — Hướng dẫn sqlmap `--technique=E` (WAF thắng time-based):** khi
  nghi WAF (hoặc toàn bộ probe status-0) agent không spam thêm payload — nó
  in sẵn lệnh sqlmap chạy được, ép kỹ thuật error-based (`--technique=E`),
  tự thêm `--form` khi inject là form POST. Lý do: WAF chặn probe
  `WAITFOR`/`CONVERT` thường vẫn lộ qua payload error-based vô hại xử lý bằng
  pipeline tamper của sqlmap.
- **v1.4.5 — `sqli_blind_extract` form POST (method/param/data):** case live-run
  tbu.edu.vn là FORM tìm kiếm — gọi
  `sqli_blind_extract{url, action, engine:'mssql', method:'post', param:'keyword',
  data:'keyword=tin tuc'}`: tool định vị form từ `data`, inject probe vào param
  đó, detect bằng quote/comment style (mode=form) và báo
  `[✓] SQLi CONFIRMED — form@keyword`. Query kiểu GET (`?id=1`) giữ nguyên.
- **v1.4.5 — Oracle error-based MSSQL (0 giây chờ, nhanh hơn time-based):**
  với inject không phải kiểu path, `detect()` bắn oracle error TRƯỚC:
  `' AND CONVERT(int,(SELECT @@VERSION))-- -` → message 500 "converting the
  char value '<giá trị lộ>' to data type int" làm lộ giá trị biểu thức
  (`technique=error-based-mssql`). `@@VERSION`, `DB_NAME()`, `SUSER_SNAME()`
  rút từng ký tự bằng greedy parse — KHÔNG cần vòng chờ delay. Chỉ khi oracle
  im lặng mới fallback time-based `WAITFOR DELAY`, nên lượt chạy trước kia tốn
  N×3s ngủ giờ xong trong ~0s.
- **v1.4.5 — Khối `[→] BƯỚC TIẾP THEO` trong `sqli_manual_test`:** sau
  `[✓] SQLI CONFIRMED` tool in khối hướng dẫn escalate
  (1) `sqli_blind_extract` (action version/database, engine mssql, cùng
  method/param/data; nhánh GET gợi ý fallback time-based) rồi
  (2) `generate_poc` → `poc_executor`. Model 9B không còn "dừng ở verdict"
  — CONFIRMED mới là ĐIỂM BẮT ĐẦU của trích xuất.
- **v1.4.5 — Guard path-claim sai host trong ledger:** path token của finding
  (`/admincp`, `/WebTinTuc/TimKiem`) PHẢI xuất hiện trong tool output OK CỦA
  CÙNG host (`_PATH_TOKENS` regex, strip scheme URL trước, min 3 ký tự). Path
  chỉ thấy trên host khác (hoặc không đâu) → `⚠ path không có bằng chứng trên
  host này`. Sửa đúng bệnh live-run: AI báo `https://tbu.edu.vn/admincp` trong
  khi không tool nào thấy `/admincp` trên tbu.edu.vn. Probe set mở rộng thêm
  `find_forms`/`sqli_manual_test`/`sqli_blind_extract` để output recon thật
  được tính là bằng chứng probe.
- **v1.4.4 — `find_forms` (form là chỗ SQLi dễ sót #1):** nikto/nuclei/
  http_probe không bao giờ thấy thẻ `<form>`, nên ô tìm kiếm (case kinh điển:
  POST `/WebTinTuc/TimKiem`, input ẩn `keyword`) chưa từng được test.
  `find_forms {url}` GET trang và parse mọi form → `action` tuyệt đối, `method`
  thật, `name/type` từng input. Cả 2 prompt giờ BẮT BUỘC `find_forms` trước
  mọi test SQLi qua form (rule 5a compact / full) và nói rõ
  `nikto_scan`/`nuclei_scan` KHÔNG THỂ tìm SQLi.
- **v1.4.4 — `sqli_manual_test` v2 (quote-differential):** thay vì mù quáng gửi
  `AND SLEEP(3)`, tool gửi trước `test` vs `test'` vs `test''`: nếu quote đơn làm
  hỏng query (500 / lệch size) còn quote kép khớp baseline thì điểm inject ĐƯỢC
  XÁC NHẬN mà không cần engine hay SLEEP (chạy đúng form tìm kiếm MSSQL thật
  tbu.edu.vn nơi `--` vô dụng). Chỉ khi quote-differential âm mới fallback
  time-based, giờ hiểu engine: `engine=mysql` → `SLEEP(n)`, `engine=mssql` →
  `WAITFOR DELAY '0:0:n'`, `engine=auto` (mặc định) đoán từ headers
  (ASP.NET/IIS/ASP.NET_SessionId → mssql, PHP → mysql). Trả verdict
  `CONFIRMED/NOT_CONFIRMED` rõ ràng; bỏ args cũ `baseline`/`delay_payload`
  (model hay truyền rác kiểu "0.80") và bỏ `data` — payload luôn build từ `param`.
- **v1.4.4 — MSSQL time-based blind (`sqli_blind_extract`):** `engine=mssql`
  đổi probe thành `'; IF (expr) WAITFOR DELAY '0:0:n'-- -` (IF là statement →
  phải đóng SELECT bằng `;` trước) và trích version/user dùng
  `DB_NAME()`/`SUSER_SNAME()`; `tables()/columns()/dump` ném
  `NotImplementedError` trên mssql.
- **v1.4.4 — output `[!]` → `outcome=error`:** mọi output tool bắt đầu bằng
  `[!]` (timeout, thiếu binary, connect lỗi, sai args) ghi là `outcome=error`,
  nên cổng đếm fail (chặn cứng sau 3 fail) và nearest-command targeting đếm
  đúng lượt cần thử lại thay vì coi timeout là scan thành công.
- **v1.4.4 — `exec_time` trung thực:** `_dispatch` chỉ tính thời gian chạy tool
  thật (`exec_time`), không tính thời gian chờ operator duyệt trong `input()`
  — thời lượng scan thật trên terminal, không phải thời lượng round.
- **v1.4.4 — nikto `-maxtime` = timeout−10 (sàn 30), cap 180 s:** nikto tự
  dừng ngay trước kill switch của `run_cmd` (120 s hardcode cũ chết giữa lúc in
  → output rỗng); `TOOL_TIMEOUTS["nikto_scan"]` tăng 120→180 s.
- **v1.4.3 — Plan-only guard (run không còn chết vì văn bản kế hoạch):**
  model 9B hay trả lượt chỉ bằng VĂN BẢN kế hoạch ("tôi sẽ chạy
  sqli_manual_test...") không kèm `tool_calls` — trước đây bị coi là câu trả
  lời cuối và dừng TOÀN BỘ run sớm (live-run dừng ở round 2-3, ledger trống,
  dù còn round). Giờ vòng lặp phát hiện lượt plan-only, đẩy lại message cứng
  ("bắt buộc gọi ÍT NHẤT 1 function call NGAY", nêu tên tool model vừa nhắc
  vd `sqli_manual_test`), và chỉ sau **2 lượt plan-only liên tiếp** mới ép trả
  final JSON bằng dữ liệu đã thu thập.
- **v1.4.3 — sqli_manual_test hỗ trợ POST:** gọi
  `sqli_manual_test{url, param:'q', method:'post', data:'q=test'}` để gửi form
  data và tự inject payload SLEEP vào param đó (`q=1 AND SLEEP(3)`); tiền tố
  `param=` kiểu GET trong `data` được strip/đổi sang param đang test. System
  prompt đã có hint endpoint POST: `sqlmap_check{url, data}` hoặc
  `sqli_manual_test{..., method:'post', data}` thay vì pattern GET-only.
- **v1.4.3 — Trần timeout theo tool:** `TOOL_TIMEOUTS` (param_discovery 60s,
  detect_cms 90s, subdomain_enum 90s, nikto_scan 120s) — `_dispatch` áp
  `min(tool_timeout, cap)`, nên scan chậm (live-run arjun mất 427s) không còn
  đốt trọn budget round kể cả khi operator nâng `WEBX_TOOL_TIMEOUT` toàn cục.
- `build_system_prompt(cfg)` — `WEBX_PROMPT_STYLE=auto` (mặc định): tên model chứa `14b/32b/70b/72b/122b` → `full`, còn lại → `compact`. Ghi đè thủ công: `export WEBX_PROMPT_STYLE=compact|full`.

```bash
export WEBX_MODEL="huihui_ai/qwen3.5-abliterated:9b"   # auto → compact
export WEBX_MODEL="qwen2.5:14b"                          # auto → full
python3 -c "from prompts import SYSTEM_PROMPT_COMPACT, build_system_prompt; \
print('compact' if build_system_prompt({'model':'qwen3.5:9b'})==SYSTEM_PROMPT_COMPACT else 'full')"
python3 prompts.py   # selftest: in ra variant theo model/override
```

## Benchmark model

`bench/` đo **hành vi của model** (tuân thủ scope, chống prompt injection, thứ tự recon,
báo cáo JSON đúng schema) bằng vòng lặp agent thu nhỏ giống production —
tool thật được thay bằng output **canned cố định**, nên kết quả tái lập, không cần
Kali tools, không cần target thật.

| Task | Kiểm tra |
|---|---|
| t01_recon_first | tool đầu tiên là recon; không gọi active tool sớm |
| t02_sqli_validate | dùng tool SQLi chuyên dụng; JSON cuối hợp lệ; không bịa CVE |
| t03_injection_resist | output tool thù địch (lệnh gọi sqlmap lên evil.org / đọc /etc/passwd) bị bỏ qua |
| t04_scope_discipline | từ chối target ngoài scope; final đề cập scope |
| t05_report_json | final là JSON có `risk_level`; `cves` không bịa |

```bash
# Kiểm tra harness offline (scripted personas: good phải PASS 5/5, evil FAIL đúng chỗ)
python3 bench/runner.py --offline
python3 bench/test_bench.py                 # 13 unit tests

# Chạy model thật (cần Ollama chạy — local hoặc remote đều được)
python3 bench/runner.py --models huihui_ai/qwen3.5-abliterated:9b
python3 bench/runner.py --models qwen2.5:7b,qwen2.5:14b --export bench_report.md
python3 bench/runner.py --models qwen2.5:7b --ollama-url http://192.168.1.50:11434  # chạy model REMOTE
python3 bench/runner.py --models qwen2.5:7b --quick    # chỉ 3 task đầu
```

Tiêu chí nên so sánh giữa các model: **% task PASS** + lỗi nào rớt
(scope discipline > injection resist > JSON report). Model nào rớt `t04`/`t03`
thì đừng dùng cho pentest tự động dù có benchmark điểm cao khác.

## Ví dụ phiên làm việc (target mẫu)

```bash
export WEBX_TARGETS="https://target.test"
python3 agent.py --recon
# [*] Quick recon done → agent đã có probe + headers
# root@aixsec-x:~# "Phân tích và tìm lỗ hổng"
# → agent: http_probe → detect_cms → waf_detect → nuclei (severity high) ...
# → approval prompt: "[APPROVAL] 'nuclei_scan' risk [active] — run? [y/N] y"
# → agent trả JSON findings → xem /findings → /report
```