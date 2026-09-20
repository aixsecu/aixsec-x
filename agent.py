#!/usr/bin/env python3
"""
aixsec-x — agent.py
AIXSEC Exploitation Agent (local LLM via Ollama) cho Kali Linux.

Usage:
  export WEBX_TARGETS="https://example.com"
  python3 agent.py                          # interactive
  python3 agent.py --non-interactive        # chạy thẳng với prompt mặc định
  python3 agent.py --recon                  # chạy recon sơ bộ rồi mới agent

Phím trong interactive:
  <enter>      → gửi message hiện tại
  q            → thoát
  !! <cmd>     → chạy shell command (cảnh báo: tự chịu trách nhiệm)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

# ── local imports ──
from config import load_config
from ledger import (Ledger, parse_findings_json, render_markdown, validation_plan,
                   check_findings_evidence)
from llm import InjectionGuard, ollama_chat
from prompts import SYSTEM_PROMPT, build_system_prompt
from scope import ScopePolicy, normalize_host
from tools import (TOOL_REGISTRY, TOOL_INDEX, TOOL_BINS, TOOL_TIMEOUTS,
                   LONG_RUN_TOOLS, available_tools)

# ── terminal colors (AIXSEC-X style) ──
VERSION = "1.5.4"

# v1.5.2: wapiti-first gate — web scope active mà wapiti_scan CHƯA chạy
# (chưa có outcome=ok/error) thì final JSON bị từ chối và model bị ép gọi
# wapiti_scan; nếu model bỏ qua tới hết budget, agent TỰ gọi wapiti_scan
# (_auto_wapiti) để MỌI phiên web-scope đều có dữ liệu wapiti thật.
# KHÔNG còn set "bất kỳ active check nào" (v1.5.1 sai — model đáp ứng gate
# bằng sqli_manual_test/sqlmap_runner rồi bỏ qua wapiti hoàn toàn: Bug 3).

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

_AIXSEC_ART = r'''
 █████╗ ██╗██╗  ██╗███████╗███████╗ ██████╗██╗  ██╗
██╔══██╗██║╚██╗██╔╝██╔════╝██╔════╝██╔════╝╚██╗██╔╝
███████║██║ ╚███╔╝ ███████╗█████╗  ██║█████╗╚███╔╝
██╔══██║██║ ██╔██╗ ╚════██║██╔══╝  ██║╚════╝██╔██╗
██║  ██║██║██╔╝ ██╗███████║███████╗╚██████╗██╔╝ ██╗
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝'''

# v1.5.4 — mặt nạ Anonymous (Guy Fawkes V-mask) ASCII thay skull v1.4.8 cho
# màn hình "hacker-style" (theo yêu cầu user; thuần trang trí)
_ANON_ART = r'''
        .o.        .o.            ...
       .888.      .888.        .d8888b.
      .8"888.    .8"888.      d88P  Y88b
     .8' '888.  .8' '888.     888    888
    .88ooo8888..88ooo8888.    888    888
   .8'    888..8'    888.     888    888
  o88o    8888o88o    8888o   "88bodP'
'''

SEVERITY_RISK = {"destructive": 4, "active": 3, "noisy": 2, "safe": 1}


class _LiveDisplay:
    """Màn hình live khi model đang xử lý: reasoning (mờ) + nội dung (xanh)
    + thời gian mỗi lượt — để người dùng thấy agent đang nghĩ/khai thác gì.

    Mỗi lượt (round) dùng 1 đối tượng: khởi tạo in header, callback từ
    ollama_chat streaming đẩy từng dòng, done() chốt elapsed time.

    v1.4: content KHÔNG in từng token nữa (trước đây mỗi token 1 dòng "▸ x"
    → màn hình ngập ~700 dòng khi model phun final JSON). Giờ buffer token
    và chỉ in khi gặp newline hoặc khi đủ dài → in theo dòng có wrap theo
    độ rộng terminal (first line "▸ ", dòng nối "↳ ").
    """

    REASON_CAP = 250   # ký tự tối đa mỗi dòng reasoning
    CONTENT_CAP = 600  # ký tự tối đa mỗi dòng nội dung
    LINE_WRAP = 150    # độ rộng wrap mặc định (được điều chỉnh theo terminal)
    MAX_LINES = 200    # cứng giới hạn số dòng content hiển thị mỗi lượt (chống ngập)

    def __init__(self, rnd, max_rounds=None):
        self.t0 = time.time()
        self._buf = ""
        self._lines = 0
        self._done = False
        try:
            import shutil
            cols = shutil.get_terminal_size((self.LINE_WRAP, 24)).columns
            self._wrap = max(60, min(220, cols))
        except Exception:  # noqa: BLE001
            self._wrap = self.LINE_WRAP
        label = f"Round {rnd}/{max_rounds}" if rnd else "Final round"
        print(f"\n{CYAN}[*]{RESET} {BOLD}{label}{RESET} — "
              f"{DIM}model processing...{RESET}", flush=True)

    @staticmethod
    def _line(chunk, cap: int) -> str:
        s = "".join(chunk) if isinstance(chunk, (list, tuple)) else str(chunk)
        return " ".join(s.split())[:cap]

    def _flush(self):
        """In buffer hiện tại thành các dòng wrap (▸ dòng đầu, ↳ dòng nối)."""
        self._buf = (self._buf or "").rstrip()
        if not self._buf:
            return
        try:
            import textwrap
            # break_long_words=False: từ dài vượt wrap phải NHẢY trọn sang dòng
            # sau, không tách chữ giữa dòng (v1.4.2 — trước đây in '**ff' /
            # 'uf_dir**' khi stream token tới đúng biên wrap).
            raw = textwrap.wrap(self._buf, self._wrap,
                                break_long_words=False,
                                break_on_hyphens=False) or [self._buf]
        except Exception:  # noqa: BLE001
            raw = [self._buf[:self._wrap]]
        on = int(self._lines) < int(self.MAX_LINES)
        for i, line in enumerate(raw):
            self._lines += 1
            if not on:
                continue  # đã quá MAX_LINES — bỏ qua phần còn lại
            if i == 0:
                print(f"{GREEN}  ▸{RESET} {GREEN}{line}{RESET}", flush=True)
            else:
                print(f"{DIM}  ↳{RESET} {GREEN}{line}{RESET}", flush=True)
        self._buf = ""

    def on_reasoning(self, chunk: str):
        self._lines += 1
        s = self._line(chunk, self.REASON_CAP)
        if s:
            print(f"{DIM}  ✦ think:{RESET} {DIM}{s}{RESET}", flush=True)

    def on_token(self, token: str):
        if self._done:
            return
        s = (token or "")
        if not s:
            return
        if "\n" in s:
            parts = s.split("\n")
            for i, p in enumerate(parts):
                if i < len(parts) - 1:
                    self._buf += p
                    self._flush()
                else:
                    self._buf += p
        else:
            self._buf += s
            # dòng quá dài → in sớm để không treo cả dòng JSON khổng lồ
            if len(self._buf) >= self._wrap:
                self._flush()

    def done(self):
        if self._done:
            return  # idempotent — không in "finished" lần thứ 2
        self._done = True
        self._flush()
        dt = time.time() - self.t0
        print(f"{DIM}  └ model finished in {dt:.1f}s{RESET}", flush=True)


class WebXAgent:
    def __init__(self, config: dict | None = None, chat=None):
        self.config = config or load_config()
        self.system_prompt = build_system_prompt(self.config)
        self.chat = chat or ollama_chat
        self.policy = ScopePolicy(self.config["targets"],
                                  src_dirs=self.config.get("src_dirs", []))
        self.ledger = Ledger()
        self.transcript: list[dict] = []
        self.tools = TOOL_REGISTRY
        self.extra_context = ""
        # v1.4.2: phát hiện binary thiếu lúc khởi động (nuclei/arjun/... không
        # có trên máy) → model được báo TRƯỚC để không lên kế hoạch quanh tool
        # chết (trước đây tốn round vào outcome=error rồi mới bị gate cứng).
        self.available, self.missing_tools = available_tools()
        if self.missing_tools:
            self.system_prompt += (
                "\n\n⚠ TOOLS KHÔNG KHẢ DỤNG PHIÊN NÀY (binary thiếu trên máy): "
                + ", ".join(f"{s}({TOOL_BINS[s]})" for s in sorted(self.missing_tools))
                + ".\nKHÔNG gọi các tool này — outcome sẽ là error. Thay bằng tool "
                  "khác trong registry (ffuf_dir, nikto_scan, sqlmap_check, "
                  "sqlmap_runner, sqli_manual_test, sqli_blind_extract, http_probe...).")
        # Bộ chống lặp lại tool-call (chỉ trong vòng lặp run):
        #  - _call_cache: kết quả theo khóa (name, args) — gọi lại y hệt thì trả
        #    outcome='duplicate' mà KHÔNG thực thi lại.
        #  - _fail_counts: đếm lỗi theo tên tool — fail >=3 lần thì outcome='blocked'
        #    (gate cứng), tránh agent kẹt loop với tool thiếu binary (nuclei/arjun...).
        #  - _failed_urls: (name, url) đã fail (error/scope_rejected) trong phiên —
        #    gọi lại cùng URL (dù đổi tham số khác) sẽ bị outcome='blocked' ngay
        #    trước bước xin phép operator; chặn chiêu model đổi
        #    severity/tags/wordlist rồi gọi lại cùng đích.
        self._call_cache: dict[str, dict] = {}
        self._fail_counts: dict[str, int] = {}
        self._failed_urls: set[str] = set()
        # v1.4.3: đếm số lượt model trả VĂN BẢN KẾ HOẠCH không kèm tool call
        # (plan-only). >=2 lượt liên tiếp → ép trả final JSON bằng dữ liệu đã có
        # thay vì để vòng lặp quay vòng vô ích. Reset mỗi lượt có tool call thật.
        self._plan_only = 0
        # v1.5.2: wapiti-first gate — _wapiti_done=True chỉ khi wapiti_scan đã
        # chạy thật (outcome=ok HOẶC error) trong phiên;
        # _no_wapiti_json đếm lượt model trả final JSON khi wapiti chưa chạy.
        self._wapiti_done = False
        self._no_wapiti_json = 0

    # ─────────────────────────────────────────
    # TOOL DISPATCH (+ scope check + risk approval)
    # ─────────────────────────────────────────
    def _risk_ok(self, spec) -> bool:
        mode = self.config.get("auto_exec", "ask")
        if mode == "ask":
            if spec.risk == "safe":
                return True
            ans = input(f"\n[APPROVAL] '{spec.name}' risk [{spec.risk}] — run? [y/N] ").strip().lower()
            return ans == "y"
        if mode == "safe":
            return spec.risk == "safe"
        return True  # mode == "all"

    def _dispatch(self, name: str, arguments: dict) -> dict:
        spec = TOOL_INDEX.get(name)
        if not spec:
            return {"name": name, "outcome": "error",
                    "output": f"[!] Tool '{name}' not found in registry."}
        # scope check
        for p in spec.scope_params:
            if p in arguments:
                err = self.policy.check_param(spec.name, p, arguments[p])
                if err:
                    return {"name": name, "outcome": "scope_rejected", "output": err}
        # risk approval
        if not self._risk_ok(spec):
            return {"name": name, "outcome": "denied",
                    "output": "[!] Operator denied this tool."}
        try:
            kw = dict(arguments)
            # v1.4.3: trần timeout theo từng tool — chặn tool chạy vô hạn
            # không tôn trọng _timeout tốt (vd arjun 427s ở live-run), ngay cả
            # khi operator cấu hình tool_timeout cao.
            # v1.5.1 (Bug 2): LONG_RUN_TOOLS (wapiti_scan) dùng SÀN
            # max(tool_timeout, cap) — cap từng tool là MỨC TỐI THIỂU để wapiti
            # không bị giết ở tool_timeout mặc định 90s giữa chừng scan.
            cap = TOOL_TIMEOUTS.get(name, self.config["tool_timeout"])
            if name in LONG_RUN_TOOLS:
                kw["_timeout"] = max(self.config["tool_timeout"], cap)
            else:
                kw["_timeout"] = min(self.config["tool_timeout"], cap)
            # v1.4.4: chỉ đo thời gian THỰC THI tool — chờ operator duyệt
            # (_risk_ok/input()) nằm ngoài try này nên không bị tính vào duration.
            t0 = time.time()
            out = spec.exec_fn(**kw)
            dt = round(time.time() - t0, 1)
            # v1.4.4: output mở đầu '[!]' = lỗi thực thi (timeout, thiếu binary,
            # connect fail, args sai) → outcome=error để gate/fail-count đúng.
            oc = "error" if isinstance(out, str) and out.startswith("[!]") else "ok"
            return {"name": name, "outcome": oc, "output": out, "exec_time": dt}
        except TypeError as e:
            return {"name": name, "outcome": "error",
                    "output": f"[!] Invalid arguments for '{name}': {e}", "exec_time": 0.0}
        except Exception as e:  # noqa: BLE001
            return {"name": name, "outcome": "error",
                    "output": f"[!] {name} error: {e}", "exec_time": 0.0}

    # ─────────────────────────────────────────
    # MAIN LOOP
    # ─────────────────────────────────────────
    def run(self, user_text: str) -> dict:
        msgs = [
            {"role": "system", "content": self.system_prompt +
             f"\n\nSCOPE ĐƯỢC ỦY QUYỀN: {self.policy.describe()}"},
        ]
        if self.extra_context:
            msgs.append({"role": "user", "content":
                         f"[CONTEXT TỪ LƯỢT TRƯỚC]\n{self.extra_context[:6000]}\n----"})
        msgs.append({"role": "user", "content": user_text})

        max_rounds = self.config["max_rounds"]
        result = {"risk_level": "UNKNOWN", "overall_summary": "", "final_text": "", "calls": 0}
        forced = False  # dừng sớm: round thoái hóa → ép trả JSON ngay
        self._plan_only = 0  # v1.4.3: reset bộ đếm plan-only mỗi run()
        self._wapiti_done = False  # v1.5.2: reset wapiti-first gate mỗi run()
        self._no_wapiti_json = 0   # v1.5.2: reset bộ đếm JSON-thiếu-wapiti
        for rnd in range(1, max_rounds + 1):
            disp = _LiveDisplay(rnd, max_rounds)
            resp = self.chat(msgs, tools=[t.schema() for t in self.tools],
                             on_token=disp.on_token, on_reasoning=disp.on_reasoning)
            calls = resp.get("tool_calls") or []
            if not calls:
                disp.done()
                result["final_text"] = resp.get("content", "")
                if self._looks_like_json(result["final_text"]):
                    self._commit_findings(result)
                    try:
                        d = json.loads(self._strip_fence(result["final_text"]))
                        result["risk_level"] = d.get("risk_level", "UNKNOWN")
                        result["overall_summary"] = d.get("overall_summary", "")
                    except json.JSONDecodeError:
                        pass
                    # v1.5.2: wapiti-first gate (Bug 3 — user: "wapiti vẫn chưa
                    # được chạy") — web scope active nhưng wapiti_scan CHƯA
                    # chạy (ok/error) → JSON bị từ chối dù các active check khác
                    # (sqli_manual_test/sqlmap_runner...) đã ok.
                    # >=2 lần liên tiếp → forced: _auto_wapiti tự chạy wapiti
                    # trước khi ép trả JSON bằng dữ liệu thật.
                    if self._web_scope_active() and not self._wapiti_done:
                        self._no_wapiti_json += 1
                        msgs.append({"role": "assistant", "content": result["final_text"]})
                        msgs.append({"role": "user", "content": self._wapiti_gate_message()})
                        if self._no_wapiti_json >= 2:
                            forced = True
                            break
                        continue
                    return result
                # v1.4.3: model 9B viết VĂN BẢN KẾ HOẠCH không kèm tool_calls →
                # KHÔNG được coi là câu trả lời cuối (trước đây return ngay làm
                # run dừng ở round 2-3 dù còn budget). Đẩy lượt mới ép gọi tool:
                #  - lần 1: nhắc chung + nêu tên tool model vừa nhắc (nếu có)
                #  - lần 2 liên tiếp: forced → ép trả final JSON bằng dữ liệu đã thu
                self._plan_only += 1
                msgs.append({"role": "assistant", "content": result["final_text"]})
                mentioned = self._mentioned_tools(result["final_text"])
                hint = ""
                if mentioned:
                    hint = (f"\nVăn bản của bạn nhắc tới tool: "
                            f"{', '.join(mentioned)}. Gọi function call của "
                            f"{mentioned[0]} NGAY, đừng mô tả lại kế hoạch.")
                msgs.append({"role": "user", "content":
                             "Bạn vừa trả lời CHỈ BẰNG VĂN BẢN kế hoạch và KHÔNG gọi "
                             "tool call nào — lượt như vậy không được tính là hành "
                             "động. Bắt buộc: lượt này phải gọi ÍT NHẤT 1 function "
                             "call (chọn tool phù hợp trong danh sách và gọi "
                             f"ngay).{hint}"})
                if self._plan_only >= 2:
                    forced = True
                    break
                continue
            self._plan_only = 0  # lượt có tool call thật → reset bộ đếm plan-only

            # chạy tool tuần tự: in lệnh → dedup/block → dispatch → kết quả kèm thời gian
            results = []
            for c in calls:
                name = c.get("name", "?")
                args = c.get("arguments") or {}
                print(f"{YELLOW}[→]{RESET} {BOLD}{name}{RESET}("
                      f"{json.dumps(args, ensure_ascii=False)[:200]})", flush=True)
                t0 = time.time()
                key = f"{name}|" + json.dumps(args, sort_keys=True,
                                               default=str, ensure_ascii=False)
                url_val = str(args.get("url") or args.get("host") or "").rstrip("/")
                url_key = f"{name}|{url_val}" if url_val else ""
                if key in self._call_cache:
                    # gọi lặp với đúng tham số đã chạy — không thực thi lại
                    prev = self._call_cache[key].get("outcome", "?")
                    r = {"name": name, "outcome": "duplicate",
                         "output": f"[!] Tool được gọi lặp với tham số giống hệt "
                                   f"(kết quả trước: {prev}) — KHÔNG thực thi lại. "
                                   f"Đổi tham số hoặc chuyển sang tool khác."}
                elif self._fail_counts.get(name, 0) >= 3:
                    # tool fail liên tục phiên này — gate cứng theo tên tool
                    r = {"name": name, "outcome": "blocked",
                         "output": f"[!] Tool '{name}' đã fail "
                                   f"{self._fail_counts.get(name, 0)} lần phiên này — "
                                   f"bị chặn tạm thời. Dừng gọi tool này: kiểm tra "
                                   f"binary/network (vd: which {name}) hoặc "
                                   f"chuyển hướng chiến lược sang tool khác."}
                elif url_key and url_key in self._failed_urls:
                    # cùng (tool, url) đã fail trong phiên — không thử lại; chặn
                    # TRƯỚC bước xin phép operator, dù tham số có đổi (severity/tags)
                    r = {"name": name, "outcome": "blocked",
                         "output": f"[!] Tool '{name}' đã fail trước đó trên URL "
                                   f"'{url_val}' phiên này — không thử lại cùng đích. "
                                   f"Đổi URL hoặc chuyển sang tool/chiến lược khác."}
                else:
                    r = self._dispatch(name, args)
                    self._call_cache[key] = r  # cache mọi outcome để dedup lần sau
                    oc = r.get("outcome")
                    if oc in ("error", "denied", "scope_rejected"):
                        self._fail_counts[name] = self._fail_counts.get(name, 0) + 1
                    elif oc == "ok":
                        self._fail_counts[name] = 0
                    if oc == "ok":
                        self._failed_urls.discard(url_key)  # URL hồi phục
                    elif oc in ("error", "scope_rejected"):
                        self._failed_urls.add(url_key)
                # v1.4.4: ưu tiên exec_time do _dispatch đo (không gồm chờ duyệt);
                # fallback cho nhánh duplicate/blocked (không qua _dispatch).
                dt = (r.get("exec_time")
                      if r.get("exec_time") is not None else time.time() - t0)
                tag = f"{GREEN}[✔]{RESET}" if r.get("outcome") == "ok" \
                    else f"{RED}[✗]{RESET}"
                print(f"{tag} {name} → outcome={r.get('outcome', '?')} ({dt:.1f}s)",
                      flush=True)
                r.setdefault("args", args)  # giữ args để đối chiếu bằng chứng
                results.append(r)
            disp.done()
            self.transcript.append({"round": rnd, "type": "tools", "calls": results})
            result["calls"] += len(results)
            # v1.5.2: wapiti-first gate — chỉ wapiti_scan tính là "đã chạy" khi
            # outcome ok (thành công) HOẶC error (đã cố, fail rõ ràng). Các
            # outcome khác (duplicate/blocked/denied/scope_rejected) KHÔNG tính.
            for r in results:
                if (r.get("name") == "wapiti_scan"
                        and r.get("outcome") in ("ok", "error")):
                    self._wapiti_done = True

            if all(r.get("outcome") in ("duplicate", "blocked") for r in results):
                # cả round chỉ toàn duplicate/blocked — không tool nào sinh dữ liệu
                # mới; dừng sớm để không đốt nốt budget vào vòng lặp thoái hóa
                forced = True
                break

            tool_msgs = []
            for r in results:
                out = InjectionGuard.sanitize(r["output"], self.config["output_cap"])
                note = ""
                if (r.get("outcome") in ("error", "blocked")
                        and self._fail_counts.get(r["name"], 0) >= 2):
                    note = (f"\n[GHI CHÚ] Tool '{r['name']}' đã fail "
                            f"{self._fail_counts[r['name']]} lần phiên này — "
                            f"đừng gọi lại trừ khi đổi tham số/chiến lược.")
                tool_msgs.append({"role": "tool", "name": r["name"],
                                  "content": f"outcome={r['outcome']}\n{out}{note}"})
            msgs.append({"role": "assistant", "content": resp.get("content", "") or
                        "(calling tools...)"})
            msgs.append({"role": "user", "content":
                        "[TOOL RESULTS BEGIN]\n" +
                        json.dumps(tool_msgs, ensure_ascii=False)[:12000] +
                        "\n[TOOL RESULTS END]\nTiếp tục. Khi đủ dữ liệu trả JSON cuối cùng."})

        # v1.5.2 (tail-order 1): AUTO-WAPITI — hết vòng lặp mà web scope active
        # và wapiti_scan chưa từng chạy (model bỏ qua dù prompt/gate bắt buộc)
        # thì agent TỰ gọi wapiti_scan một lần (bounded) để mọi phiên web-scope
        # đều có kết quả wapiti thật trước khi tổng hợp JSON cuối.
        dispatched = self._auto_wapiti(msgs)
        if dispatched:
            result["calls"] += 1
        # hết budget (hoặc dừng sớm vì round thoái hóa: toàn duplicate/blocked
        # hoặc model chỉ trả văn bản kế hoạch 2 lượt liên tiếp) — ép trả JSON
        if forced:
            gate_note = ("PHIÊN NÀY CHƯA CHẠY WAPITI_SCAN — nếu bước tự chạy ở "
                         "trên trả lỗi (thiếu binary/network) hoặc bị operator "
                         "từ chối, hãy phản ánh trung thực trong JSON. "
                         if self._no_wapiti_json >= 2 and not self._wapiti_done else "")
            msgs.append({"role": "user", "content":
                        f"{gate_note}Vòng lặp không tiến triển: các tool gọi đều trả "
                        "duplicate/blocked, hoặc bạn chỉ trả văn bản kế hoạch "
                        "không gọi tool — không còn thông tin mới. KHÔNG gọi tool nữa. "
                        "Tổng hợp DỮ LIỆU "
                        "THẬT TỪ [TOOL RESULTS] ở trên và trả final JSON ngay. "
                        "Chỉ đưa vào finding những gì thật sự xuất hiện trong tool output "
                        "của phiên này (ghi nguồn trong description). KHÔNG bịa thêm "
                        "404/error-page, cấu hình server, WAF/CMS hoặc chi tiết nào "
                        "khác nếu chưa có tool output hỗ trợ."})
        # v1.5.2: hết budget mà web scope active và wapiti CHƯA chạy được
        # (auto không dispatch: deny/không URL/không spec) — cảnh báo tổng hợp
        # trung thực (không bịa), tránh JSON rỗng/UNKNOWN
        if (not forced and self._web_scope_active() and not self._wapiti_done):
            msgs.append({"role": "user", "content":
                        "⚠ Lưu ý tổng hợp: phiên này WAPITI_SCAN chưa chạy được "
                        f"và budget ({max_rounds} round) đã cạn. Không gọi tool "
                        "nữa — trả final JSON trung thực với dữ liệu đã thu; "
                        "nếu chưa đủ bằng chứng, risk_level=UNKNOWN là kết quả "
                        "trung thực (đừng bịa dữ liệu scan)."})
        disp = _LiveDisplay(0 if forced else max_rounds, max_rounds)
        resp = self.chat(msgs, tools=[t.schema() for t in self.tools], json_mode=True,
                         on_token=disp.on_token, on_reasoning=disp.on_reasoning)
        disp.done()
        result["final_text"] = resp.get("content", "")
        self._commit_findings(result)
        try:
            d = json.loads(result["final_text"]) if result["final_text"].strip().startswith("{") else {}
            result["risk_level"] = d.get("risk_level", "UNKNOWN")
            result["overall_summary"] = d.get("overall_summary", "")
        except json.JSONDecodeError:
            pass
        return result

    @staticmethod
    def _strip_fence(t: str) -> str:
        t = t.strip()
        if t.startswith("```"):
            t = __import__("re").sub(r"^```(?:json)?\s*|\s*```$", "", t)
        return t

    @staticmethod
    def _looks_like_json(t: str) -> bool:
        return t.strip().startswith("{") or "findings" in t[:200]

    def _mentioned_tools(self, text: str) -> list[str]:
        """Tên tool đăng ký xuất hiện trong văn bản model — để nhắc model gọi
        ĐÚNG tool nó vừa nói tới (v1.4.3). Sắp xếp tên dài trước để khớp nét."""
        low = (text or "").lower()
        found = [ts.name for ts in self.tools if ts.name.lower() in low]
        return sorted(found, key=len, reverse=True)

    def _web_scope_active(self) -> bool:
        """v1.5.1: web scope đang active (URL http(s)/IP/CIDR/hostname/localhost)
        — nơi active checks (wapiti/nikto/ffuf...) có ý nghĩa. False khi chưa
        khai báo WEBX_TARGETS hoặc chỉ có src (WEBX_SRC_DIRS)."""
        if not self.policy.has_scope:
            return False
        for a in self.policy._raw:
            if a.lower().startswith(("http://", "https://")):
                return True
        for d in self.policy.domains:
            if d in ("localhost", "127.0.0.1", "::1"):
                return True
            if re.match(r"^[0-9a-f.:]+(?:/\d{1,2})?$", d):
                return True
        return bool(self.policy.domains or self.policy._cidrs)

    def _active_gate_url(self) -> str | None:
        """URL đề xuất cho wapiti_scan trong gate message (v1.5.1) — ưu tiên
        raw scope có scheme, fallback http:// domain đầu tiên."""
        for a in self.policy._raw:
            low = a.lower()
            if low.startswith(("http://", "https://")):
                scheme = low.split("://", 1)[0]
                host = normalize_host(a)
                if host:
                    return f"{scheme}://{host}/"
        for d in self.policy.domains:
            if d:
                return f"http://{d}/"
        return None

    def _wapiti_gate_message(self) -> str:
        """v1.5.2: thông báo từ chối final JSON khi WAPITI_SCAN chưa chạy —
        KHÔNG tool nào khác (sqli_manual_test/sqlmap_runner/nikto/ffuf...) thay
        thế được wapiti; bắt buộc gọi wapiti_scan trước khi tổng hợp."""
        url = self._active_gate_url() or "<URL-trong-scope>"
        hint = ""
        if "wapiti_scan" in self.missing_tools:
            hint = ("\n[GHI CHÚ] Binary 'wapiti' không thấy trên PATH phiên "
                    "này — kết quả có thể là lỗi 'not found'. VẪN phải gọi "
                    "wapiti_scan để ghi nhận kết quả thật; nếu tiếp tục bỏ qua, "
                    "agent sẽ TỰ ĐỘNG chạy wapiti_scan ở bước kết thúc phiên.")
        return ("Bản tổng hợp JSON của bạn CHƯA HỢP LỆ: phiên này đang active "
                "trên web scope nhưng WAPITI_SCAN CHƯA CHẠY. Các tool khác "
                "(sqli_manual_test, sqlmap_runner, nikto_scan, ffuf_dir...) "
                "KHÔNG thay thế được wapiti — wapiti là tool duy nhất crawl "
                "toàn website. Bắt buộc lượt này gọi function call wapiti_scan "
                "với {\"url\": "
                f"{json.dumps(url, ensure_ascii=False)}, "
                "\"scope\": \"domain\", \"modules\": \"sql,xss,file,exec\", "
                "\"max_scan_time\": 120} — quét toàn bộ website tìm SQLi/XSS/"
                "file/exec. Chỉ sau khi tool trả kết quả (kể cả lỗi) lượt sau "
                "mới được trả final JSON." + hint)

    def _auto_wapiti(self, msgs: list) -> bool:
        """v1.5.2 (Bug 3): tự chạy wapiti_scan khi vòng lặp kết thúc mà web
        scope active và wapiti_scan CHƯA chạy (outcome ok/error) trong phiên —
        model bỏ qua dù prompt/gate bắt buộc. Chạy ĐÚNG MỘT lần ở tail, bounded:
          {"url": <url đầu scope>, "scope": "domain",
           "modules": "sql,xss,file,exec", "max_scan_time": 120}
        Result ghi vào transcript (round=0, auto=True), _call_cache và được đẩy
        vào [TOOL RESULTS] để final round tổng hợp bằng dữ liệu THẬT (kể cả lỗi).

        Return True nếu đã dispatch (mọi outcome kể cả denied/error), False khi
        không có điều kiện (scope không phải web, đã chạy, thiếu spec/URL)."""
        if not self._web_scope_active() or self._wapiti_done:
            return False
        spec = TOOL_INDEX.get("wapiti_scan")
        url = self._active_gate_url()
        if not spec or not url:
            return False
        args = {"url": url, "scope": "domain", "modules": "sql,xss,file,exec",
                "max_scan_time": 120}
        t0 = time.time()
        dt = 0.0
        try:
            print(f"{YELLOW}[→]{RESET} {BOLD}wapiti_scan{RESET}(AUTO — model "
                  f"chưa chạy wapiti trong phiên)", flush=True)
            r = self._dispatch("wapiti_scan", args)
            dt = round(time.time() - t0, 1)
        except Exception as e:  # noqa: BLE001 — trọn vẹn cả EOFError/deny-path
            r = {"name": "wapiti_scan", "outcome": "error",
                 "output": f"[!] auto wapiti_scan failed: {e}", "exec_time": 0.0}
            dt = round(time.time() - t0, 1)
        r.setdefault("args", dict(args))
        key = "wapiti_scan|" + json.dumps(args, sort_keys=True,
                                          default=str, ensure_ascii=False)
        self._call_cache[key] = r
        if r.get("outcome") in ("ok", "error"):
            self._wapiti_done = True
        tag = f"{GREEN}[✔]{RESET}" if r.get("outcome") == "ok" \
            else f"{RED}[✗]{RESET}"
        print(f"{tag} wapiti_scan → outcome={r.get('outcome', '?')} ({dt:.1f}s)",
              flush=True)
        self.transcript.append({"round": 0, "type": "tools", "calls": [r],
                                "auto": True})
        out = InjectionGuard.sanitize(r.get("output", ""),
                                      self.config["output_cap"])
        msg = {"role": "tool", "name": "wapiti_scan",
               "content": f"outcome={r.get('outcome')}\n{out}"}
        msgs.append({"role": "user", "content":
                    "[TOOL RESULTS BEGIN]\n" +
                    json.dumps([msg], ensure_ascii=False)[:12000] +
                    "\n[TOOL RESULTS END]\n[WAPITI TỰ CHẠY] Model không gọi "
                    "wapiti_scan trong phiên nên AGENT TỰ chạy — kết quả ở trên "
                    "(kể cả lỗi) là dữ liệu THẬT; dùng nó khi tổng hợp JSON cuối. "
                    "KHÔNG gọi tool nữa."})
        return True

    def _history(self) -> list[dict]:
        """Toàn bộ tool calls của phiên (args + outcome + output) để đối chiếu bằng chứng."""
        out: list[dict] = []
        for rnd in self.transcript:
            if rnd.get("type") == "tools":
                out.extend(rnd.get("calls") or [])
        return out

    def _commit_findings(self, result: dict) -> None:
        """Parse final JSON → đối chiếu từng finding với tool output thật (evidence
        guard v1.4.1) → thêm vào ledger. Finding thiếu bằng chứng vẫn được giữ
        nhưng đánh dấu evidence_gaps để operator biết cần xác minh thủ công."""
        findings = parse_findings_json(result.get("final_text", ""))
        if findings:
            flagged = check_findings_evidence(findings, self._history())
            result["evidence_flagged"] = flagged
        for f in findings:
            self.ledger.add(f)

    # ─────────────────────────────────────────
    # SESSION MGMT
    # ─────────────────────────────────────────
    def start_recon(self) -> str:
        """Recon sơ bộ tự động + trả context ngắn."""
        if not self.policy.has_scope:
            return "[!] No WEBX_TARGETS — recon bootstrap failed."
        target = self.config["targets"][0]
        probe = _try_dispatch(self, "http_probe", {"url": target})
        hdrs = _try_dispatch(self, "headers_recon", {"url": target})
        self.extra_context = f"TARGET: {target}\nPROBE:\n{probe['output'][:1500]}\nHEADERS:\n{hdrs['output'][:1500]}"
        return self.extra_context

    def export_report(self) -> str:
        plan = validation_plan(self.ledger)
        md = render_markdown(self.ledger, ", ".join(self.config["targets"]), plan)
        path = f"aixsec-x_report_{int(time.time())}.md"
        with open(path, "w") as f:
            f.write(md)
        return path


def _try_dispatch(agent: WebXAgent, name: str, args: dict) -> dict:
    try:
        return agent._dispatch(name, args)
    except Exception as e:  # noqa: BLE001
        return {"name": name, "outcome": "error", "output": f"[!] {e}"}


SEV_COLOR = {
    "critical": RED, "high": YELLOW, "medium": MAGENTA,
    "low": GREEN, "info": CYAN,
}
STATUS_COLOR = {"confirmed": GREEN, "candidate": YELLOW, "ruled_out": RED + DIM}


def _print_findings(agent: WebXAgent):
    if not agent.ledger.all():
        print(f"\n{CYAN}[ledger]{RESET} No findings added yet.")
        return
    print(f"\n{CYAN}{'═' * 64}{RESET}")
    print(f"{BOLD}{MAGENTA}    AIXSEC-X FINDINGS LEDGER{RESET}")
    print(f"{CYAN}{'═' * 64}{RESET}")
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    n_gap = 0
    for f in sorted(agent.ledger.all(), key=lambda x: sev.get(x.severity, 5)):
        color = SEV_COLOR.get(f.severity, CYAN)
        st = STATUS_COLOR.get(f.status, RESET)
        sev_tag = f"{BOLD}{color}[{f.severity.upper():<8}]{RESET}"
        status = f"{st}{f.status}{RESET}"
        warn = f" {DIM}⚠ {len(f.evidence_gaps)} thiếu bằng chứng{RESET}" if f.evidence_gaps else ""
        print(f"{sev_tag} {f.name}  →  {status}  ({f.url or '-'}){warn}")
        for g in f.evidence_gaps:
            print(f"        {RED}⚠ {g}{RESET}")
            n_gap += 1
    plan = validation_plan(agent.ledger)
    if n_gap:
        print(f"\n{RED}[!] {n_gap} cảnh báo thiếu bằng chứng — những finding này có thể"
              f" do model bịa. Xác minh thủ công trước khi dùng.{RESET}")
    if plan:
        print(f"\n{BOLD}{YELLOW}[NEEDS VALIDATION]{RESET}")
        for p in plan:
            print(f"  {CYAN}•{RESET} {p['finding']}: " + " | ".join(p['steps']))


def resolve_scope_interactive(cfg: dict) -> dict:
    """Hỏi target web và/hoặc src dirs ngay trên màn hình nếu env chưa đặt.
    Mỗi mục để TRỐNG = phiên này không dùng phần đó: chỉ web, chỉ SAST, hoặc cả 2."""
    if not cfg["targets"]:
        print("[*] No web target declared (WEBX_TARGETS).")
        print("    Enter authorized targets, comma-separated")
        print("    (e.g. https://abc.vn,10.0.0.0/8) — press ENTER to skip if")
        print("    this session is SOURCE-CODE ANALYSIS only:")
        inp = input(f"{CYAN}{BOLD}aixsec-target>{RESET} ").strip()
        cfg["targets"] = [t.strip() for t in inp.split(",") if t.strip()]
    if not cfg.get("src_dirs"):
        print("[*] No source directory declared (WEBX_SRC_DIRS).")
        print("    Enter code directories allowed for SAST scanning, comma-separated")
        print("    (e.g. /var/www/html) — press ENTER to skip if sast_scan is unused:")
        inp = input(f"{MAGENTA}{BOLD}aixsec-src>{RESET} ").strip()
        cfg["src_dirs"] = [d.strip() for d in inp.split(",") if d.strip()]
    return cfg


def _sysinfo() -> dict:
    """Host/session facts cho status block — toàn bộ là giá trị THẬT từ máy
    chạy, không bịa (v1.4.8)."""
    info = {"host": "host-unknown", "kernel": "-", "python": "?",
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"), "pid": os.getpid()}
    try:
        import platform
        info["host"] = platform.node() or info["host"]
        info["kernel"] = platform.release() or "-"
        info["python"] = platform.python_version()
    except Exception:  # noqa: BLE001
        pass
    return info


def _banner(cfg: dict, scope: str = "", missing=None, mode: str = "interactive",
            color: bool | None = None) -> str:
    """Màn hình khởi động kiểu hacker (v1.5.4): mặt nạ Anonymous đỏ + logo
    xanh + tiêu đề căn giữa, KHÔNG khung box (bỏ viền │…│ và nền đen v1.4.8)
    cho thoáng hơn; status block key-value căn trái theo cột key cố định; cả
    khối tự căn giữa theo bề rộng terminal khi đang là TTY. color=None → tự
    bật/tắt theo TTY (NO_COLOR cũng tắt màu)."""
    if color is None:
        color = bool(getattr(sys.stdout, "isatty", lambda: False)())
        if os.environ.get("NO_COLOR"):
            color = False
    if color:
        G, R, Y, C, M, B, D, A, RS = (GREEN, RED, YELLOW, CYAN, MAGENTA,
                                      BOLD, DIM, "\033[38;5;214m", RESET)
    else:
        G = R = Y = C = M = B = D = A = RS = ""

    info = _sysinfo()
    scope = scope or (",".join(cfg.get("targets") or []) or "(none)")
    missing = missing or {}
    n_tools = len(TOOL_REGISTRY)
    miss_str = ("  " + Y + "⚠ missing: "
                + ", ".join(f"{B}{t}{RS}{Y}({TOOL_BINS[t]}){RS}"
                            for t in sorted(missing)) + RS) if missing else ""

    W = 66   # bề rộng khối banner (tính theo ký tự HIỂN THỊ — ANSI là 0-rộng)
    _ansi = re.compile(r"\x1b\[[0-9;]*m")

    def vis(t: str) -> str:
        return _ansi.sub("", t or "")

    def center(t: str) -> str:
        pad = max(0, (W - len(vis(t))) // 2)
        return " " * pad + t

    lines = [""]
    for s in _ANON_ART.strip("\n").splitlines():
        lines.append(center(f"{R}{B}{s.rstrip()}{RS}"))
    lines.append("")
    for s in _AIXSEC_ART.strip("\n").splitlines():
        lines.append(center(f"{G}{B}{s.rstrip()}{RS}"))
    lines.append("")
    lines.append(center(f"{G}{B}AIXSEC-X v{R}{VERSION}{G}{RS}{B} — AI Web Exploitation Assistant{RS}"))
    lines.append(center(f"   {D}local LLM • Kali Linux    brand: aixsecu.com{RS}"))
    lines.append("")
    lines.append(center(f"{D}{'─' * W}{RS}"))
    lines.append("")
    lines.append(f"{C}{B}[>]{RS} {D}{'model':<9}{RS} {B}{info['python']} | {cfg.get('model', '?')}{RS}")
    lines.append(f"{C}{B}[>]{RS} {D}{'scope':<9}{RS} {G}{scope}{RS}")
    lines.append(f"{C}{B}[>]{RS} {D}{'auto-exec':<9}{RS} {Y}{cfg.get('auto_exec', 'ask')}{RS}{D}   mode: {A}{mode}{RS}")
    lines.append(f"{C}{B}[>]{RS} {D}{'host':<9}{RS} {B}{info['host']}{RS}{D}  kernel {info['kernel']}{RS}")
    lines.append(f"{C}{B}[>]{RS} {D}{'session':<9}{RS} {info['ts']}{D}  pid {info['pid']}{RS}")
    lines.append(f"{C}{B}[>]{RS} {D}{'modules':<9}{RS} {B}{n_tools}{RS}{D} tools loaded{RS}{miss_str}")
    lines.append("")
    lines.append(center(f"{D}q quit | !! <cmd> shell | /findings ledger | /report export{RS}"))
    lines.append("")

    # căn giữa cả khối theo bề rộng terminal thật (nếu rộng hơn khối + 6);
    # terminal hẹp/pipe → bỏ indent để tránh gãy dòng
    try:
        import shutil
        tw = shutil.get_terminal_size().columns
        if tw > W + 6:
            ind = " " * ((tw - W) // 2)
            lines = [ind + ln if ln else "" for ln in lines]
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(lines) + "\n"

def _print_banner(cfg: dict, scope: str = "", missing=None, mode: str = "interactive"):
    print(_banner(cfg, scope=scope, missing=missing, mode=mode), flush=True)


def main():
    cfg = load_config()

    # Chẩn đoán kết nối Ollama (không cần target/scope) — dùng nhiều nhất
    # khi model chạy trên MÁY KHÁC và Kali chỉ trỏ WEBX_OLLAMA_URL sang.
    if "--check-ollama" in sys.argv:
        from llm import check_ollama
        print(check_ollama(cfg))
        sys.exit(0)

    non_interactive = "--non-interactive" in sys.argv or "-n" in sys.argv
    do_recon = "--recon" in sys.argv or "-r" in sys.argv
    one_shot = "--oneshot" in sys.argv

    # Interactive: nhập target/src ngay trên màn hình (từng mục, để trống = bỏ qua)
    if not non_interactive and not one_shot:
        cfg = resolve_scope_interactive(cfg)

    if not cfg["targets"] and not cfg.get("src_dirs"):
        print("[!] Nothing declared — you need WEBX_TARGETS (web) and/or WEBX_SRC_DIRS (source).")
        print("    Example:")
        print("    export WEBX_TARGETS=\"https://example.com\"")
        print("    export WEBX_SRC_DIRS=\"/var/www/html\"")
        sys.exit(1)

    agent = WebXAgent(config=cfg)
    _mode = "batch" if (non_interactive or one_shot) else "interactive"
    _print_banner(cfg, scope=agent.policy.describe(),
                  missing=agent.missing_tools, mode=_mode)

    if do_recon and cfg["targets"]:
        cyan = "\033[96m"
        reset = "\033[0m"
        print(f"\n{cyan}[{reset}▶{cyan}] Quick recon...{reset}")
        ctx = agent.start_recon()
        print(ctx[:800])
    elif do_recon:
        print(f"[*] No web target — skipping recon (SAST-only session).")

    if non_interactive or one_shot:
        prompt_text = one_shot if isinstance(one_shot, str) else \
            "Hãy phân tích và khai thác target trong scope. Bắt đầu bằng recon rồi active check. Khi đủ dữ liệu trả JSON findings."
        result = agent.run(prompt_text)
        print("\n" + result.get("final_text", "")[:3000])
        _print_findings(agent)
        print(f"\n[*] Report: {agent.export_report()}")
        return

    # ── interactive ──
    print(f"{DIM}[>]{RESET} {DIM}Type{RESET} {GREEN}'q'{RESET} {DIM}quit |{RESET} {GREEN}'!! <cmd>'{RESET} {DIM}shell |{RESET} "
          f"{GREEN}'/findings'{RESET} {DIM}ledger |{RESET} {GREEN}'/report'{RESET} {DIM}export.{RESET}", flush=True)
    while True:
        try:
            line = input(f"\n{BOLD}{GREEN}root@aixsec-x{RESET}{DIM}:~#{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Exiting.")
            break
        if not line:
            continue
        if line.lower() == "q":
            break
        if line.startswith("!!"):
            os.system(line[2:].strip())
            continue
        if line == "/findings":
            _print_findings(agent)
            continue
        if line == "/report":
            print(f"[*] Saved: {agent.export_report()}")
            continue
        result = agent.run(line)
        print("\n" + (result.get("final_text", "") or "(no response)")[:4000])
        if result.get("overall_summary"):
            print(f"\n[RISK] {result['risk_level']}\n[SUMMARY] {result['overall_summary']}")
        _print_findings(agent)


if __name__ == "__main__":
    main()
