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
from urllib.parse import urljoin

# ── local imports ──
from config import load_config
from inventory import Inventory, TestHistory
from ledger import (Ledger, parse_findings_json, render_markdown, validation_plan,
                   check_findings_evidence)
from llm import InjectionGuard, ollama_chat
from context_optimization import (ContextBuilder, ContextLimits, ContextRequest,
                                  PromptComposer, PromptParts, RuntimeMetrics,
                                  TokenBudgetManager)
from prompts import SYSTEM_PROMPT, build_orchestration_prompt, build_system_prompt
from scope import ScopePolicy, normalize_host
from tools import (TOOL_REGISTRY, TOOL_INDEX, TOOL_BINS, TOOL_TIMEOUTS,
                   LONG_RUN_TOOLS, available_tools, _WAPITI_FIX, capability_report)

# ── terminal colors (AIXSEC-X style) ──
# v1.8.0: HTTP Session Engine (http_engine.py) — http_request là adapter trên
# engine (cookie jar theo host, auth, redirect history, timing, evidence, replay,
# proxy WEBX_HTTP_PROXY/WEBX_HTTPS_PROXY).
VERSION = "4.1.0"

# v1.7.0 (#12 attack memory): phân loại vuln_class cho TestHistory theo tool
# (sqli→sqli, scanner→scan, recon→recon, poc→poc; tool không khớp → "").
_TOOL_VULN = {}
for _t in ("sqli_manual_test", "sqli_blind_extract", "sqlmap_check", "sqlmap_runner"):
    _TOOL_VULN[_t] = "sqli"
for _t in ("wapiti_scan", "nikto_scan", "nuclei_scan", "sast_scan"):
    _TOOL_VULN[_t] = "scan"
for _t in ("http_probe", "http_request", "headers_recon", "detect_cms",
           "waf_detect", "ffuf_dir", "param_discovery", "subdomain_enum",
           "dns_lookup", "crawler", "api_discovery", "api_import"):
    _TOOL_VULN[_t] = "recon"
for _t in ("generate_poc", "poc_executor"):
    _TOOL_VULN[_t] = "poc"
for _t in ("auth_context_set", "auth_context_list", "auth_login",
           "auth_logout", "auth_context_remove"):
    _TOOL_VULN[_t] = "auth"
for _t in ("auth_compare", "authorization_reason"):
    _TOOL_VULN[_t] = "authorization"
for _t in ("business_rule_set", "business_workflow_test", "business_reason"):
    _TOOL_VULN[_t] = "business_logic"
for _t in ("sast_dast_correlate",):
    _TOOL_VULN[_t] = "correlation"
for _t in ("dynamic_plan", "phase3_status"):
    _TOOL_VULN[_t] = "planning"

# v1.5.8 (Bug A): chuỗi lỗi LLM từ llm.py — nhận diện để KHÔNG đếm là plan-only
# (trước đây timeout bị coi là "văn bản kế hoạch" → plan_only=2 → forced break →
# final round cũng timeout → final_text = chuỗi lỗi → ledger rỗng dù wapiti đã
# chạy thành công). Lần 1: thử lại (model có thể đang load). Lần 2 liên tiếp:
# coi model down → tổng hợp findings từ tool output thật (Bug B).
_LLM_FAIL_PREFIXES = ("[!] Ollama timeout", "[!] Ollama first-token timeout",
                       "[!] Ollama completion timeout", "[!] Ollama overall timeout",
                       "[!] Cannot reach Ollama", "[!] Ollama error")


def _llm_failure(content: str) -> bool:
    return (content or "").strip().startswith(_LLM_FAIL_PREFIXES)


def _retryable_wapiti_error(result: dict) -> bool:
    """True when Wapiti produced no report because its execution budget expired."""
    if result.get("name") != "wapiti_scan" or result.get("outcome") != "error":
        return False
    text = str(result.get("output") or "").lower()
    return any(marker in text for marker in
               ("timed out", "timeout", "time limit", "không hoàn tất"))

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

# v1.5.6: ĐÃ BỎ _ANON_ART (mặt nạ Anonymous v1.5.4 — hình `.888.` đọc thành
# chữ "AAO") theo yêu cầu user; banner chỉ còn logo _AIXSEC_ART.

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

    def done(self, response=None):
        if self._done:
            return  # idempotent — không in "finished" lần thứ 2
        self._done = True
        self._flush()
        dt = time.time() - self.t0
        failed = response is not None and _llm_failure(response.get("content", ""))
        state = "failed" if failed else "finished"
        print(f"{DIM}  └ model {state} in {dt:.1f}s{RESET}", flush=True)
        if failed:
            print(response.get("content", ""), flush=True)


class WebXAgent:
    def __init__(self, config: dict | None = None, chat=None):
        self.config = config or load_config()
        self.system_prompt = build_system_prompt(self.config)
        self.chat = chat or ollama_chat
        self.policy = ScopePolicy(self.config["targets"],
                                  src_dirs=self.config.get("src_dirs", []))
        self.ledger = Ledger()
        self.transcript: list[dict] = []
        # v1.6.0 (roadmap #1/#12/#13): Attack Surface Inventory — host→port→
        # service→URL→method→param→auth→tech, tích lũy từ tool output OK thật.
        self.inventory = Inventory()
        # v1.7.0 (#12): attack memory — cái GÌ ĐÃ THỬ (endpoint×param×vuln_class×
        # tool×outcome), KHÔNG lặp lại; tách khỏi attack surface (cái ĐÃ BIẾT).
        self.test_history = TestHistory()
        self.capabilities = None   # v1.6.0 (#14): lazy — probe version chỉ khi yêu cầu
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
        # v1.5.6: AI-NATIVE mode (WEBX_AI_NATIVE=1) — model TỰ phân tích lỗ hổng
        # bằng http_request, KHÔNG bắt buộc wapiti/sqlmap. Gate thay thế:
        # final JSON chỉ hợp lệ khi có ít nhất 1 http_request outcome=ok
        # (response THẬT) trong transcript. _no_http_json đếm lượt JSON bị chặn.
        self.ai_native = bool(self.config.get("ai_native", False))
        self._no_http_json = 0
        self.context_metrics = RuntimeMetrics()
        self.context_metrics_history: list[dict] = []

    def _context_history(self) -> list[dict]:
        values = []
        for turn in self.transcript:
            for call in turn.get("calls") or []:
                args = call.get("args") or {}
                values.append({"tool": call.get("name", ""),
                    "outcome": call.get("outcome", ""),
                    "url": args.get("url") or args.get("target") or "",
                    "parameter": args.get("param") or ""})
        return values

    def _current_endpoint(self) -> str:
        for turn in reversed(self.transcript):
            for call in reversed(turn.get("calls") or []):
                args = call.get("args") or {}
                value = args.get("url") or args.get("target")
                if not value and isinstance(args.get("request"), dict):
                    value = args["request"].get("url")
                if value:
                    return str(value)
        return str((self.config.get("targets") or [""])[0])

    def _current_context_selectors(self) -> dict:
        values = {"auth_context": "", "workflow": "", "hypothesis_id": "",
                  "parameter": ""}
        for turn in reversed(self.transcript):
            for call in reversed(turn.get("calls") or []):
                args = call.get("args") or {}
                values["auth_context"] = str(args.get("context") or
                    ((args.get("contexts") or [""])[0] if isinstance(
                        args.get("contexts"), list) else "") or values["auth_context"])
                for key in ("workflow", "hypothesis_id"):
                    values[key] = str(args.get(key) or values[key])
                values["parameter"] = str(args.get("param") or values["parameter"])
                if any(values.values()):
                    return values
        return values

    def _recent_tool_context(self) -> str:
        """Bounded evidence from several recent tool calls.

        Phase 4.1 previously exposed only the last round. A duplicate call in
        that round could therefore hide every successful HTTP response and the
        Wapiti result from final synthesis. Keep the latest six calls, while
        prioritising Wapiti and successful calls, and include bounded structured
        data so HTTP status codes do not have to be inferred from ``outcome``.
        """
        calls: list[tuple[bool, dict]] = []
        for turn in reversed(self.transcript):
            is_auto = bool(turn.get("auto"))
            for call in reversed(turn.get("calls") or []):
                calls.append((is_auto, call))
        if not calls:
            return ""
        selected: list[tuple[bool, dict]] = []
        # Evidence-bearing calls first; duplicate/blocked calls remain useful
        # only when room is left.
        for wanted in (lambda c: c.get("name") == "wapiti_scan",
                       lambda c: c.get("outcome") == "ok",
                       lambda c: c.get("outcome") == "error",
                       lambda c: True):
            for pair in calls:
                if pair in selected or not wanted(pair[1]):
                    continue
                selected.append(pair)
                if len(selected) >= 6:
                    break
            if len(selected) >= 6:
                break
        values = []
        for is_auto, call in selected:
            args = call.get("args") or {}
            row = {"name": call.get("name"), "outcome": call.get("outcome"),
                   "auto": is_auto,
                   "arguments": {key: args[key] for key in
                                 ("url", "target", "param", "method", "scope")
                                 if key in args},
                   "output": InjectionGuard.sanitize(
                       str(call.get("output") or ""), 1400)}
            data = call.get("data")
            if isinstance(data, dict):
                # Structured result is authoritative but still target-derived;
                # serialize it inside the same untrusted-data boundary.
                raw = json.dumps(data, ensure_ascii=False, sort_keys=True,
                                 default=str)[:1800]
                row["structured_data"] = InjectionGuard.sanitize(raw, 1800)
            values.append(row)
        prefix = "[WAPITI TỰ CHẠY]\n" if any(flag for flag, _ in selected) else ""
        return prefix + json.dumps(values, ensure_ascii=False, sort_keys=True)[:9000]

    def _context_tool_schemas(self) -> list[dict]:
        if not self.config.get("context_optimization", True):
            return [item.schema() for item in self.tools]
        names = {"dynamic_plan", "phase3_status"}
        if not self.transcript:
            names.update({"http_probe", "headers_recon", "crawler", "api_discovery"})
            if self.config.get("src_dirs"):
                names.add("sast_scan")
        if self._web_scope_active():
            names.add("http_request")
            if self.ai_native:
                names.update({"authorization_reason", "auth_compare"})
            elif not self._wapiti_done:
                names.add("wapiti_scan")
        try:
            import security_analysis as _security_analysis
            plan = _security_analysis.manager().plan("coverage", max_actions=10)
            names.update(item["tool"] for item in plan.get("actions") or []
                         if item.get("state") in {"planned", "blocked"})
        except (ValueError, TypeError):
            pass
        maximum = max(4, int(self.config.get("context_max_tools", 14)))
        ordered = [item for item in self.tools if item.name in names]
        return [item.schema() for item in ordered[:maximum]]

    def _prepare_llm_messages(self, messages: list[dict], goal: str,
                              tool_schemas: list[dict] | None = None) -> list[dict]:
        if not self.config.get("context_optimization", True):
            return messages
        import auth_context as _auth_context
        import security_analysis as _security_analysis
        from autonomy import KnowledgeGraph
        graph = KnowledgeGraph.from_phase_state(
            self.inventory, self.test_history, _auth_context.manager().list())
        state = _security_analysis.manager()
        limits = ContextLimits(
            max_graph_nodes=int(self.config.get("context_max_graph_nodes", 40)),
            max_observations=int(self.config.get("context_max_observations", 12)),
            max_hypotheses=int(self.config.get("context_max_hypotheses", 6)),
            max_history=int(self.config.get("context_max_history", 12)),
            max_evidence=int(self.config.get("context_max_evidence", 8)))
        self.context_metrics = RuntimeMetrics()
        selectors = self._current_context_selectors()
        context = ContextBuilder(graph, state.planner_memory, limits).build(
            ContextRequest(goal=goal, endpoint=self._current_endpoint(), **selectors),
            self._context_history(), self.context_metrics)
        from context_optimization import estimate_tokens
        reserved = int(self.config.get("reserved_completion_tokens", 2048))
        tool_tokens = estimate_tokens(tool_schemas or [])
        configured_max = int(self.config.get("max_prompt_tokens", 12000))
        message_max = max(reserved + 256, configured_max - tool_tokens)
        manager = TokenBudgetManager(message_max, reserved)
        last_instruction = ""
        for message in reversed(messages):
            if message.get("role") == "user":
                last_instruction = str(message.get("content") or "")
                break
        # The original task is protected; transient gate instructions are kept
        # only when they differ from it and are bounded independently.
        reasoning = goal
        if last_instruction and last_instruction != goal:
            reasoning += "\n\nCurrent instruction:\n" + last_instruction[:1800]
        policy = ("Authorized scope: " + self.policy.describe() +
                  ". Existing dispatcher scope checks and operator risk approval are mandatory.")
        if self._web_scope_active():
            if self.ai_native and not self._http_evidence_ok():
                policy += (" Before final JSON, call http_request and obtain at least one "
                           "successful real HTTP response.")
            elif not self.ai_native and not self._wapiti_done:
                policy += (" Before final JSON, call wapiti_scan for the authorized web "
                           "target; an explicit tool error also satisfies the attempt gate.")
        prepared = PromptComposer(manager).compose(PromptParts(
            system=build_orchestration_prompt(self.config),
            policy=policy,
            planner=context, tool=self._recent_tool_context(), reasoning=reasoning),
            self.context_metrics)
        self.context_metrics.prompt_chars += len(json.dumps(
            tool_schemas or [], ensure_ascii=False, separators=(",", ":")))
        self.context_metrics.estimated_tokens += tool_tokens
        self.context_metrics_history.append(self.context_metrics.to_dict())
        self.context_metrics_history = self.context_metrics_history[-100:]
        return prepared

    def context_runtime_metrics(self) -> dict:
        return self.context_metrics.to_dict()

    def _chat_contextual(self, messages: list[dict], goal: str, **kwargs) -> dict:
        schemas = [] if kwargs.get("json_mode") else self._context_tool_schemas()
        kwargs["tools"] = schemas
        prepared = self._prepare_llm_messages(messages, goal, schemas)
        started = time.perf_counter()
        response = self.chat(prepared, config=self.config, **kwargs)
        elapsed = (time.perf_counter() - started) * 1000
        llm_metrics = response.get("metrics") or {}
        self.context_metrics.llm_latency_ms = round(elapsed, 3)
        self.context_metrics.first_token_latency_ms = float(
            llm_metrics.get("first_token_latency_ms") or 0)
        self.context_metrics.completion_latency_ms = float(
            llm_metrics.get("completion_latency_ms") or elapsed)
        if self.context_metrics_history:
            self.context_metrics_history[-1] = self.context_metrics.to_dict()
        return response

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
            if name == "wapiti_scan":
                # max_scan_time bounds Wapiti's scan phase. Allow a small
                # cleanup/report window instead of always granting the old
                # fixed 600-second floor. Operators can explicitly raise
                # WEBX_TOOL_TIMEOUT for unusually large targets.
                requested = max(30, int(arguments.get("max_scan_time") or 300))
                bounded = min(cap, requested + 90)
                kw["_timeout"] = max(self.config["tool_timeout"], bounded)
            elif name in LONG_RUN_TOOLS:
                kw["_timeout"] = max(self.config["tool_timeout"], cap)
            else:
                kw["_timeout"] = min(self.config["tool_timeout"], cap)
            # v1.4.4: chỉ đo thời gian THỰC THI tool — chờ operator duyệt
            # (_risk_ok/input()) nằm ngoài try này nên không bị tính vào duration.
            t0 = time.time()
            res = spec.exec_fn(**kw)
            dt = round(time.time() - t0, 1)
            # v1.7.0 (structured ToolResult): tool TIÊN TIẾN trả (output_text,
            # data_dict); tool cũ/binary vẫn trả plain string → data=None.
            if (isinstance(res, tuple) and len(res) == 2
                    and isinstance(res[0], str)):
                out, data = res
            else:
                out, data = res, None
            # v1.4.4: output mở đầu '[!]' = lỗi thực thi (timeout, thiếu binary,
            # connect fail, args sai) → outcome=error để gate/fail-count đúng.
            oc = "error" if isinstance(out, str) and out.startswith("[!]") else "ok"
            r = {"name": name, "outcome": oc, "output": out, "exec_time": dt}
            if data is not None:
                r["data"] = data
            return r
        except TypeError as e:
            return {"name": name, "outcome": "error",
                    "output": f"[!] Invalid arguments for '{name}': {e}", "exec_time": 0.0}
        except Exception as e:  # noqa: BLE001
            return {"name": name, "outcome": "error",
                    "output": f"[!] {name} error: {e}", "exec_time": 0.0}

    def _record_test(self, name: str, args: dict, r: dict) -> None:
        """v1.7.0 (#12): ghi attack memory — endpoint/param đã THỬ (mọi outcome
        trừ duplicate). vuln_class theo _TOOL_VULN; evidence_id bỏ trống cho
        Phase 2 (evidence state machine gắn bằng chứng/kết quả vào record)."""
        if r.get("outcome") == "duplicate":
            return
        url = ""
        for k in ("url", "target"):
            v = args.get(k)
            if v:
                url = str(v)
                break
        if not url and isinstance(args.get("request"), dict):
            url = str(args["request"].get("url") or "")
        if not url:
            return
        self.test_history.add(
            endpoint=url,
            parameter=str(args.get("param") or ""),
            vuln_class=_TOOL_VULN.get(name, ""),
            tool=name,
            outcome=r.get("outcome") or "ok",
        )

    def run_autonomous(self, goal: str = "coverage", max_cycles: int | None = None,
                       checkpoint_path: str | None = None) -> dict:
        """Run the Phase 4 loop through the normal policy-aware dispatcher.

        This is an additive API: ``run`` and all Phase 1-3 tool APIs retain
        their existing behavior. The operator controls risk through auto_exec.
        """
        import auth_context as _auth_context
        import security_analysis as _security_analysis
        from autonomy import (AutonomousRuntime, ExecutionBudget, Goal,
                              KnowledgeGraph, PlannerMemory, WorkflowModel)

        _security_analysis.manager().bind(
            self.inventory, self.test_history, self.ledger, self.available)
        checkpoint = checkpoint_path or self.config.get("autonomy_checkpoint", "")

        def execute(action: dict) -> dict:
            name, arguments = action["tool"], action.get("arguments") or {}
            result = self._dispatch(name, arguments)
            self._record_test(name, arguments, result)
            event = {**result, "args": arguments}
            self.inventory.ingest([event])
            _security_analysis.manager().ingest_tool_result(event)
            return result

        if checkpoint and self.config.get("autonomy_resume") and os.path.exists(checkpoint):
            runtime = AutonomousRuntime.resume(checkpoint, execute)
        else:
            budget = ExecutionBudget(
                max_actions=int(self.config.get("autonomy_max_actions", 100)),
                max_requests=int(self.config.get("autonomy_max_requests", 500)),
                max_seconds=float(self.config.get("autonomy_max_seconds", 3600)),
                max_risk=float(self.config.get("autonomy_max_risk", 20)),
            )
            graph = KnowledgeGraph.from_phase_state(
                self.inventory, self.test_history, _auth_context.manager().list())
            for target in self.config.get("targets") or []:
                if str(target).startswith(("http://", "https://")) and not graph.query(
                        "endpoint", url=str(target)):
                    graph.add_node("endpoint", {"url": str(target), "methods": ["GET"],
                                                "auth_hints": [],
                                                "sources": ["configured_target"]})
            workflow = WorkflowModel()
            workflow.infer_from_runs(self.inventory.analysis.get("workflow_runs") or [])
            runtime = AutonomousRuntime(graph, PlannerMemory(), workflow, budget,
                                        capabilities=set(self.available), executor=execute)
        result = runtime.run(Goal(goal), max_cycles=max_cycles,
                             checkpoint_path=checkpoint or None)
        self.inventory.analysis["autonomy_status"] = result
        self.inventory.analysis["knowledge_graph"] = runtime.graph.to_dict()
        return result

    # ─────────────────────────────────────────
    # MAIN LOOP
    # ─────────────────────────────────────────
    def run(self, user_text: str) -> dict:
        # v1.8.0: mỗi run() bắt đầu với Session Engine SẠCH (cookie jar + request
        # records của lượt trước KHÔNG rò sang lượt này) + áp proxy từ config
        # (WEBX_HTTP_PROXY/WEBX_HTTPS_PROXY) — http_request dùng CHUNG engine này.
        import http_engine as _he
        _he.reset_sessions()
        import auth_context as _auth_context
        _auth_context.reset_contexts()
        import security_analysis as _security_analysis
        _security_analysis.reset()
        _security_analysis.manager().bind(
            self.inventory, self.test_history, self.ledger, self.available)
        _px = {k: v for k, v in (("http", self.config.get("http_proxy")),
                                 ("https", self.config.get("https_proxy"))) if v}
        _he.set_proxies(_px or None)
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
        llm_down = False  # v1.5.8 (Bug A/B): model down (2 lỗi LLM liên tiếp)
        self._llm_fail = 0  # v1.5.8: bộ đếm lỗi LLM liên tiếp (reset mỗi run)
        self._plan_only = 0  # v1.4.3: reset bộ đếm plan-only mỗi run()
        self._wapiti_done = False  # v1.5.2: reset wapiti-first gate mỗi run()
        self._no_wapiti_json = 0   # v1.5.2: reset bộ đếm JSON-thiếu-wapiti
        self._no_http_json = 0     # v1.5.6: reset bộ đếm JSON-thiếu-http_request (AI-native)
        for rnd in range(1, max_rounds + 1):
            disp = _LiveDisplay(rnd, max_rounds)
            resp = self._chat_contextual(
                msgs, user_text, tools=[t.schema() for t in self.tools],
                on_token=disp.on_token, on_reasoning=disp.on_reasoning)
            # Chốt đồng hồ model ngay khi Ollama trả về. Thời gian thực thi
            # tool được in riêng bởi dispatcher và không được cộng vào nhãn
            # "model finished".
            disp.done(resp)
            calls = resp.get("tool_calls") or []
            if not calls:
                result["final_text"] = resp.get("content", "")
                # v1.5.8 (Bug A): chuỗi lỗi LLM (timeout/không kết nối) KHÔNG
                # phải văn bản kế hoạch — trước đây bị đếm plan_only → forced
                # break sớm + final round cũng timeout → ledger rỗng dù wapiti
                # đã chạy ok. Lần 1: thử lại (model có thể đang load). Lần 2
                # liên tiếp: model down → dừng sớm, tổng hợp từ tool output thật.
                if _llm_failure(result["final_text"]):
                    self._llm_fail += 1
                    if self._llm_fail >= 2:
                        forced = True
                        llm_down = True
                        break
                    msgs.append({"role": "assistant", "content": result["final_text"]})
                    msgs.append({"role": "user", "content":
                                "⚠ Lỗi kết nối model (timeout) — có thể model "
                                "đang load. Thử lại lượt này: gọi ÍT NHẤT 1 "
                                "function call NGAY, không cần văn bản dài."})
                    continue
                self._llm_fail = 0  # phản hồi thật → reset bộ đếm lỗi LLM
                if self._looks_like_json(result["final_text"]):
                    self._apply_final_contract(result)
                    # v1.5.2: wapiti-first gate (Bug 3 — user: "wapiti vẫn chưa
                    # được chạy") — web scope active nhưng wapiti_scan CHƯA
                    # chạy (ok/error) → JSON bị từ chối dù các active check khác
                    # (sqli_manual_test/sqlmap_runner...) đã ok.
                    # >=2 lần liên tiếp → forced: _auto_wapiti tự chạy wapiti
                    # trước khi ép trả JSON bằng dữ liệu thật.
                    # v1.5.6: AI-NATIVE mode (WEBX_AI_NATIVE=1) THAY THẾ gate
                    # này — không bắt buộc wapiti; thay vào đó JSON chỉ hợp lệ
                    # khi có ít nhất 1 http_request outcome=ok (response THẬT
                    # do model tự thu thập và phân tích).
                    if self.ai_native:
                        if self._web_scope_active() and not self._http_evidence_ok():
                            self._no_http_json += 1
                            msgs.append({"role": "assistant", "content": result["final_text"]})
                            msgs.append({"role": "user", "content": self._ai_native_gate_message()})
                            if self._no_http_json >= 2:
                                forced = True
                                break
                            continue
                        return result
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
            self._llm_fail = 0   # v1.5.8: lượt có tool call thật → model OK

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
                # v1.7.0 (#12): attack memory — ghi NGAY sau khi có kết quả
                # (kể cả error/blocked; duplicate đã ghi ở lần dispatch đầu).
                if r.get("outcome") != "duplicate":
                    self._record_test(name, args, r)
            self.transcript.append({"round": rnd, "type": "tools", "calls": results})
            # v1.6.0 (#1/#12/#13): gom tool output OK của round vào attack surface
            self.inventory.ingest(results)
            for _analysis_result in results:
                _security_analysis.manager().ingest_tool_result(_analysis_result)
            result["calls"] += len(results)
            # v1.5.2: wapiti-first gate — chỉ wapiti_scan tính là "đã chạy" khi
            # outcome ok (thành công) HOẶC error (đã cố, fail rõ ràng). Các
            # outcome khác (duplicate/blocked/denied/scope_rejected) KHÔNG tính.
            for r in results:
                if (r.get("name") == "wapiti_scan"
                        and (r.get("outcome") == "ok"
                             or (r.get("outcome") == "error"
                                 and not _retryable_wapiti_error(r)))):
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
            # v1.6.0 (#1/#13): chèn attack surface đã biết vào lượt sau — model
            # KHÔNG rescan host/endpoint có sẵn, chỉ chọn bước mới (tech→tool).
            surf = self.inventory.render()
            surf_note = ("\n[ATTACK SURFACE — đã biết, KHÔNG rescan các mục này; "
                         "dùng tech/endpoint để chọn bước TIẾP THEO]:\n" + surf
                         ) if surf else ""
            # v1.7.0 (#12): attack memory — những gì ĐÃ THỬ để model KHÔNG lặp
            # lại tool-call trên cùng endpoint/param/lớp lỗ hổng.
            th_note = ("\n" + self.test_history.render()) \
                if self.test_history.record_count() else ""
            try:
                live_plan = _security_analysis.manager().plan("coverage", max_actions=8)
                plan_rows = [
                    f"- {a['state']} P{a['priority']} {a['tool']} "
                    f"reason={a['reason']}"
                    + (f" blocked_by={','.join(a['blocked_by'])}" if a["blocked_by"] else "")
                    for a in live_plan["actions"]]
                plan_note = ("\n[DYNAMIC PLAN — live state, ưu tiên action planned; "
                             "giải quyết blocked_by trước]:\n" + "\n".join(plan_rows)) \
                    if plan_rows else ""
            except (ValueError, TypeError):
                plan_note = ""
            msgs.append({"role": "user", "content":
                        "[TOOL RESULTS BEGIN]\n" +
                        json.dumps(tool_msgs, ensure_ascii=False)[:12000] +
                        "\n[TOOL RESULTS END]\nTiếp tục. Khi đủ dữ liệu trả JSON cuối cùng."
                        + surf_note + th_note + plan_note})

        # v1.5.2 (tail-order 1): AUTO-WAPITI — hết vòng lặp mà web scope active
        # và wapiti_scan chưa từng chạy (model bỏ qua dù prompt/gate bắt buộc)
        # thì agent TỰ gọi wapiti_scan một lần (bounded) để mọi phiên web-scope
        # đều có kết quả wapiti thật trước khi tổng hợp JSON cuối.
        # v1.5.6: AI-NATIVE mode KHÔNG chạy auto-wapiti (không bắt buộc wapiti).
        dispatched = self._auto_wapiti(msgs)
        if dispatched:
            result["calls"] += 1
        # hết budget (hoặc dừng sớm vì round thoái hóa: toàn duplicate/blocked
        # hoặc model chỉ trả văn bản kế hoạch 2 lượt liên tiếp) — ép trả JSON
        if forced:
            if self.ai_native:
                gate_note = ("PHIÊN NÀY CHƯA CÓ HTTP_REQUEST THÀNH CÔNG — nếu "
                             "bạn đã gọi http_request mà đều lỗi (network/scope/"
                             "timeout), hãy phản ánh trung thực trong JSON. "
                             if self._no_http_json >= 2
                             and not self._http_evidence_ok() else "")
            else:
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
        # v1.5.6: AI-native dùng điều kiện tương đương — chưa có http_request ok.
        if not forced and self._web_scope_active():
            if self.ai_native:
                if not self._http_evidence_ok():
                    msgs.append({"role": "user", "content":
                                "⚠ Lưu ý tổng hợp: phiên này CHƯA CÓ HTTP_REQUEST "
                                "THÀNH CÔNG nào "
                                f"và budget ({max_rounds} round) đã cạn. Không gọi "
                                "tool nữa — trả final JSON trung thực với dữ liệu "
                                "đã thu; nếu chưa đủ bằng chứng, risk_level=UNKNOWN "
                                "là kết quả trung thực (đừng bịa dữ liệu scan)."})
            elif not self._wapiti_done:
                msgs.append({"role": "user", "content":
                            "⚠ Lưu ý tổng hợp: phiên này WAPITI_SCAN chưa chạy được "
                            f"và budget ({max_rounds} round) đã cạn. Không gọi tool "
                            "nữa — trả final JSON trung thực với dữ liệu đã thu; "
                            "nếu chưa đủ bằng chứng, risk_level=UNKNOWN là kết quả "
                            "trung thực (đừng bịa dữ liệu scan)."})
        # Nếu hai lượt đầu timeout nhưng auto-wapiti vừa bổ sung bằng chứng mới,
        # cho model đúng một cơ hội tổng hợp cuối. Đây là một tác vụ khác với
        # hai lượt plan trước và thường thành công sau khi model đã load xong.
        # Không có dữ liệu mới thì giữ fail-fast và tổng hợp tại chỗ.
        if llm_down and not dispatched:
            result["llm_down"] = True
            result["llm_note"] = ("[!] Model không phản hồi (lỗi Ollama) — "
                                  "kết quả được tổng hợp từ tool output thật "
                                  "của phiên (không có phân tích của model).")
            self._synthesize_findings_json(result)
            self._commit_findings(result)
            return result
        disp = _LiveDisplay(0 if forced else max_rounds, max_rounds)
        resp = self._chat_contextual(
            msgs, user_text, tools=[t.schema() for t in self.tools], json_mode=True,
            on_token=disp.on_token, on_reasoning=disp.on_reasoning)
        disp.done(resp)
        result["final_text"] = resp.get("content", "")
        if _llm_failure(result["final_text"]):
            result["llm_down"] = True
            result["llm_note"] = ("[!] Model không phản hồi ở final round — "
                                  "kết quả được tổng hợp từ tool output thật "
                                  "của phiên (không có phân tích của model).")
            self._synthesize_findings_json(result)
            self._commit_findings(result)
            return result
        self._llm_fail = 0
        self._apply_final_contract(result)
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

    def _synthesize_findings_json(self, result: dict) -> None:
        """Model down → tổng hợp findings từ dữ liệu Wapiti thật trong history.

        Ưu tiên ``ToolResult.data.findings`` vì đây là contract có cấu trúc,
        sau đó mới parse output chữ để tương thích các adapter/release cũ:
        `[SEVERITY] CATEGORY (param=X) — METHOD /path [module=...]` + dòng
        `    → ` theo sau (bỏ wstg:/curl:). Dừng ở marker `[✓] TỔNG HỢP LỖ
        HỔNG` — phần summary có dòng no-param match regex → duplicate. Không
        bịa: không có dòng nào → risk UNKNOWN, findings rỗng."""
        detail_re = re.compile(
            r"^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)(?:\s+\(param=([^)]+)\))?"
            r"\s+—\s+(\S+)\s+(\S+)(?:\s+\[module=([^\]]+)\])?$")
        scope_re = re.compile(r"\[✓\] wapiti QUÉT XONG.*—\s+(\S+)\s+\[scope=")
        stop_marker = "[✓] TỔNG HỢP LỖ HỔNG"
        seen: set = set()
        findings: list[dict] = []
        target = ""
        severity = {"0": "info", "1": "low", "2": "medium", "3": "high",
                    "4": "critical", "info": "info", "low": "low",
                    "medium": "medium", "high": "high", "critical": "critical"}
        history = self._history()

        # New structured result path. It remains usable even when display text
        # is truncated, localized, or reformatted.
        for msg in history:
            if msg.get("name") != "wapiti_scan" or msg.get("outcome") != "ok":
                continue
            data = msg.get("data")
            if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
                continue
            base = str(data.get("target") or "")
            target = target or base
            for item in data["findings"]:
                if not isinstance(item, dict):
                    continue
                cat = str(item.get("category") or "").strip()
                if not cat:
                    continue
                method = str(item.get("method") or "GET").upper()
                path = str(item.get("path") or "")
                param = str(item.get("parameter") or "")
                module = str(item.get("module") or "")
                key = (cat, method, path, param)
                if key in seen:
                    continue
                seen.add(key)
                raw_level = str(item.get("level") or "info").lower()
                findings.append({
                    "name": cat,
                    "severity": severity.get(raw_level, "info"),
                    "url": urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                           if base else path,
                    "port": "", "service": "",
                    "description": (f"{cat} phát hiện bởi wapiti "
                                    f"(module={module or '?'})"),
                    "fix": _WAPITI_FIX.get(cat, _WAPITI_FIX.get("_default", "")),
                    "cves": [], "source": "wapiti_scan (auto — model down)",
                    "source_tool": "wapiti_scan", "parameter": param,
                })
        for msg in history:
            text = msg.get("output") or ""
            if not text:
                continue
            if not target:
                m = scope_re.search(text)
                if m:
                    target = m.group(1)
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if stop_marker in line:
                    break
                m = detail_re.match(line.strip())
                if not m:
                    continue
                sev, cat, param, method, path, module = m.groups()
                key = (cat, method, path, param)
                if key in seen:
                    continue
                seen.add(key)
                detail = ""
                if i + 1 < len(lines):
                    nxt = lines[i + 1].strip()
                    if nxt.startswith("→") and not nxt.startswith(("→ wstg:", "→ curl:")):
                        detail = nxt[1:].strip()
                desc = f"{cat} phát hiện bởi wapiti (module={module or '?'})"
                if detail:
                    desc += f" — {detail}"
                findings.append({
                    "name": cat,
                    "severity": sev.lower(),
                    "url": f"{target}{path}" if target else path,
                    "port": "",
                    "service": "",
                    "description": desc,
                    "fix": _WAPITI_FIX.get(cat, _WAPITI_FIX.get("_default", "")),
                    "cves": [],
                    # v1.6.0 (#15): source_tool = scanner chính (giữ 'source'
                    # cho tương thích test/parse cũ)
                    "source": "wapiti_scan (auto — model down)",
                    "source_tool": "wapiti_scan",
                    "parameter": param or "",
                })
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        findings.sort(key=lambda f: rank.get(f["severity"], 0), reverse=True)
        result["risk_level"] = findings[0]["severity"] if findings else "UNKNOWN"
        if findings:
            result["overall_summary"] = (
                f"Tổng hợp tự động từ tool output thật (wapiti_scan) — model "
                f"không phản hồi (lỗi Ollama) nên không có phân tích của "
                f"model. {len(findings)} finding từ wapiti.")
        else:
            result["overall_summary"] = (
                "Model không phản hồi (lỗi Ollama) và không có finding nào "
                "tổng hợp được từ tool output — risk UNKNOWN là kết quả trung thực.")
        result["findings"] = findings
        result["final_text"] = json.dumps({
            "risk_level": result["risk_level"],
            "overall_summary": result["overall_summary"],
            "findings": findings,
        }, ensure_ascii=False, indent=2)

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

    def _http_evidence_ok(self) -> bool:
        """v1.5.6: AI-NATIVE mode — có ít nhất 1 http_request outcome=ok trong
        transcript (response THẬT do model tự thu thập) thì final JSON có cơ sở
        bằng chứng. Chỉ đếm outcome=ok (error/denied/blocked/duplicate không
        phải response thật)."""
        for entry in self.transcript:
            for r in entry.get("calls", []):
                if (r.get("name") == "http_request"
                        and r.get("outcome") == "ok"):
                    return True
        return False

    def _ai_native_gate_message(self) -> str:
        """v1.5.6: thông báo từ chối final JSON trong AI-NATIVE mode — KHÔNG
        bắt buộc wapiti/sqlmap; bắt buộc ít nhất 1 http_request outcome=ok
        (response thật) trước khi tổng hợp findings."""
        url = self._active_gate_url() or "<URL-trong-scope>"
        return ("Bản tổng hợp JSON của bạn CHƯA HỢP LỆ: phiên này đang chạy "
                "chế độ AI-NATIVE (WEBX_AI_NATIVE=1) — KHÔNG bắt buộc "
                "wapiti_scan/sqlmap_runner, nhưng MỌI finding phải dựa trên "
                "response HTTP THẬT do chính bạn thu thập qua tool http_request. "
                "Hiện chưa có http_request nào outcome=ok trong phiên. Bắt buộc "
                "lượt này gọi function call http_request với "
                f"{{\"method\": \"get\", \"url\": "
                f"{json.dumps(url, ensure_ascii=False)}}} "
                "(hoặc post kèm body) để lấy response thật, TỰ phân tích "
                "(quote-differential, error-based, timing, XSS reflection, SSTI, "
                "path traversal...) rồi mới tổng hợp JSON. Chỉ sau khi có ít "
                "nhất 1 response http_request thật, lượt sau mới được trả "
                "final JSON.")

    def _auto_wapiti(self, msgs: list) -> bool:
        """v1.5.2 (Bug 3): tự chạy wapiti_scan khi vòng lặp kết thúc mà web
        scope active và wapiti_scan CHƯA chạy (outcome ok/error) trong phiên —
        model bỏ qua dù prompt/gate bắt buộc. Chạy ĐÚNG MỘT lần ở tail, bounded:
          {"url": <url đầu scope>, "scope": "domain",
           "modules": "sql,xss,file,exec", "max_scan_time": 120}
        Result ghi vào transcript (round=0, auto=True), _call_cache và được đẩy
        vào [TOOL RESULTS] để final round tổng hợp bằng dữ liệu THẬT (kể cả lỗi).

        v1.5.6: AI-NATIVE mode (WEBX_AI_NATIVE=1) KHÔNG chạy auto-wapiti —
        model tự phân tích bằng http_request, wapiti không bắt buộc.

        Return True nếu đã dispatch (mọi outcome kể cả denied/error), False khi
        không có điều kiện (scope không phải web, đã chạy, AI-native, thiếu
        spec/URL)."""
        if self.ai_native:
            return False
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
        if (r.get("outcome") == "ok"
                or (r.get("outcome") == "error" and not _retryable_wapiti_error(r))):
            self._wapiti_done = True
        tag = f"{GREEN}[✔]{RESET}" if r.get("outcome") == "ok" \
            else f"{RED}[✗]{RESET}"
        print(f"{tag} wapiti_scan → outcome={r.get('outcome', '?')} ({dt:.1f}s)",
              flush=True)
        scan_data = r.get("data") or {}
        if isinstance(scan_data, dict) and isinstance(scan_data.get("findings"), list):
            print(f"[i] Wapiti: {len(scan_data['findings'])} findings; "
                  f"crawled={scan_data.get('crawled', '?')}; "
                  f"report={scan_data.get('report_path', '?')}", flush=True)
        self.transcript.append({"round": 0, "type": "tools", "calls": [r],
                                "auto": True})
        self.inventory.ingest([r])   # v1.6.0: wapiti auto cũng vào attack surface
        import security_analysis as _security_analysis
        _security_analysis.manager().ingest_tool_result(r)
        self._record_test("wapiti_scan", args, r)
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

    def _apply_final_contract(self, result: dict) -> None:
        """Validate final JSON before accepting its risk or ledger entries.

        Require structured Wapiti support for scanner-attributed findings.
        Scan summaries are observations, never vulnerability findings. Other
        adapters retain their existing evidence validation.
        """
        raw = self._strip_fence(str(result.get("final_text") or ""))
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(data, dict):
            return
        items = data.get("findings")
        if not isinstance(items, list):
            items = []
        valid_items = [item for item in items
                       if isinstance(item, dict) and str(item.get("name") or "").strip()]
        invalid_count = len(items) - len(valid_items)
        # Scanner observations are not vulnerabilities. For structured Wapiti
        # evidence require a matching category, URL and parameter, and use the
        # scanner's severity rather than allowing the model to inflate it.
        rejected = []
        accepted = []
        wapiti_runs = [r for r in self._history()
                       if r.get("name") == "wapiti_scan" and r.get("outcome") == "ok"
                       and isinstance(r.get("data"), dict)
                       and isinstance(r["data"].get("findings"), list)]
        only_wapiti = bool(wapiti_runs) and not any(
            r.get("outcome") == "ok" and r.get("name") != "wapiti_scan"
            for r in self._history())
        levels = {"0": "info", "1": "low", "2": "medium", "3": "high",
                  "4": "critical"}
        for item in valid_items:
            name = str(item.get("name") or "").lower()
            source = " ".join(str(item.get(k) or "") for k in
                              ("source", "source_tool", "description")).lower()
            scan_observation = bool(re.search(
                r"^(?:wapiti[ \-_]*)?(?:domain |web |website )?scan(?: summary| report| results?| completed)?$",
                name.strip()))
            matches = []
            if only_wapiti or "wapiti" in source or "wapiti" in name:
                for run in wapiti_runs:
                    base = str(run["data"].get("target") or run.get("args", {}).get("url") or "")
                    for finding in run["data"]["findings"]:
                        if not isinstance(finding, dict):
                            continue
                        category = str(finding.get("category") or "").strip().lower()
                        url = urljoin(base.rstrip("/") + "/", str(finding.get("path") or ""))
                        if (category and category in name
                                and str(item.get("url") or "").rstrip("/") == url.rstrip("/")
                                and str(item.get("parameter") or "") == str(finding.get("parameter") or "")):
                            matches.append(finding)
                if wapiti_runs and not matches:
                    rejected.append(item)
                    continue
            if scan_observation:
                rejected.append(item)
                continue
            if matches:
                item = dict(item)
                rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                item["severity"] = max(
                    (levels.get(str(f.get("level")), str(f.get("level") or "info").lower())
                     for f in matches), key=lambda v: rank.get(v, 0))
            accepted.append(item)
        valid_items = accepted
        risk = str(data.get("risk_level") or "UNKNOWN").upper()
        if risk not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
            risk = "UNKNOWN"
        summary = str(data.get("overall_summary") or "")
        if not valid_items:
            risk = "UNKNOWN"
            if invalid_count:
                note = (f"Đã loại {invalid_count} finding không đúng schema "
                        "(thiếu trường name); không còn finding hợp lệ nên risk UNKNOWN.")
                summary = (summary.rstrip() + " " + note).strip()
        if rejected or wapiti_runs:
            ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            severities = [str(f.get("severity") or "").lower() for f in valid_items]
            risk = max((v for v in severities if v in ranks),
                       key=ranks.get, default="UNKNOWN").upper()
        if rejected:
            summary = (f"Đã loại {len(rejected)} mục mô tả scan hoặc không khớp bằng chứng Wapiti. "
                       f"Còn {len(valid_items)} finding; đánh giá chưa đầy đủ.")
            result["unsupported_findings"] = len(rejected)
        data["findings"] = valid_items
        data["risk_level"] = risk
        data["overall_summary"] = summary
        # Always emit the validated object so terminal output, ledger and API
        # consumers observe the same result.
        result["final_text"] = json.dumps(data, ensure_ascii=False, indent=2)
        result["risk_level"] = risk
        result["overall_summary"] = summary
        result["findings"] = valid_items
        if invalid_count:
            result["invalid_findings"] = invalid_count
        self._commit_findings(result)

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
        # v1.6.0: recon bootstrap cũng nuôi attack surface
        self.inventory.ingest([probe, hdrs])
        # v1.7.0 (#12): recon bootstrap cũng là attack memory
        self._record_test("http_probe", {"url": target}, probe)
        self._record_test("headers_recon", {"url": target}, hdrs)
        self.extra_context = f"TARGET: {target}\nPROBE:\n{probe['output'][:1500]}\nHEADERS:\n{hdrs['output'][:1500]}"
        return self.extra_context

    def export_report(self) -> str:
        plan = validation_plan(self.ledger)
        md = render_markdown(self.ledger, ", ".join(self.config["targets"]), plan)
        # v1.6.0 (#1): report kèm attack surface phiên này (endpoint/tech đã biết)
        surf = self.inventory.render(limit=60)
        if surf:
            md += f"\n## Attack Surface (phiên này)\n```\n{surf}\n```\n"
        # v1.7.0 (#12): report kèm attack memory (cái đã thử) — phân biệt rõ
        # với findings (ledger) để operator thấy phần việc đã làm.
        th = self.test_history.render(limit=60)
        if th:
            md += f"\n## Test History (đã thử — attack memory)\n```\n{th}\n```\n"
        if self.inventory.analysis:
            summary = {
                "latest_plan": self.inventory.analysis.get("latest_plan", {}),
                "authorization_hypotheses": self.inventory.analysis.get(
                    "authorization_hypotheses", []),
                "business_hypotheses": self.inventory.analysis.get(
                    "business_hypotheses", []),
                "sast_dast_correlations": self.inventory.analysis.get(
                    "sast_dast_correlations", [])[:20],
            }
            md += ("\n## Phase 3 Analysis (hypotheses, chưa phải verdict)\n```json\n" +
                   json.dumps(summary, ensure_ascii=False, indent=2)[:20000] +
                   "\n```\n")
        path = f"aixsec-x_report_{int(time.time())}.md"
        with open(path, "w") as f:
            f.write(md)
        return path

    def save_inventory(self) -> str:
        """v1.6.0: lưu attack surface JSON khi config['inventory_file'] set
        (env WEBX_INVENTORY_FILE). Trả path đã lưu, '' nếu chưa cấu hình."""
        path = (self.config.get("inventory_file") or "").strip()
        if not path:
            return ""
        try:
            self.inventory.save(path)
            return path
        except OSError as e:
            print(f"[!] Không lưu được inventory: {e}")
            return ""

    def capability_rows(self, force: bool = False) -> list[dict]:
        """v1.6.0 (#14 Capability Discovery): [{tool,binary,available,version}].
        LAZY — probe version (subprocess) chỉ khi user yêu cầu; cache để không
        chạy lại mỗi round/lúc khởi động (giữ test nhanh)."""
        if self.capabilities is None:
            self.capabilities = capability_report(force=False)
        elif force:
            self.capabilities = capability_report(force=True)
        return self.capabilities


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
        print("    (e.g. https://example.com,10.0.0.0/8) — press ENTER to skip if")
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
    """Màn hình khởi động kiểu hacker (v1.5.6): logo AIXSEC-X xanh + tiêu đề
    căn giữa, KHÔNG khung box (bỏ viền │…│ và nền đen v1.4.8) cho thoáng hơn;
    v1.5.6 BỎ mặt nạ Anonymous đỏ của v1.5.4 theo yêu cầu user; status block
    key-value căn trái theo cột key cố định; cả khối tự căn giữa theo bề rộng
    terminal khi đang là TTY. color=None → tự bật/tắt theo TTY (NO_COLOR cũng
    tắt màu)."""
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
    cap_ok = len(TOOL_BINS) - len(missing)
    lines.append(f"{C}{B}[>]{RS} {D}{'capability':<9}{RS} {B}{cap_ok}/{len(TOOL_BINS)}{RS}"
                 f"{D} external binaries present — '/capabilities' xem versions{RS}")
    lines.append("")
    lines.append(center(f"{D}q quit | !! <cmd> shell | /findings ledger | /report export | /capabilities versions{RS}"))
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

    # v1.6.0 (#14): --capabilities — in bảng tool/binary/version rồi thoát
    if "--capabilities" in sys.argv:
        for r in agent.capability_rows():
            mark = "✔" if r["available"] else "✗"
            ver = r["version"] or "(chưa cài)"
            print(f"[{mark}] {r['tool']:<22} {r['binary']:<12} {ver}")
        return

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
        if cfg.get("autonomy_enabled"):
            result = agent.run_autonomous("coverage")
            print("\n" + json.dumps(result, ensure_ascii=False, indent=2)[:3000])
            agent.save_inventory()
            return
        result = agent.run(prompt_text)
        if result.get("llm_down"):
            print("\n" + result.get("llm_note", ""))
        print("\n" + result.get("final_text", "")[:3000])
        _print_findings(agent)
        print(f"\n[*] Report: {agent.export_report()}")
        inv_path = agent.save_inventory()   # v1.6.0: WEBX_INVENTORY_FILE
        if inv_path:
            print(f"[*] Attack surface: {inv_path}")
        return

    # ── interactive ──
    print(f"{DIM}[>]{RESET} {DIM}Type{RESET} {GREEN}'q'{RESET} {DIM}quit |{RESET} {GREEN}'!! <cmd>'{RESET} {DIM}shell |{RESET} "
          f"{GREEN}'/findings'{RESET} {DIM}ledger |{RESET} {GREEN}'/report'{RESET} {DIM}export |{RESET} "
          f"{GREEN}'/autonomy [goal]'{RESET} {DIM}|{RESET} "
          f"{GREEN}'/context-metrics'{RESET}{DIM}.{RESET}", flush=True)
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
        if line == "/capabilities":
            for r in agent.capability_rows():
                mark = "✔" if r["available"] else "✗"
                ver = r["version"] or "(chưa cài)"
                print(f"[{mark}] {r['tool']:<22} {r['binary']:<12} {ver}")
            continue
        if line == "/context-metrics":
            print(json.dumps(agent.context_runtime_metrics(), ensure_ascii=False, indent=2))
            continue
        if line == "/autonomy" or line.startswith("/autonomy "):
            goal = line.partition(" ")[2].strip() or "coverage"
            print(json.dumps(agent.run_autonomous(goal), ensure_ascii=False, indent=2))
            agent.save_inventory()
            continue
        result = agent.run(line)
        if result.get("llm_down"):
            print("\n" + result.get("llm_note", ""))
        print("\n" + (result.get("final_text", "") or "(no response)")[:4000])
        if result.get("overall_summary"):
            print(f"\n[RISK] {result['risk_level']}\n[SUMMARY] {result['overall_summary']}")
        _print_findings(agent)
        agent.save_inventory()   # v1.6.0: WEBX_INVENTORY_FILE (nếu set)


if __name__ == "__main__":
    main()
