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
import sys
import time

# ── local imports ──
from config import load_config
from ledger import (Ledger, parse_findings_json, render_markdown, validation_plan)
from llm import InjectionGuard, ollama_chat
from prompts import SYSTEM_PROMPT, build_system_prompt
from scope import ScopePolicy
from tools import TOOL_REGISTRY, TOOL_INDEX

# ── terminal colors (AIXSEC-X style) ──
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

SEVERITY_RISK = {"destructive": 4, "active": 3, "noisy": 2, "safe": 1}


class _LiveDisplay:
    """Màn hình live khi model đang xử lý: reasoning (mờ) + nội dung (xanh)
    + thời gian mỗi lượt — để người dùng thấy agent đang nghĩ/khai thác gì.

    Mỗi lượt (round) dùng 1 đối tượng: khởi tạo in header, callback từ
    ollama_chat streaming đẩy từng dòng, done() chốt elapsed time.
    """

    REASON_CAP = 250   # ký tự tối đa mỗi dòng reasoning
    CONTENT_CAP = 600  # ký tự tối đa mỗi dòng nội dung

    def __init__(self, rnd, max_rounds=None):
        self.t0 = time.time()
        label = f"Round {rnd}/{max_rounds}" if rnd else "Final round"
        print(f"\n{CYAN}[*]{RESET} {BOLD}{label}{RESET} — "
              f"{DIM}model processing...{RESET}", flush=True)

    @staticmethod
    def _line(chunk, cap: int) -> str:
        s = "".join(chunk) if isinstance(chunk, (list, tuple)) else str(chunk)
        return " ".join(s.split())[:cap]

    def on_reasoning(self, chunk: str):
        s = self._line(chunk, self.REASON_CAP)
        if s:
            print(f"{DIM}  ✦ think:{RESET} {DIM}{s}{RESET}", flush=True)

    def on_token(self, token: str):
        s = self._line(token, self.CONTENT_CAP)
        if s:
            print(f"{GREEN}  ▸{RESET} {GREEN}{s}{RESET}", flush=True)

    def done(self):
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
            kw["_timeout"] = self.config["tool_timeout"]
            out = spec.exec_fn(**kw)
            return {"name": name, "outcome": "ok", "output": out}
        except TypeError as e:
            return {"name": name, "outcome": "error",
                    "output": f"[!] Invalid arguments for '{name}': {e}"}
        except Exception as e:  # noqa: BLE001
            return {"name": name, "outcome": "error", "output": f"[!] {name} error: {e}"}

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
        for rnd in range(1, max_rounds + 1):
            disp = _LiveDisplay(rnd, max_rounds)
            resp = self.chat(msgs, tools=[t.schema() for t in self.tools],
                             on_token=disp.on_token, on_reasoning=disp.on_reasoning)
            calls = resp.get("tool_calls") or []
            if not calls:
                disp.done()
                result["final_text"] = resp.get("content", "")
                if not self._looks_like_json(result["final_text"]):
                    return result
                for f in parse_findings_json(result["final_text"]):
                    self.ledger.add(f)
                try:
                    d = json.loads(self._strip_fence(result["final_text"]))
                    result["risk_level"] = d.get("risk_level", "UNKNOWN")
                    result["overall_summary"] = d.get("overall_summary", "")
                except json.JSONDecodeError:
                    pass
                return result

            # chạy tool tuần tự: in lệnh → dispatch → kết quả kèm thời gian
            results = []
            for c in calls:
                name = c.get("name", "?")
                args = c.get("arguments") or {}
                print(f"{YELLOW}[→]{RESET} {BOLD}{name}{RESET}("
                      f"{json.dumps(args, ensure_ascii=False)[:200]})", flush=True)
                t0 = time.time()
                r = self._dispatch(name, args)
                dt = time.time() - t0
                tag = f"{GREEN}[✔]{RESET}" if r.get("outcome") == "ok" \
                    else f"{RED}[✗]{RESET}"
                print(f"{tag} {name} → outcome={r.get('outcome', '?')} ({dt:.1f}s)",
                      flush=True)
                results.append(r)
            disp.done()
            self.transcript.append({"round": rnd, "type": "tools", "calls": results})
            result["calls"] += len(results)

            tool_msgs = []
            for r in results:
                out = InjectionGuard.sanitize(r["output"], self.config["output_cap"])
                tool_msgs.append({"role": "tool", "name": r["name"],
                                  "content": f"outcome={r['outcome']}\n{out}"})
            msgs.append({"role": "assistant", "content": resp.get("content", "") or
                        "(calling tools...)"})
            msgs.append({"role": "user", "content":
                        "[TOOL RESULTS BEGIN]\n" +
                        json.dumps(tool_msgs, ensure_ascii=False)[:12000] +
                        "\n[TOOL RESULTS END]\nTiếp tục. Khi đủ dữ liệu trả JSON cuối cùng."})

        # hết budget — ép trả JSON
        disp = _LiveDisplay(max_rounds, max_rounds)
        resp = self.chat(msgs, tools=[t.schema() for t in self.tools], json_mode=True,
                         on_token=disp.on_token, on_reasoning=disp.on_reasoning)
        disp.done()
        result["final_text"] = resp.get("content", "")
        for f in parse_findings_json(result["final_text"]):
            self.ledger.add(f)
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
    for f in sorted(agent.ledger.all(), key=lambda x: sev.get(x.severity, 5)):
        color = SEV_COLOR.get(f.severity, CYAN)
        st = STATUS_COLOR.get(f.status, RESET)
        sev_tag = f"{BOLD}{color}[{f.severity.upper():<8}]{RESET}"
        status = f"{st}{f.status}{RESET}"
        print(f"{sev_tag} {f.name}  →  {status}  ({f.url or '-'})")
    plan = validation_plan(agent.ledger)
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


def _print_banner(cfg: dict):
    for line in _AIXSEC_ART.splitlines():
        print(f"{CYAN}{line.rstrip()}{RESET}")
    print(f"{MAGENTA}{'═' * 64}{RESET}")
    print(f"{BOLD}{GREEN}AIXSEC-X{RESET} — AI Web Exploitation Assistant  "
          f"{DIM}(local LLM • Kali Linux){RESET}")
    print(f"{DIM}Brand:{RESET} {CYAN}aixsecu.vn{RESET}   {DIM}Mode:{RESET} "
          f"{YELLOW}{cfg.get('auto_exec', 'ask')}{RESET}")
    print(f"{MAGENTA}{'═' * 64}{RESET}")


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
    _print_banner(cfg)
    print(f"{GREEN}[*]{RESET} Model       : {BOLD}{cfg['model']}{RESET}")
    print(f"{GREEN}[*]{RESET} Scope       : {agent.policy.describe()}")
    print(f"{GREEN}[*]{RESET} Auto-exec   : {cfg['auto_exec']}")

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
    print("\n[*] Interactive mode. Type 'q' to quit, '!! <cmd>' to run shell commands.")
    while True:
        try:
            line = input(f"\n{GREEN}{BOLD}aixsec-x>{RESET} ").strip()
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
