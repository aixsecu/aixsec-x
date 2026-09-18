#!/usr/bin/env python3
"""
aixsec-x — llm.py
Ollama adapter: function calling (structured tool calls) + injection guard
cho output không tin cậy.
"""
from __future__ import annotations

import json
import re

import requests

_MARKER_RE = re.compile(r"\[(?:TOOL|SEARCH|EXEC):\s*.+?\]")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def ollama_headers(cfg: dict) -> dict:
    """Header cho mọi request tới Ollama.

    WEBX_OLLAMA_AUTH có thể ghi đầy đủ ("Bearer xyz", "Basic abc") hoặc
    chỉ token ("xyz") — tự thêm tiền tố Bearer. Endpoint công khai/tunnel
    nên bật xác thực ở reverse proxy để tránh lộ LLM.
    """
    h = {}
    auth = str(cfg.get("ollama_auth") or "").strip()
    if auth:
        h["Authorization"] = auth if auth.lower().startswith(("bearer ", "basic ")) \
            else "Bearer " + auth
    return h


class InjectionGuard:
    """Strip tool-call markers / ANSI / control chars khỏi output tool
    (target thù địch có thể chèn prompt injection vào body response)."""

    @staticmethod
    def sanitize(raw: str, cap: int = 5000) -> str:
        if not raw:
            return "(no output)"
        text = _MARKER_RE.sub("[MARKER-STRIPPED]", raw)
        text = _ANSI_RE.sub("", text)
        text = _CTRL_RE.sub("", text)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        if len(text) > cap:
            text = text[:cap] + f"\n... [truncated at {cap} chars]"
        return "<untrusted tool output>\n" + text + "\n</untrusted tool output>"


def ollama_chat(messages: list, tools: list | None = None, config: dict | None = None,
                json_mode: bool = False) -> dict:
    """Gọi Ollama /api/chat. Trả {"content", "tool_calls":[{name,arguments}]}."""
    from config import load_config
    cfg = config or load_config()
    payload = {
        "model": cfg["model"],
        "messages": messages,
        "stream": False,
        "think": cfg.get("think", False),
        "options": {"temperature": cfg["temperature"], "num_ctx": cfg["num_ctx"]},
    }
    if tools:
        payload["tools"] = tools
    if json_mode:
        payload["format"] = "json"
    try:
        r = requests.post(cfg["ollama_url"] + "/api/chat", json=payload,
                          headers=ollama_headers(cfg),
                          timeout=int(cfg["tool_timeout"]) * 4 + 30)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        base = str(cfg["ollama_url"]).rstrip("/")
        return {"content": ("[!] Không kết nối được Ollama tại " + base + ".\n"
                             "    • Máy chủ đã chạy 'ollama serve' chưa?\n"
                             "    • Remote? Phải set OLLAMA_HOST=0.0.0.0 trên máy chủ.\n"
                             "    • Firewall máy chủ mở 11434/tcp chưa?\n"
                             "    • Chẩn đoán: python3 agent.py --check-ollama"),
                "tool_calls": []}
    except requests.exceptions.Timeout:
        return {"content": "[!] Ollama timeout — model đang load hoặc quá lớn.", "tool_calls": []}
    except Exception as e:
        return {"content": f"[!] Lỗi Ollama: {e}", "tool_calls": []}

    msg = r.json().get("message", {})
    calls = []
    for tc in msg.get("tool_calls", []) or []:
        fn = tc.get("function", {})
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {"_raw": args}
        calls.append({"name": fn.get("name", ""), "arguments": args or {}})
    return {"content": (msg.get("content") or "").strip(), "tool_calls": calls}


def check_ollama(config: dict | None = None) -> str:
    """Chẩn đoán nhanh: kết nối, version server, model có sẵn, WEBX_MODEL khớp chưa.

    Chạy:  python3 agent.py --check-ollama
    Giúp bắt nhanh 3 lỗi thường gặp khi dùng Ollama REMOTE:
      - máy chủ chưa bind 0.0.0.0 (OLLAMA_HOST) → kết nối bị từ chối
      - firewall chặn 11434/tcp → timeout/refused
      - model chưa pull trên MÁY CHỦ → 404 model not found
    """
    from config import load_config
    cfg = config or load_config()
    base = str(cfg["ollama_url"]).rstrip("/")
    h = ollama_headers(cfg)
    try:
        r = requests.get(base + "/api/version", timeout=10, headers=h)
        r.raise_for_status()
        ver = (r.json() or {}).get("version", "?")
    except (requests.exceptions.ConnectionError, ConnectionError):
        return ("[✗] KHÔNG kết nối được Ollama tại {0}\n"
                "    • Máy chủ đã chạy 'ollama serve' chưa?\n"
                "    • Remote: phải set OLLAMA_HOST=0.0.0.0 trên máy chủ "
                "(mặc định Ollama chỉ nghe localhost).\n"
                "    • Firewall máy chủ mở 11434/tcp chưa?  (ufw allow 11434/tcp)\n"
                "    • Thử tay:  curl {0}/api/version".format(base))
    except Exception as e:  # noqa: BLE001
        return "[✗] Lỗi khi gọi {0}: {1}".format(base, e)

    outs = ["[✓] Ollama server: {0}  (version {1})".format(base, ver)]
    try:
        r = requests.get(base + "/api/tags", timeout=10, headers=h)
        r.raise_for_status()
        names = [m.get("name", "") for m in (r.json() or {}).get("models", [])]
    except Exception as e:  # noqa: BLE001
        outs.append("[!] Không lấy được danh sách model (/api/tags): {0}".format(e))
        names = []
    if names:
        outs.append("[i] Model trên server ({0}): {1}".format(len(names), ", ".join(names[:15])))
    else:
        outs.append("[i] Server chưa có model nào — pull trên MÁY CHỦ, không phải máy client.")
    want = str(cfg.get("model") or "")
    if names and want in names:
        outs.append("[✓] WEBX_MODEL='{0}' CÓ trên server — sẵn sàng dùng.".format(want))
    elif names:
        outs.append("[✗] WEBX_MODEL='{0}' KHÔNG có trên server.\n"
                    "    Chạy trên MÁY CHỦ:  ollama pull {0}".format(want))
    return "\n".join(outs)
