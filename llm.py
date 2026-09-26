#!/usr/bin/env python3
"""
aixsec-x — llm.py
Ollama adapter: function calling (structured tool calls) + injection guard
cho output không tin cậy.
"""
from __future__ import annotations

import json
import re
import time

import requests
from urllib3.exceptions import ReadTimeoutError

_MARKER_RE = re.compile(r"\[(?:TOOL|SEARCH|EXEC):\s*.+?\]")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _set_stream_timeout(response, seconds: int) -> None:
    """Switch urllib3's socket timeout after the first streamed token.

    Requests exposes only connect/read timeout at request creation. Ollama's
    first-token and completion phases need different read deadlines, so this
    best-effort adapter updates the live socket. The monotonic overall checks
    remain authoritative when a response is actively streaming.
    """
    try:
        response.raw._fp.fp.raw._sock.settimeout(seconds)
    except (AttributeError, OSError):
        pass


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


def _parse_tool_calls(msg: dict) -> list:
    """Chuẩn hóa tool_calls từ Ollama (arguments có thể là JSON string).

    Trả list {"name", "arguments"} — arguments luôn là dict.
    """
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
    return calls


def _conn_error(cfg: dict) -> dict:
    base = str(cfg["ollama_url"]).rstrip("/")
    return {"content": ("[!] Cannot reach Ollama at " + base + ".\n"
                         "    • Is 'ollama serve' running on the server?\n"
                         "    • Remote? Set OLLAMA_HOST=0.0.0.0 on the server.\n"
                         "    • Is port 11434/tcp open in the server firewall?\n"
                         "    • Diagnose: python3 agent.py --check-ollama"),
            "tool_calls": []}


def ollama_chat(messages: list, tools: list | None = None, config: dict | None = None,
                json_mode: bool = False, on_token=None, on_reasoning=None) -> dict:
    """Gọi Ollama /api/chat. Trả {"content", "tool_calls":[{name,arguments}]}.

    stream=True (mặc định qua WEBX_STREAM): đọc NDJSON từng dòng, gọi
    on_reasoning(chunk) / on_token(chunk) live để agent hiển thị lên màn hình.
    Nếu đứt kết nối giữa chừng, trả thông báo thân thiện (không raise).
    """
    from config import load_config
    cfg = config or load_config()
    stream = bool(cfg.get("stream", False))
    payload = {
        "model": cfg["model"],
        "messages": messages,
        "stream": stream,
        "think": cfg.get("think", False),
    }
    opts = {"temperature": cfg["temperature"], "num_ctx": cfg["num_ctx"]}
    np_cap = int(cfg.get("num_predict") or 0)
    if np_cap > 0:  # v1.4.2: cap output opt-in qua WEBX_NUM_PREDICT (0 = unlimited)
        opts["num_predict"] = np_cap
    payload["options"] = opts
    if tools:
        payload["tools"] = tools
    if json_mode:
        payload["format"] = "json"
    started = time.monotonic()
    legacy = int(cfg.get("llm_timeout") or (int(cfg["tool_timeout"]) * 4 + 30))
    first_timeout = max(1, int(cfg.get("llm_first_token_timeout") or min(90, legacy)))
    completion_timeout = max(1, int(cfg.get("llm_completion_timeout") or legacy))
    overall_timeout = max(first_timeout, int(cfg.get("llm_overall_timeout") or legacy))
    try:
        request_timeout = (min(10, first_timeout), first_timeout) if stream \
            else (min(10, overall_timeout), overall_timeout)
        r = requests.post(cfg["ollama_url"] + "/api/chat", json=payload,
                          headers=ollama_headers(cfg),
                          timeout=request_timeout, stream=stream)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        return _conn_error(cfg)
    except requests.exceptions.Timeout:
        return {"content": "[!] Ollama first-token timeout — model did not start responding.",
                "tool_calls": [], "metrics": {"timeout_phase": "first_token",
                    "llm_latency_ms": round((time.monotonic() - started) * 1000, 3),
                    "first_token_latency_ms": round(
                        (time.monotonic() - started) * 1000, 3)}}
    except Exception as e:
        return {"content": f"[!] Ollama error: {e}", "tool_calls": []}

    if not stream:
        msg = r.json().get("message", {})
        return {"content": (msg.get("content") or "").strip(),
                "tool_calls": _parse_tool_calls(msg),
                "metrics": {"llm_latency_ms": round(
                    (time.monotonic() - started) * 1000, 3),
                    "completion_latency_ms": round(
                    (time.monotonic() - started) * 1000, 3)}}

    # ── streaming NDJSON ──
    parts: list[str] = []
    raw_calls: list[dict] = []
    first_token_at = None
    try:
        for line in r.iter_lines(decode_unicode=True):
            now = time.monotonic()
            if now - started > overall_timeout:
                return {"content": "[!] Ollama overall timeout.", "tool_calls": [],
                        "metrics": {"llm_latency_ms": round((now - started) * 1000, 3)}}
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            msg = obj.get("message") or {}
            # Ollama exposes thinking tokens as message.thinking.  Keep the
            # older message.reasoning alias for compatible proxies/adapters.
            thinking = msg.get("thinking") or msg.get("reasoning")
            if first_token_at is None and (msg.get("content") or thinking
                                           or msg.get("tool_calls") or obj.get("done")):
                first_token_at = now
                _set_stream_timeout(r, min(completion_timeout, overall_timeout))
            if first_token_at is not None and now - first_token_at > completion_timeout:
                return {"content": "[!] Ollama completion timeout.", "tool_calls": [],
                        "metrics": {"first_token_latency_ms": round(
                            (first_token_at - started) * 1000, 3),
                            "completion_latency_ms": round((now - first_token_at) * 1000, 3)}}
            tok = msg.get("content")
            if tok:
                parts.append(tok)
                if on_token is not None:
                    on_token(tok)
            if thinking:
                if on_reasoning is not None:
                    on_reasoning(thinking)
            for tc in msg.get("tool_calls") or []:
                raw_calls.append(tc)
            if obj.get("done"):
                break
    except requests.exceptions.ConnectionError as exc:
        # Requests wraps urllib3 read timeouts in ConnectionError while streaming.
        if isinstance(exc.__context__, ReadTimeoutError) or any(
                isinstance(arg, ReadTimeoutError) for arg in exc.args):
            label = "first-token" if first_token_at is None else "completion"
            return {"content": f"[!] Ollama {label} timeout.", "tool_calls": [],
                    "metrics": {"timeout_phase": label.replace("-", "_"),
                                "llm_latency_ms": round((time.monotonic() - started) * 1000, 3)}}
        return _conn_error(cfg)
    except requests.exceptions.Timeout:
        label = "first-token" if first_token_at is None else "completion"
        return {"content": f"[!] Ollama {label} timeout.", "tool_calls": [],
                "metrics": {"timeout_phase": label.replace("-", "_"),
                    "llm_latency_ms": round((time.monotonic() - started) * 1000, 3)}}
    except Exception as e:
        return {"content": f"[!] Ollama error: {e}", "tool_calls": []}
    finally:
        r.close()
    finished = time.monotonic()
    return {"content": "".join(parts).strip(),
            "tool_calls": _parse_tool_calls({"tool_calls": raw_calls}),
            "metrics": {"llm_latency_ms": round((finished - started) * 1000, 3),
                        "first_token_latency_ms": round(
                            ((first_token_at or finished) - started) * 1000, 3),
                        "completion_latency_ms": round(
                            (finished - (first_token_at or started)) * 1000, 3)}}


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
        return ("[✗] CANNOT reach Ollama at {0}\n"
                "    • Is 'ollama serve' running on the server?\n"
                "    • Remote: set OLLAMA_HOST=0.0.0.0 on the server "
                "(Ollama only listens on localhost by default).\n"
                "    • Is port 11434/tcp open in the server firewall?  (ufw allow 11434/tcp)\n"
                "    • Test manually:  curl {0}/api/version".format(base))
    except Exception as e:  # noqa: BLE001
        return "[✗] Error calling {0}: {1}".format(base, e)

    outs = ["[✓] Ollama server: {0}  (version {1})".format(base, ver)]
    try:
        r = requests.get(base + "/api/tags", timeout=10, headers=h)
        r.raise_for_status()
        names = [m.get("name", "") for m in (r.json() or {}).get("models", [])]
    except Exception as e:  # noqa: BLE001
        outs.append("[!] Could not list models (/api/tags): {0}".format(e))
        names = []
    if names:
        outs.append("[i] Models on server ({0}): {1}".format(len(names), ", ".join(names[:15])))
    else:
        outs.append("[i] Server has no models yet — pull ON THE SERVER, not the client.")
    want = str(cfg.get("model") or "")
    if names and want in names:
        outs.append("[✓] WEBX_MODEL='{0}' found on server — ready to use.".format(want))
    elif names:
        outs.append("[✗] WEBX_MODEL='{0}' NOT found on server.\n"
                    "    Run ON THE SERVER:  ollama pull {0}".format(want))
    return "\n".join(outs)
