#!/usr/bin/env python3
"""
aixsec-x — config.py
Đọc toàn bộ cấu hình từ biến môi trường (KHÔNG hardcode credential).
"""
import os


def load_config() -> dict:
    return {
        # ── Ollama ──
        #   WEBX_OLLAMA_URL: local (http://localhost:11434) HOẶC máy khác
        #   (http://<IP-may-model>:11434, tunnel SSH/Cloudflare…)
        "ollama_url": os.environ.get("WEBX_OLLAMA_URL", "http://localhost:11434"),
        #   WEBX_OLLAMA_AUTH: header Authorization tùy chọn (vd "Bearer <token>"
        #   hoặc "Basic ...") cho endpoint remote có xác thực
        "ollama_auth": os.environ.get("WEBX_OLLAMA_AUTH", ""),
        "model": os.environ.get("WEBX_MODEL", "qwen2.5:7b"),
        "num_ctx": int(os.environ.get("WEBX_NUM_CTX", "16384")),

        # ── Agent loop ──
        "max_rounds": int(os.environ.get("WEBX_MAX_ROUNDS", "12")),
        "tool_timeout": int(os.environ.get("WEBX_TOOL_TIMEOUT", "90")),
        "output_cap": int(os.environ.get("WEBX_OUTPUT_CAP", "5000")),
        "auto_exec": os.environ.get("WEBX_AUTO_EXEC", "ask").lower(),
        #   ask | safe | all
        #   ask  → hỏi operator trước hành động noisy/destructive
        #   safe → chỉ chạy tool an toàn tự động (httpx, dns, headers)
        #   all  → tự chạy mọi tool model yêu cầu (KHÔNG khuyến nghị)

        # ── Scope (bắt buộc — comma separated) ──
        "targets": [t.strip() for t in os.environ.get("WEBX_TARGETS", "").split(",") if t.strip()],

        # ── Source scan roots cho sast_scan (comma separated) ──
        "src_dirs": [d.strip() for d in os.environ.get("WEBX_SRC_DIRS", "").split(",") if d.strip()],

        # ── DB (bỏ trống = không lưu) ──
        "db": {
            "enabled": os.environ.get("WEBX_DB_ENABLED", "0") == "1",
            "host": os.environ.get("WEBX_DB_HOST", "localhost"),
            "user": os.environ.get("WEBX_DB_USER", ""),
            "pass": os.environ.get("WEBX_DB_PASS", ""),
            "name": os.environ.get("WEBX_DB_NAME", "webx"),
        },

        # ── Orality / quality ──
        "temperature": float(os.environ.get("WEBX_TEMPERATURE", "0.1")),
        "think": os.environ.get("WEBX_THINK", "0") == "1",
        #   WEBX_THINK=1 → bật thinking mode (không khuyến nghị khi dùng function calling)
        "prompt_style": os.environ.get("WEBX_PROMPT_STYLE", "auto").lower(),
        #   auto | compact | full
        #   auto    → heuristic theo model: ≤9B dùng compact, ≥14B dùng full
        #   compact → prompt ngắn, ít luật (model nhỏ tuân theo tốt hơn)
        #   full    → prompt chi tiết (model lớn)
    }
