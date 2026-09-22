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
        # WEBX_NUM_PREDICT: cap số token sinh ra (opt-in; "0" = không giới hạn)
        "num_predict": int(os.environ.get("WEBX_NUM_PREDICT", "0") or "0"),

        # ── Agent loop ──
        # 8 vòng mặc định: cân bằng độ sâu khai thác vs thời gian/chi phí LLM
        # (12 vòng trên máy 4 vCPU có thể chạy 20-30 phút/vòng model 9B).
        "max_rounds": int(os.environ.get("WEBX_MAX_ROUNDS", "8")),
        "tool_timeout": int(os.environ.get("WEBX_TOOL_TIMEOUT", "90")),
        #   WEBX_LLM_TIMEOUT: giây tối đa chờ model trả lời MỖI lượt gọi Ollama
        #   (mặc định 300s — model 9B trên CPU có thể mất 1-3 phút/lượt)
        "llm_timeout": int(os.environ.get("WEBX_LLM_TIMEOUT", "300")),
        # Phase 4.1 separates an unresponsive model from a slow completion.
        "llm_first_token_timeout": int(os.environ.get("WEBX_LLM_FIRST_TOKEN_TIMEOUT", "30")),
        "llm_completion_timeout": int(os.environ.get("WEBX_LLM_COMPLETION_TIMEOUT", "180")),
        "llm_overall_timeout": int(os.environ.get("WEBX_LLM_OVERALL_TIMEOUT", "210")),
        "output_cap": int(os.environ.get("WEBX_OUTPUT_CAP", "5000")),
        "context_optimization": os.environ.get("WEBX_CONTEXT_OPTIMIZATION", "1") == "1",
        "max_prompt_tokens": int(os.environ.get("WEBX_MAX_PROMPT_TOKENS", "12000")),
        "reserved_completion_tokens": int(os.environ.get(
            "WEBX_RESERVED_COMPLETION_TOKENS", "2048")),
        "context_max_graph_nodes": int(os.environ.get("WEBX_CONTEXT_MAX_GRAPH_NODES", "40")),
        "context_max_observations": int(os.environ.get("WEBX_CONTEXT_MAX_OBSERVATIONS", "12")),
        "context_max_hypotheses": int(os.environ.get("WEBX_CONTEXT_MAX_HYPOTHESES", "6")),
        "context_max_history": int(os.environ.get("WEBX_CONTEXT_MAX_HISTORY", "12")),
        "context_max_evidence": int(os.environ.get("WEBX_CONTEXT_MAX_EVIDENCE", "8")),
        "context_max_tools": int(os.environ.get("WEBX_CONTEXT_MAX_TOOLS", "14")),
        #   WEBX_NUM_PREDICT: cap cứng số token model sinh mỗi lượt (v1.4.2).
        #   0 = không giới hạn (mặc định). Đặt 512-2048 nếu model viết essay dài
        #   làm chậm từng round — rủi ro: final JSON bị cắt cụt nếu đặt quá thấp.
        "auto_exec": os.environ.get("WEBX_AUTO_EXEC", "ask").lower(),
        #   ask | safe | all
        #   ask  → hỏi operator trước hành động noisy/destructive
        #   safe → chỉ chạy tool an toàn tự động (httpx, dns, headers)
        #   all  → tự chạy mọi tool model yêu cầu (KHÔNG khuyến nghị)
        # v1.5.6: AI-NATIVE mode — model TỰ phân tích lỗ hổng bằng http_request
        # (không bắt buộc wapiti/sqlmap). Bật: WEBX_AI_NATIVE=1. Kết hợp
        # WEBX_AUTO_EXEC=all để hoàn toàn hands-free (không hỏi approval).
        "ai_native": os.environ.get("WEBX_AI_NATIVE", "0") == "1",

        # Phase 4 autonomous runtime is opt-in. It reuses the same scope and
        # approval boundary as interactive dispatch and checkpoints atomically.
        "autonomy_enabled": os.environ.get("WEBX_AUTONOMY", "0") == "1",
        "autonomy_checkpoint": os.environ.get("WEBX_AUTONOMY_CHECKPOINT", "").strip(),
        "autonomy_resume": os.environ.get("WEBX_AUTONOMY_RESUME", "0") == "1",
        "autonomy_max_actions": int(os.environ.get("WEBX_AUTONOMY_MAX_ACTIONS", "100")),
        "autonomy_max_requests": int(os.environ.get("WEBX_AUTONOMY_MAX_REQUESTS", "500")),
        "autonomy_max_seconds": float(os.environ.get("WEBX_AUTONOMY_MAX_SECONDS", "3600")),
        "autonomy_max_risk": float(os.environ.get("WEBX_AUTONOMY_MAX_RISK", "20")),

        # ── Scope (bắt buộc — comma separated) ──
        "targets": [t.strip() for t in os.environ.get("WEBX_TARGETS", "").split(",") if t.strip()],

        # ── Source scan roots cho sast_scan (comma separated) ──
        "src_dirs": [d.strip() for d in os.environ.get("WEBX_SRC_DIRS", "").split(",") if d.strip()],

        # ── Attack Surface Inventory (v1.6.0) ──
        #   WEBX_INVENTORY_FILE: nếu set → agent TỰ lưu inventory JSON
        #   (host→port→service→URL→endpoint→method→param→auth→tech, tích lũy từ
        #   tool output OK thật) sau mỗi vòng và khi thoát. Bỏ trống = không lưu.
        "inventory_file": os.environ.get("WEBX_INVENTORY_FILE", ""),

        # ── HTTP Proxy (v1.8.0 — HTTP Session Engine) ──
        #   WEBX_HTTP_PROXY / WEBX_HTTPS_PROXY: proxy cho http_request
        #   (Session Engine) khi cần đi qua MITM proxy (Burp/ZAP) hoặc egress.
        #   Định dạng vd "http://127.0.0.1:8080". Bỏ trống = kết nối thẳng.
        "http_proxy": os.environ.get("WEBX_HTTP_PROXY", "").strip(),
        "https_proxy": os.environ.get("WEBX_HTTPS_PROXY", "").strip(),

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
        "stream": os.environ.get("WEBX_STREAM", "1") == "1",
        #   WEBX_STREAM=1 → stream NDJSON từ Ollama về, agent hiển thị live
        #   reasoning + nội dung đang sinh lên màn hình. Đặt 0 để tắt (chờ
        #   nguyên response, không có hiển thị live).
        "prompt_style": os.environ.get("WEBX_PROMPT_STYLE", "auto").lower(),
        #   auto | compact | full
        #   auto    → heuristic theo model: ≤9B dùng compact, ≥14B dùng full
        #   compact → prompt ngắn, ít luật (model nhỏ tuân theo tốt hơn)
        #   full    → prompt chi tiết (model lớn)
    }
