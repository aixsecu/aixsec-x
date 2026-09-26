"""Phase 2 auth contexts, login lifecycle and differential observations.

This module deliberately records facts, not authorization-vulnerability verdicts.
Every context owns an isolated requests.Session per origin. Configuration values
may use ``env:NAME`` so credentials do not need to appear in tool arguments.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import http_engine as he
import requests

MAX_CONTEXTS = 16
MAX_STEPS = 12
MAX_COMPARE_CONTEXTS = 8
MAX_RESPONSE_BYTES = 2_000_000
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_VAR = re.compile(r"\{\{([A-Za-z][A-Za-z0-9_.-]{0,63})\}\}")
_ENV = re.compile(r"\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}")


def _origin(url: str) -> str:
    p = urlsplit(str(url or ""))
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("auth context URL must be HTTP(S) without credentials")
    host = p.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = p.port or (443 if p.scheme == "https" else 80)
    default = 443 if p.scheme == "https" else 80
    return f"{p.scheme.lower()}://{host}" + (f":{port}" if port != default else "")


def _resolve_secret(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("env:"):
        name = value[4:]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("invalid environment variable reference")
        if name not in os.environ:
            raise ValueError(f"environment variable {name} is not set")
        return os.environ[name]
    if isinstance(value, str):
        def replace(match):
            name = match.group(1)
            if name not in os.environ:
                raise ValueError(f"environment variable {name} is not set")
            return os.environ[name]
        return _ENV.sub(replace, value)
    if isinstance(value, dict):
        return {str(k): _resolve_secret(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_secret(v) for v in value]
    return value


def _substitute(value: Any, variables: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _VAR.sub(lambda m: variables.get(m.group(1), m.group(0)), value)
    if isinstance(value, dict):
        return {str(k): _substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, variables) for v in value]
    return value


def _json_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split(".") if path else []:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise ValueError(f"JSON path not found: {path}")
    return current


def _safe_url(url: str, sensitive: tuple[str, ...] = ()) -> str:
    p = urlsplit(url)
    query = []
    red = he.EvidenceRedactor()
    for key, value in parse_qsl(p.query, keep_blank_values=True):
        query.append((key, "<redacted>" if red._is_sensitive(key, sensitive) else value))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), ""))


def _shape(value: Any, depth: int = 0) -> Any:
    if depth >= 12:
        return {"type": "truncated"}
    if isinstance(value, dict):
        return {str(k): _shape(v, depth + 1) for k, v in sorted(value.items())[:200]}
    if isinstance(value, list):
        shapes = []
        for item in value[:20]:
            candidate = _shape(item, depth + 1)
            if candidate not in shapes:
                shapes.append(candidate)
        return shapes
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return "string"


def _response_facts(response, record, sensitive: tuple[str, ...] = ()) -> dict:
    content_type = next((str(v).split(";", 1)[0].strip().lower()
                         for k, v in response.headers.items()
                         if str(k).lower() == "content-type"), "")
    body = response.content[:MAX_RESPONSE_BYTES]
    facts = {
        "status": response.status_code,
        "final_url": _safe_url(response.url, sensitive),
        "content_type": content_type,
        "length": len(response.content),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "redirects": [{"status": h["status"], "url": _safe_url(h["url"], sensitive)}
                      for h in response.history],
        "header_names": sorted(str(k).lower() for k in response.headers),
        "cookie_names": sorted(str(k) for k in response.cookies),
        "elapsed": round(response.elapsed or record.elapsed, 3),
    }
    if "json" in content_type and len(body) <= MAX_RESPONSE_BYTES:
        try:
            facts["json_shape"] = _shape(json.loads(response.text))
        except (ValueError, RecursionError):
            facts["json_parse_error"] = True
    return facts


def _evidence(record, query_names: tuple[str, ...] = (),
              header_names: tuple[str, ...] = ()) -> dict:
    """Existing engine evidence minus response content; auth observations only
    need transport facts and hashes/shapes, never returned credential payloads."""
    evidence = record.evidence_dict()
    evidence.pop("body_snippet", None)
    evidence.pop("body", None)
    for key in list(evidence.get("params") or {}):
        if key in query_names:
            evidence["params"][key] = "<redacted>"
    for field in ("url", "final_url"):
        if evidence.get(field):
            evidence[field] = _safe_url(evidence[field], query_names)
    for hop in evidence.get("history") or []:
        hop["url"] = _safe_url(hop.get("url", ""), query_names)
    lowered = {name.lower() for name in header_names}
    for field in ("request_headers", "response_headers"):
        for key in list(evidence.get(field) or {}):
            if key.lower() in lowered:
                evidence[field][key] = "<redacted>"
    return evidence


@dataclass
class AuthContext:
    name: str
    origin: str
    transport: dict = field(default_factory=dict)
    login_steps: list[dict] = field(default_factory=list)
    logout_step: dict | None = None
    state: str = "configured"
    variables: dict[str, str] = field(default_factory=dict, repr=False)
    last_login_at: float | None = None
    last_error: str = ""
    session: he.HttpSession | None = field(default=None, repr=False)

    def ensure_session(self) -> he.HttpSession:
        if self.session is None:
            self.session = he.HttpSession(f"auth:{self.name}:{self.origin}",
                                          proxies=he.get_proxies() or None)
        return self.session

    def public(self) -> dict:
        return {
            "name": self.name, "origin": self.origin, "state": self.state,
            "transport": {
                "auth_kind": (he.parse_auth(self.transport.get("auth")) or {}).get("kind"),
                "header_names": sorted((self.transport.get("headers") or {}).keys()),
                "cookie_names": sorted((self.transport.get("cookies") or {}).keys()),
                "query_names": sorted((self.transport.get("params") or {}).keys()),
            },
            "login_steps": len(self.login_steps),
            "has_logout": self.logout_step is not None,
            "last_login_at": round(self.last_login_at, 2) if self.last_login_at else None,
            "last_error": self.last_error,
        }

    def sensitive_query_names(self) -> tuple[str, ...]:
        names = []
        parsed = he.parse_auth(str(self.transport.get("auth") or ""))
        if parsed and parsed.get("kind") == "apiquery":
            names.append(str(parsed.get("name") or ""))
        for key, value in (self.transport.get("params") or {}).items():
            raw = str(value)
            if raw.startswith("env:") or "${ENV:" in raw or "{{" in raw:
                names.append(str(key))
        return tuple(name for name in names if name)

    def sensitive_header_names(self) -> tuple[str, ...]:
        names = []
        parsed = he.parse_auth(str(self.transport.get("auth") or ""))
        if parsed and parsed.get("kind") == "api_key":
            names.append(str(parsed.get("name") or ""))
        for key, value in (self.transport.get("headers") or {}).items():
            raw = str(value)
            if raw.startswith("env:") or "${ENV:" in raw or "{{" in raw:
                names.append(str(key))
        return tuple(name for name in names if name)

    def evidence(self, record) -> dict:
        return _evidence(record, self.sensitive_query_names(),
                         self.sensitive_header_names())

    def _request(self, spec: dict, *, record: bool = False):
        spec = _substitute(_resolve_secret(copy.deepcopy(spec)), self.variables)
        url = str(spec.get("url") or "")
        if _origin(url) != self.origin:
            raise ValueError("auth context request cannot leave its configured origin")
        transport = _substitute(_resolve_secret(copy.deepcopy(self.transport)), self.variables)
        headers = dict(transport.get("headers") or {})
        headers.update(spec.get("headers") or {})
        params = dict(transport.get("params") or {})
        params.update(spec.get("params") or {})
        cookies = dict(transport.get("cookies") or {})
        cookies.update(spec.get("cookies") or {})
        follow = bool(spec.get("follow_redirects", True))
        method = str(spec.get("method") or "GET").upper()
        request_kwargs = {
            "headers": headers, "params": params, "cookies": cookies,
            "auth": transport.get("auth"), "form": spec.get("form"),
            "json_body": spec.get("json"), "body": spec.get("body"),
            "follow_redirects": False,
            "timeout": min(60., max(.1, float(spec.get("timeout", 15)))),
            "record": record, "max_response_bytes": MAX_RESPONSE_BYTES,
        }
        history = []
        try:
            for hop in range(11):
                response, request_record = self.ensure_session().request(
                    method, url, **request_kwargs)
                location = next((str(v) for k, v in response.headers.items()
                                 if str(k).lower() == "location"), "")
                if not follow or response.status_code not in (301, 302, 303, 307, 308) \
                        or not location:
                    response.history = history
                    request_record.response = response
                    return response, request_record
                if hop == 10:
                    raise ValueError("too many redirects")
                destination = urljoin(response.url, location)
                if _origin(destination) != self.origin:
                    raise ValueError("auth context redirect cannot leave its configured origin")
                history.append({"url": response.url, "status": response.status_code,
                                "headers": he.redact_headers(response.headers)})
                if response.status_code == 303 or (response.status_code in (301, 302)
                                                    and method == "POST"):
                    method = "GET"
                    request_kwargs["form"] = None
                    request_kwargs["json_body"] = None
                    request_kwargs["body"] = None
                url = destination
                request_kwargs["params"] = {}
            raise ValueError("too many redirects")
        except requests.RequestException as exc:
            raise ValueError(f"HTTP request failed: {type(exc).__name__}") from None

    def login(self) -> dict:
        if not self.login_steps:
            self.state = "anonymous" if self.name == "anonymous" else "ready"
            return {"context": self.name, "state": self.state, "steps": []}
        self.session = None
        self.variables = {}
        observations = []
        try:
            for index, step in enumerate(self.login_steps):
                response, record = self._request(step)
                expected = step.get("expected_status", list(range(200, 400)))
                expected = [expected] if isinstance(expected, int) else expected
                if not isinstance(expected, list) or not all(isinstance(x, int) for x in expected):
                    raise ValueError("expected_status must be an integer or list of integers")
                if response.status_code not in expected:
                    raise ValueError(f"login step {index + 1} returned {response.status_code}")
                extracted = []
                for name, rule in (step.get("extract") or {}).items():
                    if not _NAME.fullmatch(str(name)) or not isinstance(rule, dict):
                        raise ValueError("invalid login extractor")
                    source = rule.get("from")
                    if source == "cookie":
                        value = self.ensure_session().s.cookies.get(str(rule.get("name") or name))
                    elif source == "header":
                        value = next((v for k, v in response.headers.items()
                                      if str(k).lower() == str(rule.get("name") or name).lower()), None)
                    elif source == "json":
                        value = _json_path(json.loads(response.text), str(rule.get("path") or name))
                    elif source == "body_regex":
                        pattern = str(rule.get("pattern") or "")
                        if len(pattern) > 500:
                            raise ValueError("extractor regex is too long")
                        match = re.search(pattern, response.text[:MAX_RESPONSE_BYTES])
                        value = match.group(int(rule.get("group", 1))) if match else None
                    else:
                        raise ValueError("extractor source must be cookie/header/json/body_regex")
                    if value is None or isinstance(value, (dict, list)):
                        raise ValueError(f"login extractor {name} produced no scalar value")
                    self.variables[str(name)] = str(value)
                    extracted.append(str(name))
                observations.append({"step": index + 1, "status": response.status_code,
                                     "final_url": _safe_url(response.url, self.sensitive_query_names()),
                                     "extracted_names": extracted,
                                     "evidence": self.evidence(record)})
            self.state, self.last_error, self.last_login_at = "authenticated", "", time.time()
            return {"context": self.name, "state": self.state, "steps": observations}
        except Exception as exc:
            message = str(exc) if isinstance(exc, (ValueError, TypeError)) else type(exc).__name__
            self.state, self.last_error = "login_failed", message
            self.session = None
            self.variables = {}
            raise ValueError(message) from None

    def logout(self) -> dict:
        observation = None
        remote_error = ""
        try:
            if self.logout_step and self.session is not None:
                response, record = self._request(self.logout_step)
                observation = {"status": response.status_code,
                               "final_url": _safe_url(response.url, self.sensitive_query_names()),
                               "evidence": self.evidence(record)}
        except (ValueError, TypeError) as exc:
            remote_error = str(exc)
        finally:
            self.session = None
            self.variables = {}
            self.state = "logged_out"
        return {"context": self.name, "state": self.state,
                "observation": observation, "remote_error": remote_error}


class AuthContextManager:
    def __init__(self):
        self._contexts: dict[str, AuthContext] = {}
        self._lock = threading.RLock()

    def configure(self, name: str, origin: str, *, transport=None,
                  login_steps=None, logout_step=None, replace=False) -> dict:
        if not _NAME.fullmatch(str(name or "")):
            raise ValueError("invalid auth context name")
        normalized = _origin(origin)
        steps = copy.deepcopy(login_steps or [])
        if not isinstance(steps, list) or len(steps) > MAX_STEPS:
            raise ValueError(f"login_steps must contain at most {MAX_STEPS} steps")
        if not all(isinstance(step, dict) for step in steps):
            raise ValueError("every login step must be an object")
        if transport is not None and not isinstance(transport, dict):
            raise ValueError("transport must be an object")
        if logout_step is not None and not isinstance(logout_step, dict):
            raise ValueError("logout_step must be an object")
        with self._lock:
            if name in self._contexts and not replace:
                raise ValueError(f"auth context {name} already exists")
            if name not in self._contexts and len(self._contexts) >= MAX_CONTEXTS:
                raise ValueError("too many auth contexts")
            context = AuthContext(str(name), normalized, copy.deepcopy(transport or {}),
                                  steps, copy.deepcopy(logout_step))
            self._contexts[name] = context
        return context.public()

    def get(self, name: str) -> AuthContext:
        with self._lock:
            context = self._contexts.get(name)
        if context is None:
            raise ValueError(f"unknown auth context: {name}")
        return context

    def list(self) -> list[dict]:
        with self._lock:
            return [self._contexts[name].public() for name in sorted(self._contexts)]

    def remove(self, name: str) -> bool:
        with self._lock:
            context = self._contexts.pop(name, None)
        if context:
            context.session = None
        return context is not None

    def reset(self) -> int:
        with self._lock:
            count = len(self._contexts)
            self._contexts = {}
        return count

    def compare(self, names: list[str], request: dict) -> dict:
        if not isinstance(names, list) or not 2 <= len(names) <= MAX_COMPARE_CONTEXTS:
            raise ValueError(f"compare requires 2..{MAX_COMPARE_CONTEXTS} contexts")
        if len(set(names)) != len(names):
            raise ValueError("compare context names must be unique")
        contexts = [self.get(name) for name in names]
        url = str(request.get("url") or "")
        target_origin = _origin(url)
        if any(context.origin != target_origin for context in contexts):
            raise ValueError("all contexts and request must use the same origin")
        observations = []
        raw_text: dict[str, str] = {}
        for context in contexts:
            response, record = context._request(request, record=True)
            facts = _response_facts(response, record, context.sensitive_query_names())
            observations.append({"context": context.name, "state": context.state,
                                 "response": facts, "evidence": context.evidence(record)})
            raw_text[context.name] = response.text[:200_000]
        comparisons = []
        for left_index, left in enumerate(observations):
            for right in observations[left_index + 1:]:
                a, b = left["response"], right["response"]
                comparisons.append({
                    "left": left["context"], "right": right["context"],
                    "same_status": a["status"] == b["status"],
                    "same_redirect_target": a["final_url"] == b["final_url"],
                    "same_content_type": a["content_type"] == b["content_type"],
                    "same_json_shape": a.get("json_shape") == b.get("json_shape"),
                    "same_body_hash": a["body_sha256"] == b["body_sha256"],
                    "length_delta": b["length"] - a["length"],
                    "body_similarity": round(SequenceMatcher(
                        None, raw_text[left["context"]], raw_text[right["context"]],
                        autojunk=True).ratio(), 4),
                })
        sensitive = tuple(sorted({name for context in contexts
                                  for name in context.sensitive_query_names()}))
        return {"url": _safe_url(url, sensitive), "method": str(request.get("method") or "GET").upper(),
                "contexts": names, "observations": observations,
                "comparisons": comparisons, "interpretation": "facts_only"}


_manager = AuthContextManager()


def manager() -> AuthContextManager:
    return _manager


def reset_contexts() -> int:
    return _manager.reset()
