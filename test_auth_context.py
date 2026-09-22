"""Phase 2 auth context, lifecycle, comparator and inventory tests."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import auth_context
from inventory import Inventory


class AuthHandler(BaseHTTPRequestHandler):
    def _json(self, status, value, headers=None):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        if self.path == "/login" and form.get("password") == ["SECRET"]:
            user = form.get("username", [""])[0]
            self._json(200, {"csrf": f"csrf-{user}", "access_token": "RETURNED-SECRET"},
                       {"Set-Cookie": f"uid={user}; Path=/; HttpOnly"})
        elif self.path == "/logout":
            self._json(204, {})
        else:
            self._json(401, {"error": "bad login"})

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        auth = self.headers.get("Authorization", "")
        if self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/private")
            self.end_headers()
        elif self.path == "/redirect-in":
            self.send_response(302)
            self.send_header("Location", "/whoami")
            self.end_headers()
        elif self.path == "/objects/2":
            if auth == "Bearer ADMIN-SECRET":
                self._json(200, {"id": 2, "owner": "B", "role": "admin"})
            elif "uid=B" in cookie and self.headers.get("X-CSRF") == "csrf-B":
                self._json(200, {"id": 2, "owner": "B"})
            elif "uid=A" in cookie:
                self._json(403, {"error": "forbidden"})
            else:
                self._json(401, {"error": "unauthorized"})
        elif self.path == "/whoami":
            self._json(200, {"cookie": cookie or "none"})
        elif self.path == "/large":
            body = b"x" * (2_000_001)
            self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        else:
            self._json(404, {"error": "missing"})

    def log_message(self, *_args):
        pass


class AuthContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), AuthHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def setUp(self):
        auth_context.reset_contexts()

    def configure_user(self, name):
        return auth_context.manager().configure(
            name, self.origin,
            transport={"headers": {"X-CSRF": "{{csrf}}"}},
            login_steps=[{
                "method": "POST", "url": self.origin + "/login",
                "form": {"username": name[-1], "password": "SECRET"},
                "expected_status": 200,
                "extract": {"csrf": {"from": "json", "path": "csrf"},
                            "token": {"from": "json", "path": "access_token"}},
            }],
            logout_step={"method": "POST", "url": self.origin + "/logout"})

    def test_four_context_differential_and_no_verdict(self):
        manager = auth_context.manager()
        manager.configure("anonymous", self.origin)
        self.configure_user("userA"); self.configure_user("userB")
        manager.configure("admin", self.origin,
                          transport={"auth": "bearer:ADMIN-SECRET"})
        manager.get("anonymous").login()
        manager.get("userA").login(); manager.get("userB").login()
        result = manager.compare(
            ["anonymous", "userA", "userB", "admin"],
            {"method": "GET", "url": self.origin + "/objects/2"})
        self.assertEqual([o["response"]["status"] for o in result["observations"]],
                         [401, 403, 200, 200])
        self.assertEqual(result["interpretation"], "facts_only")
        encoded = json.dumps(result)
        self.assertNotIn("SECRET", encoded)
        self.assertNotIn("RETURNED-SECRET", encoded)
        self.assertNotIn("IDOR", encoded)
        self.assertEqual(len(result["comparisons"]), 6)

    def test_cookie_jars_are_isolated(self):
        self.configure_user("userA"); self.configure_user("userB")
        auth_context.manager().get("userA").login()
        auth_context.manager().get("userB").login()
        result = auth_context.manager().compare(
            ["userA", "userB"], {"url": self.origin + "/whoami"})
        self.assertFalse(result["comparisons"][0]["same_body_hash"])

    def test_login_failure_discards_session_and_variables(self):
        auth_context.manager().configure("bad", self.origin, login_steps=[{
            "method": "POST", "url": self.origin + "/login",
            "form": {"username": "A", "password": "wrong"},
            "expected_status": 200}])
        context = auth_context.manager().get("bad")
        with self.assertRaisesRegex(ValueError, "returned 401"):
            context.login()
        self.assertEqual(context.state, "login_failed")
        self.assertIsNone(context.session)
        self.assertEqual(context.variables, {})

    def test_logout_clears_state(self):
        self.configure_user("userA")
        context = auth_context.manager().get("userA")
        context.login()
        result = context.logout()
        self.assertEqual(result["state"], "logged_out")
        self.assertIsNone(context.session)
        self.assertEqual(context.variables, {})

    def test_environment_secret_reference(self):
        os.environ["AIXSEC_TEST_TOKEN"] = "ADMIN-SECRET"
        try:
            auth_context.manager().configure(
                "admin", self.origin,
                transport={"auth": "bearer:${ENV:AIXSEC_TEST_TOKEN}"})
            public = auth_context.manager().get("admin").public()
            self.assertNotIn("ADMIN-SECRET", json.dumps(public))
            auth_context.manager().configure(
                "queryA", self.origin,
                transport={"auth": "apiquery:custom:${ENV:AIXSEC_TEST_TOKEN}"})
            auth_context.manager().configure(
                "queryB", self.origin,
                transport={"params": {"custom": "${ENV:AIXSEC_TEST_TOKEN}"}})
            result = auth_context.manager().compare(
                ["queryA", "queryB"], {"url": self.origin + "/whoami"})
            self.assertNotIn("ADMIN-SECRET", json.dumps(result))
            self.assertIn("%3Credacted%3E", result["observations"][0]["response"]["final_url"])
        finally:
            os.environ.pop("AIXSEC_TEST_TOKEN", None)

    def test_origin_and_context_limits(self):
        auth_context.manager().configure("a", self.origin)
        auth_context.manager().configure("b", self.origin)
        with self.assertRaisesRegex(ValueError, "same origin"):
            auth_context.manager().compare(
                ["a", "b"], {"url": "http://example.invalid/private"})
        with self.assertRaisesRegex(ValueError, "already exists"):
            auth_context.manager().configure("a", self.origin)
        with self.assertRaises(ValueError):
            auth_context.manager().configure("bad name", self.origin)

    def test_compare_requires_unique_contexts(self):
        auth_context.manager().configure("a", self.origin)
        with self.assertRaisesRegex(ValueError, "unique"):
            auth_context.manager().compare(["a", "a"], {"url": self.origin})

    def test_response_limit(self):
        auth_context.manager().configure("a", self.origin)
        auth_context.manager().configure("b", self.origin)
        with self.assertRaisesRegex(ValueError, "byte limit"):
            auth_context.manager().compare(
                ["a", "b"], {"url": self.origin + "/large"})

    def test_redirects_are_same_origin_only(self):
        auth_context.manager().configure("a", self.origin)
        auth_context.manager().configure("b", self.origin)
        result = auth_context.manager().compare(
            ["a", "b"], {"url": self.origin + "/redirect-in"})
        self.assertEqual(len(result["observations"][0]["response"]["redirects"]), 1)
        with self.assertRaisesRegex(ValueError, "redirect cannot leave"):
            auth_context.manager().compare(
                ["a", "b"], {"url": self.origin + "/redirect-out"})

    def test_inventory_persistence(self):
        manager = auth_context.manager()
        manager.configure("anonymous", self.origin)
        manager.configure("admin", self.origin,
                          transport={"auth": "bearer:ADMIN-SECRET"})
        result = manager.compare(["anonymous", "admin"],
                                 {"url": self.origin + "/objects/2"})
        inv = Inventory()
        inv.ingest([{"name": "auth_compare", "outcome": "ok", "data": result}])
        endpoint = inv.host(self.origin).endpoints[self.origin + "/objects/2"]
        self.assertEqual(endpoint.auth_observations[0]["interpretation"], "facts_only")
        self.assertEqual(inv.auth_inventory()[0]["url"], self.origin + "/objects/2")
        self.assertIn("auth_obs=1", inv.render())
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / "inventory.json")
            inv.save(path)
            self.assertEqual(inv.to_dict(), Inventory.load(path).to_dict())

    def test_tool_lifecycle(self):
        import tools
        text, data = tools._auth_context_set(name="anonymous", origin=self.origin)
        self.assertFalse(text.startswith("[!]")); self.assertEqual(data["name"], "anonymous")
        _, listed = tools._auth_context_list()
        self.assertEqual(len(listed["contexts"]), 1)
        _, removed = tools._auth_context_remove(name="anonymous")
        self.assertTrue(removed["removed"])


if __name__ == "__main__":
    unittest.main()
