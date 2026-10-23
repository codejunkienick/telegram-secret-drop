"""Tests for the serve command: the one-form web server.

Fake-only: settings, slots and posted values live in temporary directories
outside any git tree; values are placeholders like fake-value-123; the
server binds 127.0.0.1 on a free port and no test reaches another host.
"""

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path

import secret_drop
from secret_drop import load_settings, new_slot
from testports import free_port

ROOT = Path(__file__).resolve().parent
SECRET_DROP = str(ROOT / "secret_drop.py")

TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{43}")

EXPECTED_SECURITY_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none';"
                               " style-src 'unsafe-inline';"
                               " script-src 'sha256-%s';"
                               " form-action 'self';"
                               " frame-ancestors 'none';"
                               " base-uri 'none'"
                               % secret_drop._EYE_SCRIPT_HASH,
}


def _toml(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml(v) for v in value) + "]"
    raise AssertionError("unhandled TOML value: %r" % (value,))


class ServerCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="sd-test-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.allowed = self.tmp / "allowed"
        self.allowed.mkdir(mode=0o700)
        self.port = free_port()
        self.slots = str(self.tmp / "slots")
        values = {
            "lan_address": "127.0.0.1",
            "port": self.port,
            "allowed_dirs": [str(self.allowed)],
            "slots_dir": self.slots,
        }
        path = self.tmp / "settings.toml"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            data = "".join(
                "%s = %s\n" % (k, _toml(v)) for k, v in values.items()
            ).encode("utf-8")
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)
        self.settings_path = str(path)
        self.settings = load_settings(self.settings_path)
        self.host = "127.0.0.1:%d" % self.port
        self._procs = []

    def tearDown(self):
        for proc in self._procs:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
                proc.wait(timeout=30)
            if proc.stderr and not proc.stderr.closed:
                proc.stderr.close()

    def start_serve(self):
        proc = subprocess.Popen(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "serve"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            cwd=str(self.tmp))
        self._procs.append(proc)
        return proc

    def wait_serving(self, proc, name, timeout=15):
        path = Path(self.slots) / "server.json"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError(
                    "serve exited early with %s" % proc.poll())
            try:
                data = json.loads(path.read_text())
            except (FileNotFoundError, ValueError):
                time.sleep(0.05)
                continue
            if name in data.get("open", []):
                self.assertEqual(data["pid"], proc.pid)
                return data
            time.sleep(0.05)
        raise AssertionError("server.json never listed %s" % name)

    def target(self, *parts):
        return str(self.allowed.joinpath(*parts))

    def open_slot(self, name, target_name, reason="", ttl=10):
        _record, token = new_slot(self.settings, name,
                                  self.target(target_name), reason, ttl,
                                  False, False)
        return token

    def request(self, method, path, body=None, headers=None, timeout=10):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=timeout)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        conn.close()
        return result

    def assertSecurityHeaders(self, headers):
        for name, value in EXPECTED_SECURITY_HEADERS.items():
            self.assertEqual(headers.get(name), value)


class FormTest(ServerCase):
    def test_get_form_and_headers(self):
        token = self.open_slot("web", "token", 'say <hi> & "bye"')
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        status, headers, data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)
        self.assertSecurityHeaders(headers)
        text = data.decode("utf-8")
        self.assertIn("say &lt;hi&gt; &amp; &quot;bye&quot;", text)
        self.assertNotIn('say <hi> & "bye"', text)
        self.assertIn('method="post"', text)
        self.assertNotIn("action=", text)
        self.assertIn('type="password"', text)
        self.assertIn('name="value"', text)
        self.assertIn('autocomplete="off"', text)
        self.assertIn('autocapitalize="off"', text)
        self.assertIn('autocorrect="off"', text)
        self.assertIn('spellcheck="false"', text)
        self.assertIn("required", text)
        self.assertIn(">Store<", text)
        self.assertIn("Show value", text)
        self.assertNotIn(token, text)
        status, _headers, _data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)

    def test_form_phone_fields(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        status, _headers, data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)
        text = data.decode("utf-8")
        self.assertIn(
            '<meta name="viewport"'
            ' content="width=device-width, initial-scale=1">', text)
        found = re.findall(r"<input\b[^>]*>", text)
        self.assertEqual(len(found), 1)
        masked = found[0]
        self.assertIn('type="password"', masked)
        self.assertIn('name="value"', masked)
        self.assertIn("required", masked)
        for attr in ('autocomplete="off"', 'autocapitalize="off"',
                     'autocorrect="off"', 'spellcheck="false"'):
            self.assertIn(attr, masked)
        found = re.findall(r"<textarea\b[^>]*>", text)
        self.assertEqual(len(found), 1)
        plain = found[0]
        self.assertNotIn("name=", plain)
        self.assertIn("hidden", plain)
        match = re.search(r'rows="(\d+)"', plain)
        self.assertIsNotNone(match)
        self.assertGreaterEqual(int(match.group(1)), 6)
        for attr in ('autocomplete="off"', 'autocapitalize="off"',
                     'autocorrect="off"', 'spellcheck="false"'):
            self.assertIn(attr, plain)
        style = re.sub(r"\s+", "", text)
        for rule in ("width:100%", "font-family:monospace",
                     "font-size:16px", "overflow-wrap:anywhere"):
            self.assertIn(rule, style)
        found = re.findall(r"<button\b[^>]*>", text)
        eye = [tag for tag in found if 'id="secret-eye"' in tag]
        self.assertEqual(len(eye), 1)
        self.assertIn("hidden", eye[0])
        self.assertIn('aria-pressed="false"', eye[0])
        self.assertIn('id="secret-eye-label">Show value</span>', text)

    def test_form_script_hash_matches_csp(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        status, headers, data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)
        text = data.decode("utf-8")
        self.assertEqual(text.count("<script"), 1)
        self.assertEqual(text.count("</script>"), 1)
        script = text.split("<script>", 1)[1].split("</script>", 1)[0]
        digest = base64.b64encode(
            hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
        csp = headers.get("Content-Security-Policy")
        self.assertIn("script-src 'sha256-%s'" % digest, csp)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("form-action 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("base-uri 'none'", csp)
        directives = [part.strip() for part in csp.split(";")]
        script_src = [part for part in directives
                      if part.startswith("script-src")]
        self.assertEqual(len(script_src), 1)
        self.assertNotIn("'unsafe-inline'", script_src[0])
        self.assertNotIn("'unsafe-eval'", script_src[0])
        self.assertNotIn("://", text)
        self.assertNotIn("url(", text)
        for snippet in ('getElementById("secret-plain")',
                        'removeAttribute("name")',
                        'setAttribute("name", "value")',
                        '"Hide value"', '"Show value"'):
            self.assertIn(snippet, script)

    def test_routing_404s(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        import secrets as _secrets
        cases = [
            ("GET", "/s/" + _secrets.token_urlsafe(32), None),
            ("GET", "/s/!!!", None),
            ("GET", "/s/" + token + "?x=1", None),
            ("GET", "/other", None),
            ("PUT", "/s/" + token, None),
            ("GET", "/s/" + token, {"Host": "example.com"}),
        ]
        for method, path, extra in cases:
            with self.subTest(method=method, path=path):
                status, _headers, data = self.request(
                    method, path, headers=extra)
                self.assertEqual(status, 404)
                self.assertEqual(data, b"Not found.")

    def test_foreign_origin_403(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        body = urllib.parse.urlencode({"value": "x"}).encode("ascii")
        status, _headers, data = self.request(
            "POST", "/s/" + token, body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(data, b"Forbidden.")
        self.assertFalse(Path(self.target("token")).exists())
        status, _headers, _data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)

    def test_browser_same_origin_post_stores(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        status, headers, _data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Referrer-Policy"), "same-origin")
        body = urllib.parse.urlencode(
            {"value": "fake-value-123"}).encode("ascii")
        status, post_headers, data = self.request(
            "POST", "/s/" + token, body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Origin": "http://" + self.host})
        self.assertEqual(status, 200)
        self.assertEqual(data, b"Stored. You can close this page.")
        self.assertEqual(post_headers.get("Referrer-Policy"), "same-origin")
        self.assertEqual(Path(self.target("token")).read_bytes(),
                         b"fake-value-123")

    def test_null_origin_403(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        body = urllib.parse.urlencode({"value": "x"}).encode("ascii")
        status, _headers, data = self.request(
            "POST", "/s/" + token, body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Origin": "null"})
        self.assertEqual(status, 403)
        self.assertEqual(data, b"Forbidden.")
        self.assertFalse(Path(self.target("token")).exists())
        status, _headers, _data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)

    def test_body_too_large_413(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        status, _headers, data = self.request(
            "POST", "/s/" + token, body=b"v=" + b"x" * 70000,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 413)
        self.assertEqual(data, b"Request body too large.")
        status, _headers, _data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)

    def test_missing_length_411(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/s/" + token)
        conn.putheader("Host", self.host)
        conn.putheader("Content-Type",
                       "application/x-www-form-urlencoded")
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 411)
        response.read()
        conn.close()

    def test_json_content_type_400(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        status, _headers, data = self.request(
            "POST", "/s/" + token, body=b'{"value": "x"}',
            headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertIn("The value was not accepted. Try again.",
                      data.decode("utf-8"))

    def test_bad_values_400(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        bodies = [
            b"value=",
            b"value=%0D%0A",
            urllib.parse.urlencode({"value": "   "}).encode("ascii"),
            urllib.parse.urlencode({"value": "\t"}).encode("ascii"),
            urllib.parse.urlencode({"value": "a\tb"}).encode("ascii"),
            b"value=" + b"a" * 16385,
            b"other=x",
            b"value",
        ]
        for body in bodies:
            with self.subTest(body=body[:12]):
                status, _headers, data = self.request(
                    "POST", "/s/" + token, body=body,
                    headers={"Content-Type":
                             "application/x-www-form-urlencoded"})
                self.assertEqual(status, 400)
                text = data.decode("utf-8")
                self.assertIn("The value was not accepted. Try again.", text)
                self.assertIn('method="post"', text)
        status, _headers, _data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)


class StoreTest(ServerCase):
    def test_valid_post_stores(self):
        first_token = self.open_slot("first", "f-first")
        self.open_slot("second", "f-second")
        proc = self.start_serve()
        self.wait_serving(proc, "first")
        body = urllib.parse.urlencode(
            {"value": "  fake-value-123  "}).encode("ascii")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, _headers, data = self.request(
            "POST", "/s/" + first_token, body=body, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(data, b"Stored. You can close this page.")
        path = self.target("f-first")
        self.assertEqual(Path(path).read_bytes(), b"fake-value-123")
        found = os.stat(path)
        self.assertEqual(stat.S_IMODE(found.st_mode), 0o600)
        record = json.loads(
            (Path(self.slots) / "first.json").read_text())
        self.assertEqual(record["state"], "stored")
        self.assertEqual(record["length"], 14)
        status, _headers, data = self.request(
            "POST", "/s/" + first_token, body=body, headers=headers)
        self.assertEqual(status, 404)
        self.assertEqual(data, b"Not found.")
        cancel = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "cancel", "second"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(cancel.returncode, 0)
        started = time.monotonic()
        self.assertEqual(proc.wait(timeout=10), 0)
        self.assertLess(time.monotonic() - started, 5)
        logged = proc.stderr.read()
        self.assertNotIn(first_token, logged)
        self.assertNotIn("fake-value-123", logged)
        self.assertIn("POST /s/... 200", logged)
        self.assertIn("stored first (14 bytes)", logged)

    def test_value_at_size_limit_stores(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body = urllib.parse.urlencode(
            {"value": "a" * 16384}).encode("ascii")
        status, _headers, _data = self.request(
            "POST", "/s/" + token, body=body, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(Path(self.target("token")).read_bytes(),
                         b"a" * 16384)
        self.assertEqual(proc.wait(timeout=10), 0)

    def test_slow_client_does_not_hold_server(self):
        token = self.open_slot("web", "token")
        second = self.open_slot("second", "f-second")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        trickle = socket.create_connection(("127.0.0.1", self.port),
                                           timeout=30)
        trickle.sendall(
            b"GET / HTTP/1.1\r\nHost: " + self.host.encode("ascii")
            + b"\r\n")
        stop = threading.Event()
        failures = []

        def drip():
            try:
                while not stop.wait(8):
                    trickle.sendall(b"X-Drip: b\r\n")
            except OSError as exc:
                failures.append(exc)

        thread = threading.Thread(target=drip, daemon=True)
        thread.start()
        try:
            time.sleep(1)
            started = time.monotonic()
            status, _headers, _data = self.request(
                "GET", "/s/" + token, timeout=30)
            elapsed = time.monotonic() - started
        finally:
            stop.set()
        self.assertEqual(status, 200)
        self.assertLess(elapsed, 17)
        self.assertEqual(failures, [])
        self.assertEqual(trickle.recv(4096), b"")
        trickle.close()
        body = urllib.parse.urlencode(
            {"value": "fake-value-123"}).encode("ascii")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, _headers, _data = self.request(
            "POST", "/s/" + second, body=body, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(Path(self.target("f-second")).read_bytes(),
                         b"fake-value-123")
        cancel = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "cancel", "web"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(cancel.returncode, 0)
        self.assertEqual(proc.wait(timeout=10), 0)

    def test_c1_controls_refused(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        for raw in ("a\x85b", "a\x9fb"):
            with self.subTest(raw=raw):
                body = urllib.parse.urlencode(
                    {"value": raw}).encode("ascii")
                status, _headers, data = self.request(
                    "POST", "/s/" + token, body=body, headers=headers)
                self.assertEqual(status, 400)
                text = data.decode("utf-8")
                self.assertIn("The value was not accepted. Try again.", text)
                self.assertIn('method="post"', text)
        self.assertFalse(Path(self.target("token")).exists())
        body = urllib.parse.urlencode(
            {"value": "caf\xe9"}).encode("ascii")
        status, _headers, _data = self.request(
            "POST", "/s/" + token, body=body, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(Path(self.target("token")).read_bytes(),
                         "caf\xe9".encode("utf-8"))
        self.assertEqual(proc.wait(timeout=10), 0)

    def test_slow_body_closes_quietly(self):
        token = self.open_slot("web", "token")
        second = self.open_slot("second", "f-second")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        trickle = socket.create_connection(("127.0.0.1", self.port),
                                           timeout=30)
        trickle.sendall(
            b"POST /s/" + token.encode("ascii") + b" HTTP/1.1\r\n"
            b"Host: " + self.host.encode("ascii") + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 200\r\n\r\n"
            + b"value=" + b"x" * 100)
        stop = threading.Event()
        failures = []

        def drip():
            try:
                while not stop.wait(8):
                    trickle.sendall(b"x")
            except OSError as exc:
                failures.append(exc)

        thread = threading.Thread(target=drip, daemon=True)
        thread.start()
        try:
            time.sleep(1)
            started = time.monotonic()
            status, _headers, _data = self.request(
                "GET", "/s/" + token, timeout=30)
            elapsed = time.monotonic() - started
        finally:
            stop.set()
        self.assertEqual(status, 200)
        self.assertLess(elapsed, 17)
        self.assertEqual(failures, [])
        raw = b""
        while True:
            chunk = trickle.recv(4096)
            if not chunk:
                break
            raw += chunk
        self.assertEqual(raw, b"")
        trickle.close()
        stalled = socket.create_connection(("127.0.0.1", self.port),
                                           timeout=30)
        stalled.sendall(
            b"POST /s/" + second.encode("ascii") + b" HTTP/1.1\r\n"
            b"Host: " + self.host.encode("ascii") + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 10\r\n\r\n")
        stalled_raw = b""
        while True:
            chunk = stalled.recv(4096)
            if not chunk:
                break
            stalled_raw += chunk
        self.assertEqual(stalled_raw, b"")
        stalled.close()
        body = urllib.parse.urlencode(
            {"value": "fake-value-123"}).encode("ascii")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, _headers, _data = self.request(
            "POST", "/s/" + token, body=body, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(Path(self.target("token")).read_bytes(),
                         b"fake-value-123")
        cancel = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "cancel", "second"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(cancel.returncode, 0)
        self.assertEqual(proc.wait(timeout=10), 0)
        self.assertNotIn("internal_error", proc.stderr.read())

    def test_expired_slot(self):
        token = self.open_slot("late", "token", ttl=1)
        proc = self.start_serve()
        self.wait_serving(proc, "late")
        settings = load_settings(self.settings_path)
        with secret_drop._locked_slots(settings) as slots_dir:
            record = secret_drop._load_record(slots_dir, "late")
            record["expires_at"] = record["created_at"] - 1
            secret_drop._save_record(slots_dir, record)
        status, _headers, data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 404)
        self.assertEqual(data, b"Not found.")
        self.assertEqual(proc.wait(timeout=10), 0)

    def test_symlink_target_409(self):
        token = self.open_slot("hard", "token")
        dest = self.target("dest")
        Path(dest).write_bytes(b"keep-me")
        os.symlink(dest, self.target("token"))
        proc = self.start_serve()
        self.wait_serving(proc, "hard")
        body = urllib.parse.urlencode(
            {"value": "fake-value-123"}).encode("ascii")
        status, _headers, data = self.request(
            "POST", "/s/" + token, body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 409)
        self.assertEqual(
            data,
            b"Not stored (target_not_regular). Ask the agent for a new link.")
        record = json.loads(
            (Path(self.slots) / "hard.json").read_text())
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["error"], "target_not_regular")
        self.assertEqual(Path(dest).read_bytes(), b"keep-me")

    def test_two_slots_survive_first_store(self):
        first = self.open_slot("first", "f-first")
        second = self.open_slot("second", "f-second")
        proc = self.start_serve()
        self.wait_serving(proc, "first")
        body = urllib.parse.urlencode(
            {"value": "fake-value-123"}).encode("ascii")
        status, _headers, _data = self.request(
            "POST", "/s/" + first, body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 200)
        status, _headers, _data = self.request("GET", "/s/" + second)
        self.assertEqual(status, 200)
        self.assertIsNone(proc.poll())
        cancel = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "cancel", "second"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(cancel.returncode, 0)
        self.assertEqual(proc.wait(timeout=10), 0)

    def test_second_serve_already_serving(self):
        self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        other = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "serve"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(other.returncode, 0)
        self.assertEqual(other.stderr, "secret-drop: already_serving\n")
        self.assertEqual(other.stdout, "")

    def test_bind_failed(self):
        self.open_slot("web", "token")
        hold = socket.socket()
        hold.bind(("127.0.0.1", self.port))
        hold.listen(1)
        self.addCleanup(hold.close)
        proc = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "serve"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: bind_failed\n")
        self.assertEqual(proc.stdout, "")

    def test_no_open_slot_exits(self):
        started = time.monotonic()
        proc = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "serve"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")
        self.assertLess(time.monotonic() - started, 5)

    def test_reserved_name_server(self):
        proc = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "open", "--name", "server",
             "--file", self.target("token")],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: bad_name\n")
        self.assertEqual(proc.stdout, "")

    def test_no_slot_held_port_exits(self):
        hold = socket.socket()
        hold.bind(("127.0.0.1", self.port))
        hold.listen(1)
        self.addCleanup(hold.close)
        started = time.monotonic()
        proc = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "serve"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")
        self.assertLess(time.monotonic() - started, 5)

    def test_protocol_error_fixed_body(self):
        self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        sock = socket.create_connection(("127.0.0.1", self.port),
                                        timeout=10)
        sock.sendall(b"GET / HTTP/9.9\r\nHost: " + self.host.encode("ascii")
                      + b"\r\n\r\n")
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
        head, _, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(
            head.split(b"\r\n")[0].startswith(b"HTTP/1.1 505 "))
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            headers[name.strip().lower()] = value.strip()
        self.assertEqual(body, b"Bad request.")
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assertIn(b"default-src 'none'",
                      headers[b"content-security-policy"])
        self.assertEqual(headers[b"x-content-type-options"], b"nosniff")
        self.assertNotIn(b"9.9", raw)
        cancel = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "cancel", "web"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(cancel.returncode, 0)
        self.assertEqual(proc.wait(timeout=10), 0)
        self.assertEqual(proc.stderr.read(),
                         "UNKNOWN other 505 127.0.0.1\n")

    def test_symlinked_server_lock(self):
        os.mkdir(self.slots, 0o700)
        real = self.tmp / "real.lock"
        real.write_bytes(b"x")
        os.symlink(str(real), os.path.join(self.slots, "server.lock"))
        proc = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "serve"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: slots_dir_unsafe\n")
        self.assertEqual(proc.stdout, "")

    def test_chunked_body_400(self):
        token = self.open_slot("web", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "web")
        sock = socket.create_connection(("127.0.0.1", self.port),
                                        timeout=10)
        sock.sendall(
            ("POST /s/" + token + " HTTP/1.1\r\n"
             "Host: " + self.host + "\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Transfer-Encoding: chunked\r\n"
             "\r\n"
             "5\r\nhello\r\n0\r\n\r\n").encode("ascii"))
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
        head, _, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(
            head.split(b"\r\n")[0].startswith(b"HTTP/1.1 400 "))
        text = body.decode("utf-8")
        self.assertIn("The value was not accepted. Try again.", text)
        self.assertIn('method="post"', text)
        status, _headers, _data = self.request("GET", "/s/" + token)
        self.assertEqual(status, 200)


class HandshakeFileTest(ServerCase):
    def test_lists_slot_before_first_request(self):
        self.open_slot("early", "token")
        proc = self.start_serve()
        holder = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                holder = socket.create_connection(
                    ("127.0.0.1", self.port), timeout=5)
                break
            except OSError:
                if proc.poll() is not None:
                    self.fail("serve exited early")
                time.sleep(0.05)
        self.assertIsNotNone(holder)
        try:
            found = None
            end = time.monotonic() + 2.0
            while time.monotonic() < end:
                try:
                    data = json.loads(
                        (Path(self.slots) / "server.json").read_text())
                except (FileNotFoundError, ValueError):
                    time.sleep(0.05)
                    continue
                if "early" in data.get("open", []):
                    found = data
                    break
                time.sleep(0.05)
            self.assertIsNotNone(found, "server.json never listed early")
            self.assertEqual(found["pid"], proc.pid)
        finally:
            holder.close()
        cancel = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "cancel", "early"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(cancel.returncode, 0)
        self.assertEqual(proc.wait(timeout=10), 0)

    def test_served_needs_current_slot_id(self):
        import unittest.mock as mock
        record, _token = new_slot(self.settings, "page",
                                  self.target("token"), "", 10,
                                  False, False)
        stale = {"pid": os.getpid(), "open": ["page"],
                 "open_ids": ["00" * 8],
                 "updated_at": int(time.time())}
        slots_path = Path(self.slots)
        slots_path.mkdir(mode=0o700, exist_ok=True)
        tmp_name = ".server-test.tmp"
        tmp_path = slots_path / tmp_name
        tmp_path.write_bytes(json.dumps(stale).encode("utf-8"))
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, slots_path / "server.json")
        with mock.patch.object(secret_drop, "_start_unit",
                               return_value=None):
            served = secret_drop._wait_served(
                self.settings, "page", time.monotonic() + 0.5,
                record["slot_id"])
        self.assertFalse(served)

    def test_denied_peer_is_not_served(self):
        import unittest.mock as mock
        record, _token = new_slot(self.settings, "page",
                                  self.target("token"), "", 10,
                                  False, False)
        slots_path = Path(self.slots)
        slots_path.mkdir(mode=0o700, exist_ok=True)
        live = {"pid": os.getpid(), "open": ["page"],
                "open_ids": [record["slot_id"]],
                "updated_at": int(time.time())}
        tmp_path = slots_path / ".server-live.tmp"
        tmp_path.write_bytes(json.dumps(live).encode("utf-8"))
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, slots_path / "server.json")
        with mock.patch.object(secret_drop.os, "kill",
                               side_effect=PermissionError(13, "denied")):
            self.assertFalse(
                secret_drop._is_served(str(slots_path), "page",
                                       record["slot_id"]))

    def test_sigterm_exits_zero_and_unlinks(self):
        self.open_slot("term", "token")
        proc = self.start_serve()
        self.wait_serving(proc, "term")
        proc.terminate()
        try:
            code = proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.fail("serve did not exit within 2 s of SIGTERM")
        self.assertEqual(code, 0)
        self.assertFalse((Path(self.slots) / "server.json").exists())

    def test_sigterm_during_first_sync_exits_zero(self):
        import unittest.mock as mock
        new_slot(self.settings, "early-term", self.target("token"),
                 "", 10, False, False)
        real_sync = secret_drop._sync_server_file
        called = []

        def probe(settings):
            if not called:
                called.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return real_sync(settings)

        with mock.patch.object(secret_drop, "_sync_server_file",
                               side_effect=probe):
            code = secret_drop._run_server(self.settings, self.slots)
        self.assertTrue(called)
        self.assertEqual(code, 0)
        self.assertFalse((Path(self.slots) / "server.json").exists())


_EYE_HARNESS_JS = """\"use strict\";
const fs = require("fs");
const path = require("path");
const script = fs.readFileSync(
    path.join(__dirname, "page.js"), "utf8");

function makeEl(id) {
  const listeners = {};
  return {
    id: id,
    value: "",
    textContent: "",
    hidden: false,
    disabled: false,
    required: false,
    selectionStart: 0,
    selectionEnd: 0,
    attrs: {},
    getAttribute: function (k) {
      if (Object.prototype.hasOwnProperty.call(this.attrs, k)) {
        return this.attrs[k];
      }
      return null;
    },
    setAttribute: function (k, v) { this.attrs[k] = String(v); },
    removeAttribute: function (k) { delete this.attrs[k]; },
    addEventListener: function (t, f) {
      listeners[t] = listeners[t] || [];
      listeners[t].push(f);
    },
    dispatch: function (t) {
      const handlers = listeners[t] || [];
      for (const f of handlers) { f({}); }
    },
    setSelectionRange: function (a, b) {
      this.selectionStart = a;
      this.selectionEnd = b;
    },
    focus: function () {},
  };
}

const pass = makeEl("secret-value");
pass.attrs.name = "value";
pass.required = true;
const plain = makeEl("secret-plain");
plain.hidden = true;
plain.disabled = true;
const eye = makeEl("secret-eye");
eye.hidden = true;
eye.attrs["aria-pressed"] = "false";
const eyeLabel = makeEl("secret-eye-label");
eyeLabel.textContent = "Show value";
const label = makeEl("secret-label");
label.attrs.for = "secret-value";

const document = {
  getElementById: function (id) {
    if (id === "secret-value") { return pass; }
    if (id === "secret-plain") { return plain; }
    if (id === "secret-eye") { return eye; }
    if (id === "secret-eye-label") { return eyeLabel; }
    if (id === "secret-label") { return label; }
    throw new Error("unknown id " + id);
  },
};

new Function("document", script)(document);

function named() {
  const found = [];
  const controls = [pass, plain];
  for (const el of controls) {
    if (el.getAttribute("name") === "value") { found.push(el); }
  }
  return found;
}
function check(desc, cond, extra) {
  if (!cond) {
    console.log("not ok " + desc + (extra ? " :: " + extra : ""));
    process.exitCode = 1;
  } else {
    console.log("ok " + desc);
  }
}
function submitValue() {
  const found = named();
  check("exactly one named control", found.length === 1,
        "found " + found.length);
  if (found.length === 1) { return found[0].value; }
  return null;
}
function onlyOneNamed(expected) {
  const found = named();
  check("exactly one named control", found.length === 1,
        "found " + found.length);
  if (found.length === 1) {
    check("named control is " + expected.id, found[0] === expected,
          found[0].id);
    const other = expected === pass ? plain : pass;
    check("other control has no name",
          other.getAttribute("name") === null, other.id);
  }
}

onlyOneNamed(pass);
pass.value = "abc";
onlyOneNamed(pass);
let sent = submitValue();
check("masked submit sends typed value", sent === "abc",
      JSON.stringify(sent));
check("textarea unnamed while masked",
      plain.getAttribute("name") === null);

eye.dispatch("click");
onlyOneNamed(plain);
check("revealed textarea shows value", plain.value === "abc",
      JSON.stringify(plain.value));
check("revealed textarea is the named one",
      plain.getAttribute("name") === "value" &&
      pass.getAttribute("name") === null);
check("revealing sets pressed and label",
      eye.getAttribute("aria-pressed") === "true" &&
      eyeLabel.textContent === "Hide value");
eye.dispatch("click");
onlyOneNamed(pass);
check("hidden password keeps value and name",
      pass.value === "abc" && pass.getAttribute("name") === "value");
check("hiding resets pressed and label",
      eye.getAttribute("aria-pressed") === "false" &&
      eyeLabel.textContent === "Show value");

eye.dispatch("click");
onlyOneNamed(plain);
plain.value = "abcX";
plain.selectionStart = 4;
plain.selectionEnd = 4;
plain.dispatch("input");
eye.dispatch("click");
onlyOneNamed(pass);
pass.value = "abcXY";
for (let i = 0; i < 5; i++) {
  eye.dispatch("click");
  onlyOneNamed(i % 2 === 0 ? plain : pass);
}
onlyOneNamed(plain);
sent = submitValue();
check("value survives repeated toggles", sent === "abcXY",
      JSON.stringify(sent));

if (plain.getAttribute("name") !== "value") { eye.dispatch("click"); }
plain.value = "ab\\r\\ncd\\n";
plain.selectionStart = 7;
plain.selectionEnd = 7;
plain.dispatch("input");
onlyOneNamed(plain);
check("line breaks stripped", plain.value === "abcd",
      JSON.stringify(plain.value));

plain.value = "shown-secret";
plain.dispatch("input");
onlyOneNamed(plain);
sent = submitValue();
check("revealed submit sends textarea value",
      sent === "shown-secret", JSON.stringify(sent));
check("password unnamed while revealed",
      pass.getAttribute("name") === null);

if (process.exitCode) {
  console.log("FAILURES PRESENT");
} else {
  console.log("ALL PASS");
}
"""


class ScriptTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "node is not on PATH")
    def test_eye_script_swaps_named_value(self):
        record = {"name": "web", "reason": "r", "target": "/tmp/x",
                  "expires_at": int(time.time()) + 600}
        text = secret_drop._form_page(record)
        script = text.split("<script>", 1)[1].split("</script>", 1)[0]
        with tempfile.TemporaryDirectory(prefix="sd-eye-") as tmp:
            page_path = os.path.join(tmp, "page.js")
            harness_path = os.path.join(tmp, "harness.js")
            with open(page_path, "w", encoding="utf-8") as handle:
                handle.write(script)
            with open(harness_path, "w", encoding="utf-8") as handle:
                handle.write(_EYE_HARNESS_JS)
            proc = subprocess.run(
                ["node", harness_path], capture_output=True, text=True,
                timeout=60, cwd=tmp)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ALL PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
