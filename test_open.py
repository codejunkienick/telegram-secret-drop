"""Tests for the open end to end: start the unit, handshake, send link.

Fake-only: the unit is a fake systemctl script and the link goes through
a fake send script, both in a temporary dir; values are placeholders like
fake-value-123; no test touches a real unit, gc, Telegram or any network
beyond 127.0.0.1.
"""

import argparse
import contextlib
import http.client
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
import urllib.parse
from datetime import datetime
from pathlib import Path

import secret_drop
from secret_drop import load_settings
from testports import free_port

ROOT = Path(__file__).resolve().parent
SECRET_DROP = str(ROOT / "secret_drop.py")

LINK_RE = re.compile(
    r'<a href="http://127\.0\.0\.1:(\d+)/s/([A-Za-z0-9_-]{43})">'
    r"Open the form</a> on the home network before "
    r"(\d\d:\d\d)\. The link works once\.")

FAKE_SYSTEMCTL = """\
#!/usr/bin/env python3
import os
import subprocess
import sys
import time


def main():
    with open(os.environ["SD_TEST_SYSLOG"], "a") as handle:
        handle.write(" ".join(sys.argv[1:]) + "\\n")
    if sys.argv[1:3] != ["--user", "start"]:
        return 0
    if os.environ.get("SD_TEST_SYSTEMCTL_HANG") == "1":
        time.sleep(6)
        return 0
    if os.environ.get("SD_TEST_SYSTEMCTL_NOOP") == "1":
        return 0
    count_path = os.environ.get("SD_TEST_SYSTEMCTL_COUNT")
    if count_path is not None:
        try:
            with open(count_path) as handle:
                count = int(handle.read().strip() or "0")
        except (OSError, ValueError):
            count = 0
        with open(count_path, "w") as handle:
            handle.write(str(count + 1))
        if count + 1 < 2:
            return 0
    err = open(os.environ["SD_TEST_SERVER_ERR"], "ab")
    try:
        subprocess.Popen(
            [sys.executable, "-B", os.environ["SD_TEST_SECRET_DROP"],
             "--settings", os.environ["SD_TEST_SETTINGS"], "serve"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=err, start_new_session=True)
    finally:
        err.close()
    return 0


sys.exit(main())
"""

FAKE_SEND = """\
#!/usr/bin/env python3
import os
import re
import shutil
import sys
import time


def main():
    args = sys.argv[1:]
    with open(os.environ["SD_TEST_SEND_LOG"], "a") as handle:
        handle.write(" ".join(args) + "\\n")
    body = args[args.index("--body-file") + 1]
    shutil.copyfile(body, os.environ["SD_TEST_SEND_CAPTURE"])
    if os.environ.get("SD_TEST_SEND_BLOCK") == "1":
        time.sleep(60)
        return 0
    if os.environ.get("SD_TEST_SEND_FORK") == "1":
        if os.fork() == 0:
            time.sleep(30)
            os._exit(0)
        time.sleep(60)
        return 0
    if os.environ.get("SD_TEST_SEND_ECHO_LINK") == "1":
        with open(body, encoding="utf-8") as handle:
            text = handle.read()
        match = re.search(r'href="([^"]+)"', text)
        if match:
            sys.stderr.write(match.group(1) + "\\n")
    if os.environ.get("SD_TEST_SEND_RAW") == "1":
        sys.stderr.buffer.write(b"\\xff\\xfe bad\\n")
    extra = os.environ.get("SD_TEST_SEND_STDERR", "")
    if extra:
        sys.stderr.write(extra)
    print("Telegram delivery confirmed; message ID 1")
    return int(os.environ.get("SD_TEST_SEND_EXIT", "0"))


sys.exit(main())
"""


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


def _iso(when):
    return datetime.fromtimestamp(when).astimezone().isoformat(
        timespec="seconds")


class OpenCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="sd-test-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.allowed = self.tmp / "allowed"
        self.allowed.mkdir(mode=0o700)
        self.port = free_port()
        self.slots = str(self.tmp / "slots")
        self.bindir = self.tmp / "bin"
        self.bindir.mkdir(mode=0o700)
        self.write_script("systemctl", FAKE_SYSTEMCTL)
        self.write_script("send", FAKE_SEND)
        values = {
            "lan_address": "127.0.0.1",
            "port": self.port,
            "allowed_dirs": [str(self.allowed)],
            "slots_dir": self.slots,
            "send_command": [str(self.bindir / "send")],
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

    def tearDown(self):
        try:
            data = json.loads(
                (Path(self.slots) / "server.json").read_text())
        except (OSError, ValueError):
            return
        pid = data.get("pid")
        if type(pid) is not int:
            return
        try:
            os.kill(pid, 0)
        except OSError:
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                return
            time.sleep(0.05)
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    def write_script(self, name, text):
        path = self.bindir / name
        path.write_text(text)
        os.chmod(path, 0o700)
        return str(path)

    def target(self, *parts):
        return str(self.allowed.joinpath(*parts))

    def make_env(self, **overrides):
        env = dict(os.environ)
        env["PATH"] = str(self.bindir) + os.pathsep + env.get("PATH", "")
        env["SD_TEST_SETTINGS"] = self.settings_path
        env["SD_TEST_SECRET_DROP"] = SECRET_DROP
        env["SD_TEST_SYSLOG"] = str(self.tmp / "sys.log")
        env["SD_TEST_SERVER_ERR"] = str(self.tmp / "server.err")
        env["SD_TEST_SEND_LOG"] = str(self.tmp / "send.log")
        env["SD_TEST_SEND_CAPTURE"] = str(self.tmp / "body.html")
        env.update(overrides)
        return env

    def open_cli(self, env, *args, timeout=60):
        return subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "open", *args],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(self.tmp), env=env)

    def read_record(self, name):
        return json.loads(
            (Path(self.slots) / (name + ".json")).read_text())

    def test_happy_path(self):
        env = self.make_env()
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", "rotation")
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        self.assertEqual(set(shown), {"name", "state", "expires_at", "link"})
        self.assertEqual(shown["name"], "page")
        self.assertEqual(shown["state"], "open")
        self.assertEqual(shown["link"], "sent")
        record = self.read_record("page")
        self.assertEqual(shown["expires_at"], _iso(record["expires_at"]))
        body = Path(env["SD_TEST_SEND_CAPTURE"]).read_text()
        lines = body.split("\n")
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0],
                         "<b>Secret requested</b>: <code>page</code>")
        self.assertEqual(lines[1], "rotation")
        match = LINK_RE.fullmatch(lines[2])
        self.assertIsNotNone(match)
        self.assertEqual(int(match.group(1)), self.port)
        token = match.group(2)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        posted = urllib.parse.urlencode(
            {"value": "fake-value-123"}).encode("ascii")
        conn.request("POST", "/s/" + token, body=posted,
                     headers={"Content-Type":
                              "application/x-www-form-urlencoded"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        response.read()
        conn.close()
        status = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "status", "page", "--wait", "5"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp))
        self.assertEqual(status.returncode, 0)
        self.assertEqual(json.loads(status.stdout)["length"], 14)
        self.assertEqual(Path(self.target("token")).read_bytes(),
                         b"fake-value-123")
        for text in (proc.stdout, proc.stderr,
                     Path(env["SD_TEST_SYSLOG"]).read_text(),
                     Path(env["SD_TEST_SEND_LOG"]).read_text()):
            self.assertNotIn(token, text)
            self.assertNotIn("/s/", text)
        argv = Path(env["SD_TEST_SEND_LOG"]).read_text().strip().split(" ")
        self.assertEqual(argv[-6], "--format")
        self.assertEqual(argv[-5], "html")
        self.assertEqual(argv[-4], "--body-file")
        self.assertTrue(argv[-3].endswith(".html"))
        self.assertEqual(argv[-2], "--idempotency-key")
        self.assertTrue(
            re.fullmatch(r"secret-drop:[0-9a-f]{16}", argv[-1]))
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])
        server_err = Path(env["SD_TEST_SERVER_ERR"]).read_text()
        self.assertNotIn(token, server_err)
        self.assertNotIn("fake-value-123", server_err)

    def test_escaping(self):
        env = self.make_env()
        reason = 'say <hi> & "bye"'
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", reason)
        self.assertEqual(proc.returncode, 0)
        body = Path(env["SD_TEST_SEND_CAPTURE"]).read_text()
        lines = body.split("\n")
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0],
                         "<b>Secret requested</b>: <code>page</code>")
        self.assertEqual(lines[1], "say &lt;hi&gt; &amp; &quot;bye&quot;")
        self.assertNotIn(reason, body)

    def test_empty_reason(self):
        env = self.make_env()
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"))
        self.assertEqual(proc.returncode, 0)
        body = Path(env["SD_TEST_SEND_CAPTURE"]).read_text()
        lines = body.split("\n")
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0],
                         "<b>Secret requested</b>: <code>page</code>")
        self.assertIsNotNone(LINK_RE.fullmatch(lines[1]))

    def test_send_exit_1_clean(self):
        env = self.make_env(SD_TEST_SEND_EXIT="1",
                            SD_TEST_SEND_STDERR="delivery failed: x\n")
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", "rotation")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            proc.stderr,
            "secret-drop: send_failed (exit 1): delivery failed: x\n")
        self.assertEqual(proc.stdout, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])

    def test_send_exit_1_link_echo(self):
        env = self.make_env(SD_TEST_SEND_EXIT="1",
                            SD_TEST_SEND_ECHO_LINK="1")
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", "rotation")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: send_failed (exit 1)\n")
        self.assertEqual(proc.stdout, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")

    def test_dead_systemctl(self):
        env = self.make_env(SD_TEST_SYSTEMCTL_NOOP="1")
        started = time.monotonic()
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", "rotation")
        elapsed = time.monotonic() - started
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: server_not_running\n")
        self.assertEqual(proc.stdout, "")
        self.assertGreaterEqual(elapsed, 4.5)
        self.assertLess(elapsed, 15)
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        self.assertFalse(Path(env["SD_TEST_SEND_LOG"]).exists())

    def test_flaky_systemctl(self):
        count_path = str(self.tmp / "syscount")
        env = self.make_env(SD_TEST_SYSTEMCTL_COUNT=count_path)
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", "rotation")
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        self.assertEqual(shown["link"], "sent")
        self.assertGreaterEqual(int(Path(count_path).read_text()), 2)
        body = Path(env["SD_TEST_SEND_CAPTURE"]).read_text()
        self.assertEqual(len(body.split("\n")), 3)

    def open_in_process(self, **overrides):
        params = {"settings": self.settings_path, "name": "page",
                  "file": self.target("token"), "reason": "rotation",
                  "ttl_minutes": 10, "overwrite": False, "replace": False}
        params.update(overrides)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = secret_drop._open_command(
                argparse.Namespace(**params))
        return code, out.getvalue(), err.getvalue()

    def test_send_body_written_at_one_site(self):
        source = Path(SECRET_DROP).read_text()
        sites = [line.strip() for line in source.splitlines()
                 if "send-" in line
                 and not line.lstrip().startswith("#")]
        self.assertEqual(
            sites, ['name = "send-%s.html" % record["slot_id"]'])

    def test_existing_body_file_refuses_open(self):
        slot_id = "ab12cd34ef56ab78"
        Path(self.slots).mkdir(mode=0o700, exist_ok=True)
        planted = Path(self.slots) / ("send-%s.html" % slot_id)
        planted.write_bytes(b"untouchable")
        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop.secrets, "token_hex",
                                        return_value=slot_id):
            code, out, err = self.open_in_process()
        self.assertEqual(code, 1)
        self.assertEqual(err, "secret-drop: send_failed (exit body)\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        self.assertEqual(planted.read_bytes(), b"untouchable")

    def test_send_raw_stderr(self):
        env = self.make_env(SD_TEST_SEND_EXIT="1",
                            SD_TEST_SEND_RAW="1")
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", "rotation")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr,
                         "secret-drop: send_failed (exit 1)\n")
        self.assertEqual(proc.stdout, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")

    def test_send_missing_command(self):
        text = Path(self.settings_path).read_text()
        self.assertIn(str(self.bindir / "send"), text)
        Path(self.settings_path).write_text(
            text.replace(str(self.bindir / "send"),
                         "/nonexistent-sd-send"))
        env = self.make_env()
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", "rotation")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            proc.stderr,
            "secret-drop: send_failed (exit not_started)\n")
        self.assertEqual(proc.stdout, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])

    def test_send_timeout_kills_group(self):
        overlay = {"SD_TEST_SEND_LOG": str(self.tmp / "send.log"),
                   "SD_TEST_SEND_CAPTURE": str(self.tmp / "body.html"),
                   "SD_TEST_SEND_FORK": "1"}
        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_SEND_TIMEOUT", 2), \
             unittest.mock.patch.dict(os.environ, overlay):
            started = time.monotonic()
            code, out, err = self.open_in_process()
            elapsed = time.monotonic() - started
        self.assertEqual(code, 1)
        self.assertEqual(err,
                         "secret-drop: send_failed (exit timeout)\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        self.assertLess(elapsed, 20)
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])

    def test_send_error_cleans_body_file(self):
        with unittest.mock.patch.object(
                secret_drop, "_wait_served",
                return_value=True), \
             unittest.mock.patch.object(
                secret_drop, "_run_send",
                side_effect=OSError("boom")):
            code, out, err = self.open_in_process()
        self.assertEqual(code, 1)
        self.assertEqual(
            err, "secret-drop: send_failed (exit error)\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"],
                         "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])

    def test_send_interrupt_reports_interrupted(self):
        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_run_send",
                                        side_effect=KeyboardInterrupt()):
            code, out, err = self.open_in_process()
        self.assertEqual(code, 130)
        self.assertEqual(err, "secret-drop: interrupted\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])

    def test_unproven_removal_cancels_slot(self):
        # A 000 slots dir breaks removal and the cancel alike, so this
        # half asserts the line and exit only; the cancelled half is below.
        self.addCleanup(os.chmod, self.slots, 0o700)

        def send_and_lock(*args, **kwargs):
            os.chmod(self.slots, 0o000)
            return (True, None, None)

        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_run_send",
                                        side_effect=send_and_lock):
            code, out, err = self.open_in_process(name="page-a")
        os.chmod(self.slots, 0o700)
        self.assertEqual(code, 1)
        self.assertEqual(err,
                         "secret-drop: send_failed (exit cleanup)\n")
        self.assertEqual(out, "")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(len(left), 1)

        real_unlink = os.unlink

        def fail_body(path, *args, **kwargs):
            if os.path.basename(
                    os.fspath(path)).startswith("send-"):
                raise PermissionError(13, "denied",
                                      os.fspath(path))
            return real_unlink(path, *args, **kwargs)

        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_run_send",
                                        return_value=(True, None, None)), \
             unittest.mock.patch.object(secret_drop.os, "unlink",
                                        side_effect=fail_body):
            code, out, err = self.open_in_process(
                name="page-b", file=self.target("token-b"))
        self.assertEqual(code, 1)
        self.assertEqual(err,
                         "secret-drop: send_failed (exit cleanup)\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page-b")["state"], "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(len(left), 2)

    def test_success_removes_body_file(self):
        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_run_send",
                                        return_value=(True, None, None)):
            code, out, err = self.open_in_process()
        self.assertEqual(code, 0)
        shown = json.loads(out)
        self.assertEqual(shown["link"], "sent")
        self.assertEqual(shown["state"], "open")
        self.assertEqual(shown["name"], "page")
        record = self.read_record("page")
        self.assertEqual(record["state"], "open")
        self.assertEqual(shown["expires_at"], _iso(record["expires_at"]))
        self.assertEqual(err, "")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])

    def test_handshake_deadline_cancels_slot(self):
        env = self.make_env(SD_TEST_SYSTEMCTL_HANG="1")
        started = time.monotonic()
        proc = self.open_cli(env, "--name", "page",
                             "--file", self.target("token"),
                             "--reason", "rotation")
        elapsed = time.monotonic() - started
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: server_not_running\n")
        self.assertEqual(proc.stdout, "")
        self.assertGreaterEqual(elapsed, 4.0)
        self.assertLess(elapsed, 5.5)
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        self.assertFalse(Path(env["SD_TEST_SEND_LOG"]).exists())

    def test_cleanup_interrupt_cancels_slot(self):
        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_run_send",
                                        return_value=(True, None, None)), \
             unittest.mock.patch.object(secret_drop.os, "unlink",
                                        side_effect=KeyboardInterrupt()):
            code, out, err = self.open_in_process()
        self.assertEqual(code, 130)
        self.assertEqual(err, "secret-drop: interrupted\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")

    def test_cleanup_first_unlink_interrupt_reports_interrupted(self):
        calls = []
        real_unlink = os.unlink

        def flaky_unlink(path, *args, **kwargs):
            if os.path.basename(os.fspath(path)).startswith("send-"):
                calls.append(path)
                if len(calls) == 1:
                    raise KeyboardInterrupt()
            return real_unlink(path, *args, **kwargs)

        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_run_send",
                                        return_value=(True, None, None)), \
             unittest.mock.patch.object(secret_drop.os, "unlink",
                                        side_effect=flaky_unlink):
            code, out, err = self.open_in_process()
        self.assertEqual(code, 130)
        self.assertEqual(err, "secret-drop: interrupted\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])

    def test_cleanup_lstat_interrupt_reports_interrupted(self):
        real_lstat = os.lstat

        def flaky_lstat(path, *args, **kwargs):
            if os.path.basename(os.fspath(path)).startswith("send-"):
                raise KeyboardInterrupt()
            return real_lstat(path, *args, **kwargs)

        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_run_send",
                                        return_value=(True, None, None)), \
             unittest.mock.patch.object(secret_drop.os, "lstat",
                                        side_effect=flaky_lstat):
            code, out, err = self.open_in_process()
        self.assertEqual(code, 130)
        self.assertEqual(err, "secret-drop: interrupted\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])

    def test_cleanup_oserror_keeps_exit_cleanup(self):
        real_unlink = os.unlink

        def fail_unlink(path, *args, **kwargs):
            if os.path.basename(os.fspath(path)).startswith("send-"):
                raise OSError("denied")
            return real_unlink(path, *args, **kwargs)

        with unittest.mock.patch.object(secret_drop, "_wait_served",
                                        return_value=True), \
             unittest.mock.patch.object(secret_drop, "_run_send",
                                        return_value=(True, None, None)), \
             unittest.mock.patch.object(secret_drop.os, "unlink",
                                        side_effect=fail_unlink):
            code, out, err = self.open_in_process()
        self.assertEqual(code, 1)
        self.assertEqual(err,
                         "secret-drop: send_failed (exit cleanup)\n")
        self.assertEqual(out, "")
        record = self.read_record("page")
        self.assertEqual(record["state"], "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, ["send-%s.html" % record["slot_id"]])

    def test_late_handshake_never_sends(self):
        ticks = iter([100.0, 101.0, 101.0, 106.0])

        def fake_monotonic():
            try:
                return next(ticks)
            except StopIteration:
                return 200.0

        with unittest.mock.patch.object(secret_drop.time, "monotonic",
                                        side_effect=fake_monotonic), \
             unittest.mock.patch.object(secret_drop, "_is_served",
                                        side_effect=[False, True]), \
             unittest.mock.patch.object(secret_drop, "_start_unit"), \
             unittest.mock.patch.object(secret_drop,
                                        "_run_send") as run_send:
            code, out, err = self.open_in_process()
        self.assertEqual(code, 1)
        self.assertEqual(err, "secret-drop: server_not_running\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        run_send.assert_not_called()

    def test_send_spawn_failure_cancels_slot(self):
        for suffix, effect in (
                ("a", OSError("boom")),
                ("b", [KeyboardInterrupt(), None])):
            with self.subTest(wait=suffix):
                name = "page-" + suffix
                child = unittest.mock.Mock()
                child.pid = 12345
                child.wait.side_effect = effect
                with unittest.mock.patch.object(
                        secret_drop, "_wait_served",
                        return_value=True), \
                     unittest.mock.patch.object(
                        secret_drop.subprocess, "Popen",
                        return_value=child), \
                     unittest.mock.patch.object(
                        secret_drop.os, "killpg") as killpg:
                    code, out, err = self.open_in_process(name=name)
                if suffix == "b":
                    self.assertEqual(code, 130)
                    self.assertEqual(err, "secret-drop: interrupted\n")
                    killpg.assert_called_once_with(12345, signal.SIGKILL)
                else:
                    self.assertEqual(code, 1)
                    self.assertEqual(
                        err, "secret-drop: send_failed (exit error)\n")
                    killpg.assert_not_called()
                self.assertEqual(out, "")
                self.assertEqual(self.read_record(name)["state"],
                                 "cancelled")
                left = [entry for entry in os.listdir(self.slots)
                        if entry.startswith("send-")]
                self.assertEqual(left, [])

    def test_interrupted_open_cancels_slot(self):
        env = self.make_env(SD_TEST_SYSTEMCTL_NOOP="1")
        proc = subprocess.Popen(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "open", "--name", "page",
             "--file", self.target("token"),
             "--reason", "rotation"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(self.tmp), env=env)
        time.sleep(1.0)
        proc.send_signal(signal.SIGINT)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate(timeout=10)
            self.fail("open did not exit after SIGINT")
        self.assertEqual(proc.returncode, 130)
        self.assertEqual(err, "secret-drop: interrupted\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")

    def test_send_ctrl_c_interrupts_open(self):
        env = self.make_env(SD_TEST_SEND_BLOCK="1")
        proc = subprocess.Popen(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "open", "--name", "page",
             "--file", self.target("token"),
             "--reason", "rotation"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(self.tmp), env=env)
        log = Path(env["SD_TEST_SEND_LOG"])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if log.stat().st_size > 0:
                    break
            except OSError:
                pass
            time.sleep(0.05)
        else:
            proc.kill()
            self.fail("send did not start before SIGINT")
        proc.send_signal(signal.SIGINT)
        try:
            out, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate(timeout=30)
            self.fail("open did not exit after SIGINT")
        self.assertEqual(proc.returncode, 130)
        self.assertEqual(err, "secret-drop: interrupted\n")
        self.assertEqual(out, "")
        self.assertEqual(self.read_record("page")["state"], "cancelled")
        left = [entry for entry in os.listdir(self.slots)
                if entry.startswith("send-")]
        self.assertEqual(left, [])


if __name__ == "__main__":
    unittest.main()
