"""Tests for the slot records and the open, status, cancel, list commands.

Fake-only: every settings file and slot record lives in a temporary
directory outside any git tree, values are placeholders like
fake-value-123, and no test touches the network or starts a unit.
"""

import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from datetime import datetime
from pathlib import Path

_FAKE_CTL = """\
#!/usr/bin/env python3
import os
import subprocess
import sys


def main():
    if sys.argv[1:3] != ["--user", "start"]:
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

import secret_drop
from secret_drop import (
    SlotError,
    TargetError,
    ensure_slots_dir,
    find_open_by_token,
    finish,
    load_settings,
    new_slot,
)

ROOT = Path(__file__).resolve().parent
SECRET_DROP = str(ROOT / "secret_drop.py")

NOW = 1760000000
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{43}")
RUN_LIKE = re.compile(r"[A-Za-z0-9_-]{8,}")


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


class SlotCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="sd-test-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.allowed = self.tmp / "allowed"
        self.allowed.mkdir(mode=0o700)
        self.allowed_str = str(self.allowed)
        self.slots = str(self.tmp / "slots")

    def write_settings(self, values, name="settings.toml"):
        path = self.tmp / name
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
        return str(path)

    def base_values(self, **overrides):
        values = {
            "lan_address": "192.168.1.20",
            "port": 18001,
            "allowed_dirs": [self.allowed_str],
            "slots_dir": self.slots,
        }
        values.update(overrides)
        return values

    def base_settings(self, **overrides):
        return load_settings(self.write_settings(self.base_values(**overrides)))

    def assertSlotError(self, code, func, *args, **kwargs):
        with self.assertRaises(SlotError) as ctx:
            func(*args, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(str(ctx.exception), code)

    def assertTargetError(self, code, func, *args, **kwargs):
        with self.assertRaises(TargetError) as ctx:
            func(*args, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(str(ctx.exception), code)

    def record_file(self, name):
        return Path(self.slots) / (name + ".json")

    def read_record_file(self, name):
        return json.loads(self.record_file(name).read_text())


class EnsureSlotsDirTest(SlotCase):
    def test_creates_owner_only(self):
        settings = self.base_settings()
        self.assertEqual(ensure_slots_dir(settings), self.slots)
        found = os.stat(self.slots)
        self.assertEqual(stat.S_IMODE(found.st_mode), 0o700)
        self.assertEqual(found.st_uid, os.getuid())

    def test_refuses_symlink(self):
        real = self.tmp / "real"
        real.mkdir(mode=0o700)
        link = self.tmp / "link"
        os.symlink(str(real), str(link))
        settings = self.base_settings(slots_dir=str(link))
        self.assertSlotError("slots_dir_unsafe", ensure_slots_dir, settings)

    def test_refuses_group_readable(self):
        os.mkdir(self.slots, 0o700)
        os.chmod(self.slots, 0o750)
        settings = self.base_settings()
        self.assertSlotError("slots_dir_unsafe", ensure_slots_dir, settings)

    def test_refuses_file(self):
        Path(self.slots).write_bytes(b"fake-value-123")
        settings = self.base_settings()
        self.assertSlotError("slots_dir_unsafe", ensure_slots_dir, settings)

    def test_missing_parent(self):
        settings = self.base_settings(
            slots_dir=str(self.tmp / "noparent" / "slots"))
        self.assertSlotError("slots_dir_unsafe", ensure_slots_dir, settings)


class NewSlotTest(SlotCase):
    def setUp(self):
        super().setUp()
        self.settings = self.base_settings()

    def target(self, *parts):
        return str(self.allowed.joinpath(*parts))

    def test_record_shape_and_secrecy(self):
        record, token = new_slot(self.settings, "alpha",
                                 self.target("token"), "why", 10,
                                 False, False, now=NOW)
        self.assertEqual(len(token), 43)
        self.assertTrue(TOKEN_LIKE.fullmatch(token))
        self.assertEqual(set(record), set(secret_drop._RECORD_KEYS))
        self.assertEqual(record["name"], "alpha")
        self.assertEqual(record["target"], self.target("token"))
        self.assertEqual(record["reason"], "why")
        self.assertTrue(re.fullmatch(r"[0-9a-f]{16}", record["slot_id"]))
        self.assertEqual(record["token_sha256"],
                         hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(record["created_at"], NOW)
        self.assertEqual(record["expires_at"], NOW + 600)
        self.assertIsNone(record["finished_at"])
        self.assertIs(record["overwrite"], False)
        self.assertEqual(record["state"], "open")
        self.assertIsNone(record["length"])
        self.assertIsNone(record["error"])
        raw = self.record_file("alpha").read_bytes()
        found = os.stat(self.record_file("alpha"))
        self.assertEqual(stat.S_IMODE(found.st_mode), 0o600)
        text = raw.decode("utf-8")
        self.assertNotIn(token, text)
        self.assertIn(record["token_sha256"], text)

    def test_find_open_by_token(self):
        record, token = new_slot(self.settings, "alpha",
                                 self.target("token"), "", 10,
                                 False, False, now=NOW)
        found = find_open_by_token(self.settings, token, now=NOW)
        self.assertIsNotNone(found)
        self.assertEqual(found["name"], "alpha")
        self.assertEqual(find_open_by_token(
            self.settings, "A" * 43, now=NOW), None)
        self.assertEqual(find_open_by_token(
            self.settings, "not-a-token", now=NOW), None)
        self.assertEqual(find_open_by_token(
            self.settings, None, now=NOW), None)

    def test_malformed_token_reads_nothing(self):
        settings = self.base_settings(
            slots_dir=str(self.tmp / "noparent" / "slots"))
        self.assertEqual(find_open_by_token(settings, "!!!", now=NOW), None)

    def test_cancelled_token_not_found(self):
        _record, token = new_slot(self.settings, "alpha",
                                  self.target("token"), "", 10,
                                  False, False, now=NOW)
        finish(self.settings, "alpha", "cancelled", now=NOW)
        self.assertEqual(find_open_by_token(
            self.settings, token, now=NOW), None)

    def test_compare_runs_for_every_open_record(self):
        tokens = []
        for name in ("one", "two", "three"):
            _record, token = new_slot(self.settings, name,
                                      self.target("f-" + name), "", 10,
                                      False, False, now=NOW)
            tokens.append(token)
        real_compare = secret_drop.hmac.compare_digest
        calls = []

        def counting(first, second):
            calls.append(first)
            return real_compare(first, second)

        for token in tokens:
            del calls[:]
            with unittest.mock.patch.object(
                    secret_drop.hmac, "compare_digest", counting):
                found = find_open_by_token(self.settings, token, now=NOW)
            self.assertIsNotNone(found)
            self.assertEqual(found["token_sha256"],
                             hashlib.sha256(token.encode()).hexdigest())
            self.assertEqual(len(calls), 3)

    def test_expiry_by_later_now(self):
        record, token = new_slot(self.settings, "alpha",
                                 self.target("token"), "", 10,
                                 False, False, now=NOW)
        self.assertEqual(find_open_by_token(
            self.settings, token, now=record["expires_at"]), None)
        saved = self.read_record_file("alpha")
        self.assertEqual(saved["state"], "expired")
        self.assertEqual(saved["finished_at"], record["expires_at"])
        self.assertSlotError("slot_not_open", finish,
                             self.settings, "alpha", "stored",
                             length=1, now=record["expires_at"])

    def test_slot_open_and_replace(self):
        _old, old_token = new_slot(self.settings, "alpha",
                                   self.target("one"), "", 10,
                                   False, False, now=NOW)
        self.assertSlotError("slot_open", new_slot,
                             self.settings, "alpha", self.target("one"),
                             "", 10, False, False, now=NOW)
        _new, new_token = new_slot(self.settings, "alpha",
                                   self.target("one"), "", 10,
                                   False, True, now=NOW)
        self.assertNotEqual(new_token, old_token)
        self.assertEqual(find_open_by_token(
            self.settings, old_token, now=NOW), None)
        found = find_open_by_token(self.settings, new_token, now=NOW)
        self.assertIsNotNone(found)
        self.assertEqual(found["name"], "alpha")

    def test_target_in_use(self):
        new_slot(self.settings, "one", self.target("same"), "", 10,
                 False, False, now=NOW)
        self.assertSlotError("target_in_use", new_slot,
                             self.settings, "two", self.target("same"),
                             "", 10, False, False, now=NOW)

    def test_bad_inputs(self):
        for name in ("", "Bad", "-x", "has space", "a" * 65):
            with self.subTest(name=name):
                self.assertSlotError("bad_name", new_slot,
                                     self.settings, name, self.target("f"),
                                     "", 10, False, False, now=NOW)
        for reason in ("x" * 201, "line\nbreak", 5):
            with self.subTest(reason=reason):
                self.assertSlotError("bad_reason", new_slot,
                                     self.settings, "alpha",
                                     self.target("f"), reason, 10,
                                     False, False, now=NOW)
        for ttl in (0, 31, True, "10"):
            with self.subTest(ttl=ttl):
                self.assertSlotError("bad_ttl", new_slot,
                                     self.settings, "alpha",
                                     self.target("f"), "", ttl,
                                     False, False, now=NOW)

    def test_target_errors_pass_through(self):
        (self.allowed / "busy").write_bytes(b"old-bytes")
        os.mkfifo(self.target("pipe"))
        real = self.allowed / "real"
        real.mkdir(mode=0o700)
        os.symlink(str(real), str(self.allowed / "link"))
        cases = [
            ("relative/target.txt", "target_not_absolute"),
            (self.allowed_str + "/sub/../evil", "target_bad_path"),
            (str(self.tmp / "elsewhere" / "f"), "target_outside_allowed_dirs"),
            (self.target("nope", "f"), "parent_missing"),
            (self.target("link", "f"), "parent_changed"),
            (self.target("busy"), "target_exists"),
            (self.target("pipe"), "target_not_regular"),
        ]
        for index, (target, code) in enumerate(cases):
            with self.subTest(code=code):
                self.assertTargetError(code, new_slot,
                                       self.settings, "name%d" % index,
                                       target, "", 10, False, False, now=NOW)

    def test_finished_replaced_by_new_open(self):
        old, _token = new_slot(self.settings, "again",
                               self.target("token"), "", 10,
                               False, False, now=NOW)
        finish(self.settings, "again", "stored", length=14, now=NOW)
        new, _token = new_slot(self.settings, "again",
                               self.target("token"), "", 10,
                               False, False, now=NOW)
        self.assertEqual(new["state"], "open")
        self.assertNotEqual(new["slot_id"], old["slot_id"])

    def test_prune_after_seven_days(self):
        new_slot(self.settings, "old", self.target("f-old"), "", 10,
                 False, False, now=NOW)
        finish(self.settings, "old", "stored", length=1, now=NOW)
        week = 7 * 86400
        new_slot(self.settings, "probe1", self.target("f-p1"), "", 10,
                 False, False, now=NOW + week)
        self.assertTrue(self.record_file("old").exists())
        new_slot(self.settings, "probe2", self.target("f-p2"), "", 10,
                 False, False, now=NOW + week + 1)
        self.assertFalse(self.record_file("old").exists())

    def test_finish_errors(self):
        self.assertSlotError("no_such_slot", finish,
                             self.settings, "missing", "cancelled", now=NOW)
        new_slot(self.settings, "done", self.target("f"), "", 10,
                 False, False, now=NOW)
        finish(self.settings, "done", "stored", length=3, now=NOW)
        self.assertSlotError("slot_not_open", finish,
                             self.settings, "done", "cancelled", now=NOW)
        with self.assertRaises(ValueError):
            finish(self.settings, "done", "open", now=NOW)
        with self.assertRaises(ValueError):
            finish(self.settings, "done", "stored", now=NOW)

    def test_finish_failed(self):
        new_slot(self.settings, "flop", self.target("f"), "", 10,
                 False, False, now=NOW)
        record = finish(self.settings, "flop", "failed",
                        error="target_exists", now=NOW)
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["error"], "target_exists")
        self.assertIsNone(record["length"])


class SubcommandTest(SlotCase):
    def setUp(self):
        super().setUp()
        self.settings_path = self.write_settings(self.base_values())

    def run_cli(self, *args, timeout=60, settings_path=None, env=None):
        return subprocess.run(
            [sys.executable, SECRET_DROP, "--settings",
             settings_path or self.settings_path, *args],
            cwd=str(self.tmp), capture_output=True, text=True,
            timeout=timeout, env=env)

    def target(self, *parts):
        return str(self.allowed.joinpath(*parts))

    def assertNoToken(self, output, token_sha256):
        self.assertIsNone(TOKEN_LIKE.search(output))
        for run in RUN_LIKE.findall(output):
            self.assertNotEqual(
                hashlib.sha256(run.encode()).hexdigest(), token_sha256)

    def test_open_output_has_no_token(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        bindir = self.tmp / "bin"
        bindir.mkdir(mode=0o700)
        ctl = bindir / "systemctl"
        ctl.write_text(_FAKE_CTL)
        os.chmod(ctl, 0o700)
        send = bindir / "send"
        send.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(send, 0o700)
        values = self.base_values(send_command=[str(send)],
                                    lan_address="127.0.0.1", port=port)
        path = self.write_settings(values, name="open.toml")
        env = dict(os.environ)
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        env["SD_TEST_SETTINGS"] = path
        env["SD_TEST_SECRET_DROP"] = SECRET_DROP
        env["SD_TEST_SERVER_ERR"] = str(self.tmp / "server.err")
        proc = self.run_cli("open", "--name", "web",
                            "--file", self.target("token"),
                            "--reason", "why", settings_path=path, env=env)
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        self.assertEqual(set(shown),
                         {"name", "state", "expires_at", "link"})
        self.assertEqual(shown["name"], "web")
        self.assertEqual(shown["state"], "open")
        self.assertEqual(shown["link"], "sent")
        record = self.read_record_file("web")
        self.assertEqual(shown["expires_at"], _iso(record["expires_at"]))
        self.assertNoToken(proc.stdout, record["token_sha256"])
        self.assertNoToken(proc.stderr, record["token_sha256"])
        self.assertEqual(proc.stderr, "")
        cancel = subprocess.run(
            [sys.executable, SECRET_DROP, "--settings", path,
             "cancel", "web"],
            capture_output=True, text=True, timeout=30,
            cwd=str(self.tmp), env=env)
        self.assertEqual(cancel.returncode, 0)
        deadline = time.monotonic() + 10
        while (Path(self.slots) / "server.json").exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)

    def test_open_bad_name(self):
        proc = self.run_cli("open", "--name", "Bad Name",
                            "--file", self.target("token"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: bad_name\n")
        self.assertEqual(proc.stdout, "")

    def test_status_codes(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "kept", self.target("f-kept"), "", 10,
                 False, False)
        finish(settings, "kept", "stored", length=5)
        new_slot(settings, "dropped", self.target("f-dropped"), "", 10,
                 False, False)
        finish(settings, "dropped", "cancelled")
        new_slot(settings, "waiting", self.target("f-waiting"), "", 10,
                 False, False)
        proc = self.run_cli("status", "kept")
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        self.assertEqual(set(shown), {"name", "state", "path", "length",
                                      "stored_at", "expires_at", "error"})
        self.assertEqual(shown["path"], self.target("f-kept"))
        self.assertEqual(shown["length"], 5)
        record = self.read_record_file("kept")
        self.assertEqual(shown["stored_at"],
                         _iso(record["finished_at"]))
        self.assertIsNone(shown["error"])
        proc = self.run_cli("status", "dropped")
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(json.loads(proc.stdout)["state"], "cancelled")
        proc = self.run_cli("status", "waiting", "--wait", "1")
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(json.loads(proc.stdout)["state"], "open")

    def test_status_expired(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "late", self.target("f-late"), "", 1,
                 False, False, now=NOW)
        proc = self.run_cli("status", "late")
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(json.loads(proc.stdout)["state"], "expired")

    def test_cancel(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "bye", self.target("token"), "", 10,
                 False, False)
        proc = self.run_cli("cancel", "bye")
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        self.assertEqual(shown["state"], "cancelled")
        self.assertIsNone(shown["stored_at"])
        proc = self.run_cli("status", "bye")
        self.assertEqual(proc.returncode, 3)

    def test_cancel_unwritable_slots_dir_is_internal_error(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "stuck", self.target("token"), "", 10,
                 False, False)
        self.addCleanup(os.chmod, self.slots, 0o700)
        os.chmod(self.slots, 0o500)
        proc = self.run_cli("cancel", "stuck")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: internal_error\n")
        self.assertEqual(proc.stdout, "")

    def test_list_sorted(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "b-two", self.target("f-b"), "", 10,
                 False, False)
        new_slot(settings, "a-one", self.target("f-a"), "", 10,
                 False, False)
        proc = self.run_cli("list")
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        self.assertEqual([item["name"] for item in shown],
                         ["a-one", "b-two"])
        for item in shown:
            self.assertEqual(set(item), {"name", "state", "expires_at"})

    def test_no_such_slot(self):
        proc = self.run_cli("status", "nope")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: no_such_slot\n")
        self.assertEqual(proc.stdout, "")

    def test_fifo_record_never_blocks(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "ok", self.target("f-ok"), "", 10,
                 False, False)
        os.mkfifo(os.path.join(self.slots, "stuck.json"))
        proc = self.run_cli("list", timeout=10)
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        by_name = {item["name"]: item for item in shown}
        self.assertEqual(set(by_name), {"ok", "stuck"})
        self.assertEqual(by_name["stuck"]["state"], "unreadable")
        self.assertEqual(set(by_name["stuck"]), {"name", "state"})
        proc = self.run_cli("status", "ok", timeout=10)
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(json.loads(proc.stdout)["state"], "open")
        proc = self.run_cli("status", "stuck", timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: slot_unreadable\n")

    def test_name_mismatch_refused(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "alpha", self.target("f-alpha"), "", 10,
                 False, False, now=NOW)
        raw = self.record_file("alpha").read_bytes()
        self.record_file("alpha").unlink()
        self.record_file("beta").write_bytes(raw)
        proc = self.run_cli("status", "beta")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: slot_unreadable\n")
        proc = self.run_cli("list")
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        self.assertEqual(shown, [{"name": "beta", "state": "unreadable"}])

    def test_epoch_out_of_range_refused(self):
        for stamp in (10 ** 25, -(10 ** 25)):
            with self.subTest(stamp=stamp):
                name = "huge" if stamp > 0 else "tiny"
                slots = str(self.tmp / ("slots-" + name))
                settings = self.base_settings(slots_dir=slots)
                new_slot(settings, name, self.target("f-" + name), "", 10,
                         False, False, now=stamp)
                path = self.write_settings(self.base_values(slots_dir=slots),
                                           name="settings-" + name + ".toml")
                proc = self.run_cli("status", name, settings_path=path)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(proc.stderr,
                                 "secret-drop: slot_unreadable\n")
                self.assertEqual(proc.stdout, "")
                self.assertNotIn("Traceback", proc.stderr)

    def test_wait_out_of_range(self):
        for wait in ("-1", "3601"):
            with self.subTest(wait=wait):
                proc = self.run_cli("status", "nope", "--wait", wait)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(proc.stderr, "secret-drop: bad_wait\n")
                self.assertEqual(proc.stdout, "")

    def test_symlink_and_directory_records_refused(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "victim", self.target("f-victim"), "", 10,
                 False, False, now=NOW)
        os.symlink(str(self.record_file("victim")),
                   str(self.record_file("alias")))
        os.mkdir(os.path.join(self.slots, "dir.json"))
        for name in ("alias", "dir"):
            with self.subTest(name=name):
                proc = self.run_cli("status", name)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(proc.stderr,
                                 "secret-drop: slot_unreadable\n")

    def test_malformed_and_oversized_records_refused(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "big", self.target("f-big"), "", 10,
                 False, False, now=NOW)
        self.record_file("bad").write_bytes(b"not json{{{")
        raw = self.record_file("big").read_bytes()
        self.record_file("big").write_bytes(raw + b" " * 20000)
        for name in ("bad", "big"):
            with self.subTest(name=name):
                proc = self.run_cli("status", name)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(proc.stderr,
                                 "secret-drop: slot_unreadable\n")
                self.assertEqual(proc.stdout, "")
                self.assertNotIn("Traceback", proc.stderr)

    def test_concurrent_writers_serialize(self):
        settings = load_settings(self.settings_path)
        barrier = threading.Barrier(8)
        errors = []
        made = {}

        def worker(index):
            name = "w%d" % index
            try:
                barrier.wait(timeout=30)
                _record, token = new_slot(settings, name,
                                          self.target("f-" + name), "", 10,
                                          False, False)
                made[name] = token
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(index,))
                   for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(made), 8)
        for name, token in made.items():
            found = find_open_by_token(settings, token)
            self.assertIsNotNone(found)
            self.assertEqual(found["name"], name)

    def test_crash_temp_not_counted(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "real", self.target("f-real"), "", 10,
                 False, False, now=NOW)
        leftover = os.path.join(self.slots, ".slot-deadbeef00000000.tmp")
        Path(leftover).write_bytes(b'{"name": "ghost"}')
        self.assertFalse(self.record_file("ghost").exists())
        proc = self.run_cli("list")
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        self.assertEqual([item["name"] for item in shown], ["real"])

    def test_corrupt_beside_good_lists_both(self):
        settings = load_settings(self.settings_path)
        new_slot(settings, "good", self.target("f-good"), "", 10,
                 False, False)
        self.record_file("bad").write_bytes(b"not json{{{")
        self.assertTrue(self.record_file("bad").exists())
        proc = self.run_cli("list")
        self.assertEqual(proc.returncode, 0)
        shown = json.loads(proc.stdout)
        by_name = {item["name"]: item for item in shown}
        self.assertEqual(set(by_name), {"good", "bad"})
        self.assertEqual(by_name["bad"], {"name": "bad",
                                          "state": "unreadable"})
        self.assertEqual(by_name["good"]["state"], "open")
        proc = self.run_cli("status", "good")
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(json.loads(proc.stdout)["state"], "open")
        new_slot(settings, "third", self.target("f-third"), "", 10,
                 False, False)
        self.assertTrue(self.record_file("third").exists())
        self.assertTrue(self.record_file("bad").exists())
        proc = self.run_cli("status", "bad")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: slot_unreadable\n")
        self.assertEqual(proc.stdout, "")
        proc = self.run_cli("cancel", "bad")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: slot_unreadable\n")


if __name__ == "__main__":
    unittest.main()
