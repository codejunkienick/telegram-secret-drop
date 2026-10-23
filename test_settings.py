"""Tests for secret_drop.py: settings, target rules and the owner-only writer.

Fake-only: every settings file lives in a temporary directory outside any
git tree, values are placeholders like fake-value-123, and no test touches
the network or starts a unit.
"""

import dataclasses
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
import unittest.mock
from pathlib import Path

import secret_drop
from secret_drop import (
    SettingsError,
    TargetError,
    check_target,
    load_settings,
    write_secret,
)

ROOT = Path(__file__).resolve().parent
SECRET_DROP = str(ROOT / "secret_drop.py")
EXAMPLE = ROOT / "settings.example.toml"

OWNER_ONLY_FILE = "settings: must be an owner-only regular file (chmod 600)"
LAN_MESSAGE = "settings: lan_address must be a LAN, VPN or loopback address"
PORT_MESSAGE = "settings: port must be an integer from 1024 to 65535"
LIST_MESSAGE = "settings: allowed_dirs must be a list of 1 to 32 paths"
ABS_MESSAGE = "settings: allowed_dirs must be absolute normalized paths"
CHARSET_MESSAGE = ("settings: allowed_dirs must use only letters,"
                   " digits and . _ @ + / -")
SYMLINK_MESSAGE = "settings: allowed_dirs must not contain a symlink"
EXIST_MESSAGE = "settings: allowed_dirs must be existing owner-only directories"
UNIT_MESSAGE = "settings: unit must be a name ending in .service"

MARKER = "FAKE-MARKER-7QZ-no-secret"


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


class TempCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="sd-test-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.allowed = self.tmp / "allowed"
        self.allowed.mkdir(mode=0o700)
        self.allowed_str = str(self.allowed)

    def write_raw(self, text, name="settings.toml"):
        path = self.tmp / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            data = text.encode("utf-8")
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)
        return str(path)

    def write_settings(self, values, name="settings.toml"):
        return self.write_raw(
            "".join("%s = %s\n" % (k, _toml(v)) for k, v in values.items()),
            name)

    def base_values(self, **overrides):
        values = {
            "lan_address": "192.168.1.20",
            "port": 18001,
            "allowed_dirs": [self.allowed_str],
        }
        values.update(overrides)
        return values

    def load(self, values, name="settings.toml"):
        return load_settings(self.write_settings(values, name))

    def load_base(self, **overrides):
        return self.load(self.base_values(**overrides))

    def assertSettingsError(self, message, values, name="settings.toml"):
        with self.assertRaises(SettingsError) as ctx:
            self.load(values, name)
        self.assertEqual(str(ctx.exception), message)

    def assertTargetError(self, code, func, *args):
        with self.assertRaises(TargetError) as ctx:
            func(*args)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(str(ctx.exception), code)

    def assertNoTempFiles(self, directory):
        left = [e for e in os.listdir(str(directory))
                if e.startswith(".secret-drop-")]
        self.assertEqual(left, [])


class ExampleTest(TempCase):
    def example_table(self):
        lines = []
        for line in EXAMPLE.read_text().splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                body = stripped[1:].lstrip()
                if re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*=", body):
                    lines.append(body)
            else:
                lines.append(line)
        return tomllib.loads("\n".join(lines) + "\n")

    def test_keys_match_loader(self):
        self.assertEqual(set(self.example_table()),
                         set(secret_drop._KNOWN_KEYS))

    def test_commented_defaults_match_loader(self):
        table = self.example_table()
        settings = self.load_base()
        self.assertEqual(settings.slots_dir,
                         os.path.expanduser(table["slots_dir"]))
        self.assertEqual(list(settings.send_command), table["send_command"])
        self.assertEqual(settings.unit, table["unit"])
        self.assertEqual(settings.python, table["python"])


class LoadValidTest(TempCase):
    def test_full_file_loads(self):
        slots = str(self.tmp / "slots")
        values = self.base_values(
            lan_address="127.0.0.1",
            port=18002,
            slots_dir=slots,
            send_command=["gc", "telegram", "reply-current"],
            unit="secret-drop.service",
            python="/usr/bin/python3",
        )
        path = self.write_settings(values)
        settings = load_settings(path)
        self.assertEqual(settings.lan_address, "127.0.0.1")
        self.assertEqual(settings.port, 18002)
        self.assertEqual(settings.allowed_dirs, (self.allowed_str,))
        self.assertEqual(settings.slots_dir, slots)
        self.assertEqual(settings.send_command,
                         ("gc", "telegram", "reply-current"))
        self.assertEqual(settings.unit, "secret-drop.service")
        self.assertEqual(settings.python, "/usr/bin/python3")
        self.assertEqual(settings.settings_path, path)
        self.assertTrue(os.path.isabs(settings.settings_path))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            settings.port = 1

    def test_defaults_apply(self):
        settings = self.load_base()
        self.assertEqual(settings.slots_dir,
                         os.path.expanduser("~/.local/state/secret-drop"))
        self.assertEqual(settings.send_command,
                         ("gc", "telegram", "reply-current"))
        self.assertEqual(settings.unit, "secret-drop.service")
        self.assertEqual(settings.python, "/usr/bin/python3")

    def test_env_var_selects_file(self):
        path = self.write_settings(self.base_values())
        with unittest.mock.patch.dict(os.environ,
                                      {"SECRET_DROP_SETTINGS": path}):
            self.assertEqual(load_settings().settings_path, path)

    def test_missing_file_refuses(self):
        with self.assertRaises(SettingsError) as ctx:
            load_settings(str(self.tmp / "absent.toml"))
        self.assertEqual(str(ctx.exception),
                         "settings: cannot open settings file")

    def test_missing_required_key(self):
        for key in ("lan_address", "port", "allowed_dirs"):
            with self.subTest(key=key):
                values = self.base_values()
                del values[key]
                self.assertSettingsError(
                    "settings: missing required key %s" % key, values)


class LoadRefusalTest(TempCase):
    def test_mode_0644_refuses(self):
        path = self.write_settings(self.base_values())
        os.chmod(path, 0o644)
        with self.assertRaises(SettingsError) as ctx:
            load_settings(path)
        self.assertEqual(str(ctx.exception), OWNER_ONLY_FILE)

    def test_symlinked_settings_refuses(self):
        path = self.write_settings(self.base_values())
        link = str(self.tmp / "link.toml")
        os.symlink(path, link)
        with self.assertRaises(SettingsError) as ctx:
            load_settings(link)
        self.assertEqual(str(ctx.exception), OWNER_ONLY_FILE)

    def test_unknown_key_refuses(self):
        values = self.base_values(extra_key=1)
        self.assertSettingsError("settings: unknown key extra_key", values)

    def test_unknown_key_with_newline_stays_one_line(self):
        text = (
            'lan_address = "192.168.1.20"\n'
            "port = 18001\n"
            "allowed_dirs = [" + _toml(self.allowed_str) + "]\n"
            '"bad\\nkey" = 1\n'
        )
        path = self.write_raw(text)
        with self.assertRaises(SettingsError) as ctx:
            load_settings(path)
        self.assertEqual(str(ctx.exception), "settings: unknown key")
        self.assertNotIn("\n", str(ctx.exception))

    def test_bad_toml_refuses(self):
        path = self.write_raw("lan_address = = =\n")
        with self.assertRaises(SettingsError) as ctx:
            load_settings(path)
        self.assertEqual(str(ctx.exception), "settings: not valid TOML")

    def test_lan_address_refusals(self):
        for lan in ("8.8.8.8", "0.0.0.0", "224.0.0.1", "not-an-address"):
            with self.subTest(lan=lan):
                self.assertSettingsError(
                    LAN_MESSAGE, self.base_values(lan_address=lan))

    def test_lan_address_type_refuses(self):
        self.assertSettingsError(
            "settings: lan_address must be an IP address string",
            self.base_values(lan_address=12345))

    def test_port_refusals(self):
        for port in (80, 70000, True):
            with self.subTest(port=port):
                self.assertSettingsError(
                    PORT_MESSAGE, self.base_values(port=port))

    def test_allowed_dirs_container_refusals(self):
        self.assertSettingsError(LIST_MESSAGE,
                                 self.base_values(allowed_dirs=[]))
        self.assertSettingsError(
            LIST_MESSAGE, self.base_values(allowed_dirs=[self.allowed_str] * 33))
        self.assertSettingsError(
            LIST_MESSAGE, self.base_values(allowed_dirs=[self.allowed_str, 7]))

    def test_allowed_dirs_entry_refusals(self):
        self.assertSettingsError(
            ABS_MESSAGE, self.base_values(allowed_dirs=["relative/path"]))
        self.assertSettingsError(
            ABS_MESSAGE,
            self.base_values(allowed_dirs=[self.allowed_str + "/x/.."]))
        missing = str(self.tmp / "missing")
        self.assertSettingsError(
            EXIST_MESSAGE, self.base_values(allowed_dirs=[missing]))
        group = self.tmp / "group"
        group.mkdir(mode=0o700)
        os.chmod(group, 0o770)
        self.assertSettingsError(
            EXIST_MESSAGE, self.base_values(allowed_dirs=[str(group)]))
        real = self.tmp / "real"
        real.mkdir(mode=0o700)
        link = self.tmp / "link"
        os.symlink(str(real), str(link))
        self.assertSettingsError(
            SYMLINK_MESSAGE, self.base_values(allowed_dirs=[str(link)]))
        spaced = self.allowed_str + "/has space"
        self.assertSettingsError(
            CHARSET_MESSAGE, self.base_values(allowed_dirs=[spaced]))
        self.assertSettingsError(
            "settings: allowed_dirs must not repeat a directory",
            self.base_values(allowed_dirs=[self.allowed_str] * 2))
        plain = self.tmp / "plain"
        plain.write_bytes(b"fake-value-123")
        self.assertSettingsError(
            EXIST_MESSAGE, self.base_values(allowed_dirs=[str(plain)]))

    def test_unit_refusals(self):
        for unit in ("plain-name", "secret-drop.timer", 5):
            with self.subTest(unit=unit):
                self.assertSettingsError(UNIT_MESSAGE,
                                         self.base_values(unit=unit))

    def test_optional_path_refusals(self):
        self.assertSettingsError(
            "settings: slots_dir must be an absolute normalized path",
            self.base_values(slots_dir="relative/slots"))
        self.assertSettingsError(
            "settings: python must be an absolute normalized path",
            self.base_values(python="relative/python"))

    def test_send_command_refusals(self):
        message = "settings: send_command must be a list of 1 to 16 words"
        self.assertSettingsError(message, self.base_values(send_command=[]))
        self.assertSettingsError(message, self.base_values(send_command=[""]))
        self.assertSettingsError(
            message, self.base_values(send_command=["a\0b"]))
        self.assertSettingsError(
            message, self.base_values(send_command=["w"] * 17))

    def test_distinctive_value_never_echoed(self):
        with self.assertRaises(SettingsError) as ctx:
            self.load(self.base_values(lan_address="not-an-ip-" + MARKER))
        self.assertEqual(str(ctx.exception), LAN_MESSAGE)
        self.assertNotIn(MARKER, str(ctx.exception))
        with self.assertRaises(SettingsError) as ctx:
            self.load(self.base_values(unit=MARKER + ".timer!"))
        self.assertEqual(str(ctx.exception), UNIT_MESSAGE)
        self.assertNotIn(MARKER, str(ctx.exception))
        with self.assertRaises(SettingsError) as ctx:
            self.load(self.base_values(mystery="value-" + MARKER))
        self.assertEqual(str(ctx.exception), "settings: unknown key mystery")
        self.assertNotIn(MARKER, str(ctx.exception))
        with self.assertRaises(SettingsError) as ctx:
            self.load(self.base_values(
                allowed_dirs=[self.allowed_str + "/" + MARKER + " bad"]))
        self.assertEqual(str(ctx.exception), CHARSET_MESSAGE)
        self.assertNotIn(MARKER, str(ctx.exception))


class CheckTargetTest(TempCase):
    def setUp(self):
        super().setUp()
        self.settings = self.load_base()

    def target(self, *parts):
        return str(self.allowed.joinpath(*parts))

    def test_inside(self):
        (self.allowed / "sub").mkdir(mode=0o700)
        self.assertEqual(
            check_target(self.settings, self.target("sub", "secret.txt"), False),
            (self.allowed_str, ("sub",), "secret.txt"))
        deep = self.allowed / "a" / "b"
        deep.mkdir(mode=0o700, parents=True)
        self.assertEqual(
            check_target(self.settings, self.target("a", "b", "f"), False),
            (self.allowed_str, ("a", "b"), "f"))

    def test_at_allowed_root(self):
        self.assertEqual(
            check_target(self.settings, self.target("f"), False),
            (self.allowed_str, (), "f"))

    def test_outside(self):
        self.assertTargetError("target_outside_allowed_dirs", check_target,
                               self.settings, str(self.tmp / "elsewhere" / "f"),
                               False)
        self.assertTargetError("target_outside_allowed_dirs", check_target,
                               self.settings, self.allowed_str, False)

    def test_not_absolute(self):
        self.assertTargetError("target_not_absolute", check_target,
                               self.settings, "relative/target.txt", False)

    def test_bad_path(self):
        self.assertTargetError("target_bad_path", check_target,
                               self.settings,
                               self.allowed_str + "/sub/../evil", False)
        self.assertTargetError("target_bad_path", check_target,
                               self.settings, self.target("has space"), False)
        self.assertTargetError("target_bad_path", check_target,
                               self.settings,
                               self.target(".secret-drop-zzz"), False)

    def test_missing_parent(self):
        self.assertTargetError("parent_missing", check_target,
                               self.settings, self.target("nope", "f"), False)

    def test_symlinked_subdir(self):
        real = self.allowed / "real"
        real.mkdir(mode=0o700)
        os.symlink(str(real), str(self.allowed / "link"))
        self.assertTargetError("parent_changed", check_target,
                               self.settings, self.target("link", "f"), False)

    def test_group_writable_subdir(self):
        sub = self.allowed / "sub"
        sub.mkdir(mode=0o700)
        os.chmod(sub, 0o770)
        self.addCleanup(os.chmod, sub, 0o700)
        self.assertTargetError("parent_changed", check_target,
                               self.settings, self.target("sub", "f"), False)

    def test_group_writable_allowed_dir(self):
        (self.allowed / "sub").mkdir(mode=0o700)
        os.chmod(self.allowed, 0o770)
        self.addCleanup(os.chmod, self.allowed, 0o700)
        self.assertTargetError("parent_changed", check_target,
                               self.settings, self.target("f"), False)
        self.assertTargetError("parent_changed", check_target,
                               self.settings, self.target("sub", "f"), False)
        self.assertTargetError("parent_changed", write_secret,
                               self.settings, self.target("f"),
                               False, b"fake-value-123")
        self.assertTargetError("parent_changed", write_secret,
                               self.settings, self.target("sub", "f"),
                               False, b"fake-value-123")
        self.assertFalse((self.allowed / "f").exists())
        self.assertNoTempFiles(self.allowed)

    def test_symlink_target(self):
        real = self.allowed / "real"
        real.write_bytes(b"fake-value-123")
        os.symlink(str(real), str(self.allowed / "alias"))
        self.assertTargetError("target_not_regular", check_target,
                               self.settings, self.target("alias"), False)

    def test_directory_target(self):
        (self.allowed / "sub").mkdir(mode=0o700)
        self.assertTargetError("target_not_regular", check_target,
                               self.settings, self.target("sub"), False)

    def test_fifo_target(self):
        os.mkfifo(self.target("pipe"))
        self.assertTargetError("target_not_regular", check_target,
                               self.settings, self.target("pipe"), False)

    def test_existing_file(self):
        path = self.target("f")
        Path(path).write_bytes(b"old-bytes")
        self.assertTargetError("target_exists", check_target,
                               self.settings, path, False)
        self.assertEqual(check_target(self.settings, path, True),
                         (self.allowed_str, (), "f"))


class WriteSecretTest(TempCase):
    def setUp(self):
        super().setUp()
        self.settings = self.load_base()

    def test_writes_exact_bytes_owner_only(self):
        path = str(self.allowed / "token")
        count = write_secret(self.settings, path, False, b"fake-value-123")
        self.assertEqual(count, 14)
        self.assertEqual(Path(path).read_bytes(), b"fake-value-123")
        found = os.stat(path)
        self.assertEqual(stat.S_IMODE(found.st_mode), 0o600)
        self.assertEqual(found.st_uid, os.getuid())
        self.assertNoTempFiles(self.allowed)

    def test_replace_needs_overwrite(self):
        path = str(self.allowed / "token")
        Path(path).write_bytes(b"old-bytes")
        self.assertTargetError("target_exists", write_secret,
                               self.settings, path, False, b"fake-value-123")
        self.assertEqual(Path(path).read_bytes(), b"old-bytes")
        count = write_secret(self.settings, path, True, b"fake-value-123")
        self.assertEqual(count, 14)
        self.assertEqual(Path(path).read_bytes(), b"fake-value-123")
        self.assertNoTempFiles(self.allowed)

    def test_symlink_target_refused(self):
        real = self.allowed / "real"
        real.write_bytes(b"keep-me")
        link = str(self.allowed / "alias")
        os.symlink(str(real), link)
        self.assertTargetError("target_not_regular", write_secret,
                               self.settings, link, False, b"fake-value-123")
        self.assertEqual(real.read_bytes(), b"keep-me")
        self.assertNoTempFiles(self.allowed)

    def test_fifo_target_refused(self):
        os.mkfifo(str(self.allowed / "pipe"))
        self.assertTargetError("target_not_regular", write_secret,
                               self.settings, str(self.allowed / "pipe"),
                               False, b"fake-value-123")
        self.assertNoTempFiles(self.allowed)

    def test_read_only_parent(self):
        sub = self.allowed / "ro"
        sub.mkdir(mode=0o700)
        os.chmod(sub, 0o500)
        self.addCleanup(os.chmod, sub, 0o700)
        value = b"fake-value-123-" + MARKER.encode()
        with self.assertRaises(TargetError) as ctx:
            write_secret(self.settings, str(sub / "f"), False, value)
        self.assertEqual(ctx.exception.code, "parent_changed")
        self.assertEqual(str(ctx.exception), "parent_changed")
        self.assertNotIn(MARKER, str(ctx.exception))
        self.assertFalse((sub / "f").exists())
        self.assertNoTempFiles(sub)

    def test_rejects_text_value(self):
        with self.assertRaises(TypeError):
            write_secret(self.settings, str(self.allowed / "f"),
                         False, "fake-value-123")


class CheckCommandTest(TempCase):
    def run_check(self, *args):
        return subprocess.run(
            [sys.executable, SECRET_DROP, *args],
            cwd=str(self.tmp), capture_output=True, text=True, timeout=60)

    def test_check_ok(self):
        path = self.write_settings(self.base_values())
        proc = self.run_check("--settings", path, "check")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(
            proc.stdout,
            "settings ok\nunit=secret-drop.service\nslots_dir=%s\npython=%s\n"
            % (os.path.expanduser("~/.local/state/secret-drop"),
               "/usr/bin/python3"))
        self.assertEqual(proc.stderr, "")

    def test_check_prints_unit_python(self):
        path = self.write_settings(
            self.base_values(python=sys.executable))
        proc = self.run_check("--settings", path, "check")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(
            proc.stdout,
            "settings ok\nunit=secret-drop.service\nslots_dir=%s\npython=%s\n"
            % (os.path.expanduser("~/.local/state/secret-drop"),
               sys.executable))
        self.assertEqual(proc.stderr, "")

    def test_check_bad_file(self):
        path = self.write_settings(self.base_values(port=80))
        proc = self.run_check("--settings", path, "check")
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(proc.stderr.startswith("secret-drop: settings: "),
                        proc.stderr)
        self.assertIn(PORT_MESSAGE, proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_check_usage_error(self):
        path = self.write_settings(self.base_values())
        proc = self.run_check("--settings", path)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
