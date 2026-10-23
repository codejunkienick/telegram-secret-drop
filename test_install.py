"""Tests for render-unit and install.sh. Fakes only: a temp HOME and
XDG_CONFIG_HOME, a settings file inside the temp tree, and a fake
systemctl first on PATH that only records its argv. No real HOME, no
real settings file, no systemctl, no network.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from testports import free_port

ROOT = Path(__file__).resolve().parent
SECRET_DROP = str(ROOT / "secret_drop.py")
INSTALL = str(ROOT / "install.sh")

UNIT_COMMENT = ("# Rendered by secret_drop.py render-unit through"
                " install.sh; do not edit.")

FAKE_SYSTEMCTL = """\
#!/usr/bin/env python3
import os
import sys


def main():
    with open(os.environ["SD_TEST_SYSLOG"], "a") as handle:
        handle.write(" ".join(sys.argv[1:]) + "\\n")
    return 0


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


class InstallCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="sd-test-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.home = self.tmp / "home"
        self.xdg = self.tmp / "xdg"
        self.home.mkdir(mode=0o700)
        self.allowed_one = self.home / "allowed-one"
        self.allowed_two = self.home / "allowed-two"
        self.allowed_one.mkdir(mode=0o700)
        self.allowed_two.mkdir(mode=0o700)
        self.slots = str(self.tmp / "slots")
        self.port = free_port()
        self.bindir = self.tmp / "bin"
        self.bindir.mkdir(mode=0o700)
        (self.bindir / "systemctl").write_text(FAKE_SYSTEMCTL)
        os.chmod(self.bindir / "systemctl", 0o700)
        self.syslog = str(self.tmp / "sys.log")
        self.write_settings(self.tmp / "settings.toml")

    def write_settings(self, path, **overrides):
        values = {
            "lan_address": "127.0.0.1",
            "port": self.port,
            "allowed_dirs": [str(self.allowed_one),
                             str(self.allowed_two)],
            "slots_dir": self.slots,
        }
        values.update(overrides)
        data = "".join(
            "%s = %s\n" % (key, _toml(value))
            for key, value in values.items()
        ).encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)
        self.settings_path = str(path)

    def make_env(self, **overrides):
        env = dict(os.environ)
        env["PATH"] = str(self.bindir) + os.pathsep + env.get("PATH", "")
        env["HOME"] = str(self.home)
        env["XDG_CONFIG_HOME"] = str(self.xdg)
        env["SD_TEST_SYSLOG"] = self.syslog
        env.update(overrides)
        return env

    def run_render(self, script, settings):
        return subprocess.run(
            [sys.executable, "-B", script, "--settings", settings,
             "render-unit"],
            capture_output=True, text=True, timeout=60,
            cwd=str(self.tmp))

    def run_install(self, env, *args):
        return subprocess.run(
            ["sh", INSTALL, *args],
            capture_output=True, text=True, timeout=60,
            cwd=str(self.tmp), env=env)

    def expected_unit(self, python, script, settings):
        script_dir = os.path.dirname(os.path.realpath(script))
        lines = [
            UNIT_COMMENT,
            "[Unit]",
            "Description=One-time secret drop form",
            "",
            "[Service]",
            "Type=simple",
            "ExecStart=%s %s --settings %s serve" % (
                python, script, settings),
            "Restart=no",
            "TimeoutStopSec=10",
            "UMask=0077",
            "LimitCORE=0",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=tmpfs",
            "BindReadOnlyPaths=%s %s" % (script_dir, settings),
            "BindPaths=%s %s %s" % (
                self.slots, self.allowed_one, self.allowed_two),
            "RestrictSUIDSGID=true",
            "LockPersonality=true",
            "RestrictRealtime=true",
            "RestrictNamespaces=true",
            "SystemCallArchitectures=native",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        ]
        return "\n".join(lines) + "\n"

    def unit_path(self):
        return (self.xdg / "systemd" / "user" / "secret-drop.service")

    def tree_snapshot(self):
        snapshot = {}
        for root, dirs, files in os.walk(self.tmp, followlinks=False):
            for name in dirs + files:
                path = os.path.join(root, name)
                rel = os.path.relpath(path, self.tmp)
                try:
                    found = os.lstat(path)
                except OSError:
                    snapshot[rel] = ("missing", 0)
                    continue
                if stat.S_ISDIR(found.st_mode):
                    kind = "d"
                elif stat.S_ISLNK(found.st_mode):
                    kind = "l"
                else:
                    kind = "f"
                snapshot[rel] = (kind, stat.S_IMODE(found.st_mode))
        return snapshot

    def assert_no_temp_files(self):
        for root, dirs, files in os.walk(self.tmp, followlinks=False):
            for name in dirs + files:
                self.assertFalse(
                    name.startswith(".secret-drop"),
                    "temp file left at %s" % os.path.join(root, name))

    def test_render_unit_matches_template(self):
        proc = self.run_render(SECRET_DROP, self.settings_path)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, "")
        script = os.path.realpath(SECRET_DROP)
        expected = self.expected_unit("/usr/bin/python3", script,
                                      self.settings_path)
        self.assertEqual(proc.stdout, expected)
        self.assertNotIn("@", proc.stdout)
        self.assertNotIn("[Install]", proc.stdout)

    def test_render_unit_space_in_script_path(self):
        spaced = self.tmp / "dir with space"
        spaced.mkdir(mode=0o700)
        copy = spaced / "secret_drop.py"
        shutil.copyfile(SECRET_DROP, copy)
        proc = self.run_render(str(copy), self.settings_path)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "secret-drop: unsafe_path\n")
        self.assertEqual(proc.stdout, "")

    def test_install_creates_slots_and_unit(self):
        env = self.make_env()
        proc = self.run_install(env, "--settings", self.settings_path)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.slots).st_mode), 0o700)
        unit = self.unit_path()
        self.assertEqual(stat.S_IMODE(os.stat(unit).st_mode), 0o644)
        rendered = self.run_render(SECRET_DROP, self.settings_path)
        self.assertEqual(rendered.returncode, 0)
        self.assertEqual(unit.read_text(), rendered.stdout)
        lines = proc.stdout.splitlines()
        self.assertEqual(lines, [
            "created %s" % self.slots,
            "wrote %s" % unit,
            "next: systemctl --user daemon-reload"
            " (the unit is started by open, never enabled)",
        ])
        self.assertEqual(proc.stderr, "")
        self.assertFalse(Path(self.syslog).exists())

    def test_install_twice_same_file(self):
        env = self.make_env()
        first = self.run_install(env, "--settings", self.settings_path)
        self.assertEqual(first.returncode, 0)
        before = self.unit_path().read_bytes()
        second = self.run_install(env, "--settings", self.settings_path)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(self.unit_path().read_bytes(), before)
        self.assertEqual(second.stdout.splitlines(), [
            "wrote %s" % self.unit_path(),
            "next: systemctl --user daemon-reload"
            " (the unit is started by open, never enabled)",
        ])

    def test_install_dry_run_writes_nothing(self):
        env = self.make_env()
        proc = self.run_install(env, "--settings", self.settings_path,
                                "--dry-run")
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(Path(self.slots).exists())
        self.assertFalse(self.unit_path().exists())
        self.assertFalse((self.xdg / "systemd").exists())
        lines = proc.stdout.splitlines()
        self.assertEqual(lines, [
            "would create %s (mode 700)" % self.slots,
            "would write %s" % self.unit_path(),
            "next: systemctl --user daemon-reload"
            " (the unit is started by open, never enabled)",
        ])
        self.assertFalse(Path(self.syslog).exists())

    def test_install_bad_settings_writes_nothing(self):
        bad = self.tmp / "bad.toml"
        self.write_settings(bad, port=80)
        env = self.make_env()
        proc = self.run_install(env, "--settings", str(bad))
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertIn("secret-drop: settings:", proc.stderr)
        self.assertFalse(Path(self.slots).exists())
        self.assertFalse((self.xdg / "systemd").exists())
        self.assertFalse(Path(self.syslog).exists())

    def test_install_usage_errors(self):
        env = self.make_env()
        for args in (("--bogus",),
                     ("--settings", self.settings_path, "--bogus"),
                     ()):
            with self.subTest(args=args):
                proc = self.run_install(env, *args)
                self.assertEqual(proc.returncode, 64)
                self.assertIn("usage:", proc.stderr)
                self.assertEqual(proc.stdout, "")
        self.assertFalse(Path(self.slots).exists())
        self.assertFalse((self.xdg / "systemd").exists())

    def test_validate_phase_writes_nothing(self):
        cases = []
        for kind in ("mode", "symlink"):
            slots = self.tmp / ("slots-" + kind)
            if kind == "mode":
                slots.mkdir(mode=0o700)
                os.chmod(slots, 0o755)
            else:
                real = self.tmp / "slots-real"
                real.mkdir(mode=0o700)
                os.symlink(real, slots)
            settings = self.tmp / ("settings-" + kind + ".toml")
            self.write_settings(settings, slots_dir=str(slots))
            cases.append(str(settings))
        bad = self.tmp / "bad.toml"
        self.write_settings(bad, port=80)
        cases.append(str(bad))
        for settings in cases:
            with self.subTest(settings=settings):
                for args in (["--settings", settings],
                             ["--settings", settings, "--dry-run"]):
                    with self.subTest(args=args):
                        before = self.tree_snapshot()
                        proc = self.run_install(self.make_env(), *args)
                        self.assertNotEqual(proc.returncode, 0)
                        self.assertEqual(len(proc.stderr.splitlines()), 1)
                        self.assertEqual(proc.stdout, "")
                        self.assertEqual(self.tree_snapshot(), before)

    def test_dry_run_leaves_tree_unchanged(self):
        before = self.tree_snapshot()
        proc = self.run_install(self.make_env(), "--settings",
                                self.settings_path, "--dry-run")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self.tree_snapshot(), before)
        self.assertEqual(proc.stdout.splitlines(), [
            "would create %s (mode 700)" % self.slots,
            "would write %s" % self.unit_path(),
            "next: systemctl --user daemon-reload"
            " (the unit is started by open, never enabled)",
        ])
        self.assertFalse(Path(self.syslog).exists())

    def test_unsafe_unit_path_refused(self):
        unit_dir = self.xdg / "systemd" / "user"
        unit_dir.mkdir(mode=0o700, parents=True)
        target_dir = self.tmp / "link-target-dir"
        target_dir.mkdir(mode=0o700)
        target_file = self.tmp / "link-target-file"
        target_file.write_bytes(b"keep me\n")
        link = unit_dir / "secret-drop.service"

        def plant_symlink_dir():
            os.symlink(target_dir, link)

        def plant_symlink_file():
            os.symlink(target_file, link)

        def plant_dir():
            link.mkdir(mode=0o700)

        for label, plant in (("symlink-to-dir", plant_symlink_dir),
                             ("symlink-to-file", plant_symlink_file),
                             ("dir", plant_dir)):
            with self.subTest(path=label):
                plant()
                proc = self.run_install(self.make_env(), "--settings",
                                        self.settings_path)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(proc.stderr,
                                 "secret-drop: unit_path_unsafe\n")
                self.assertEqual(proc.stdout, "")
                if link.is_symlink():
                    link.unlink()
                else:
                    link.rmdir()
        self.assertEqual(sorted(os.listdir(target_dir)), [])
        self.assertEqual(target_file.read_bytes(), b"keep me\n")
        self.assert_no_temp_files()

    def test_write_then_rewrite_same_file(self):
        env = self.make_env()
        proc = self.run_install(env, "--settings", self.settings_path)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.slots).st_mode), 0o700)
        unit = self.unit_path()
        self.assertEqual(stat.S_IMODE(os.stat(unit).st_mode), 0o644)
        rendered = self.run_render(SECRET_DROP, self.settings_path)
        self.assertEqual(rendered.returncode, 0)
        self.assertEqual(unit.read_text(), rendered.stdout)
        self.assert_no_temp_files()
        self.assertEqual(proc.stdout.splitlines(), [
            "created %s" % self.slots,
            "wrote %s" % unit,
            "next: systemctl --user daemon-reload"
            " (the unit is started by open, never enabled)",
        ])
        first_bytes = unit.read_bytes()
        second = self.run_install(env, "--settings", self.settings_path)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(unit.read_bytes(), first_bytes)
        self.assertEqual(second.stdout.splitlines(), [
            "wrote %s" % unit,
            "next: systemctl --user daemon-reload"
            " (the unit is started by open, never enabled)",
        ])

    def test_only_mktemp_temp_names(self):
        real = shutil.which("mktemp", path="/usr/bin:/bin")
        self.assertIsNotNone(real)
        fake = self.bindir / "mktemp"
        fake.write_text("#!/bin/sh\n"
                        "printf '%%s\\n' \"$@\" >> \"$MKTEMP_LOG\"\n"
                        "exec %s \"$@\"\n" % real)
        os.chmod(fake, 0o700)
        log = str(self.tmp / "mktemp.log")
        env = self.make_env(MKTEMP_LOG=log)
        proc = self.run_install(env, "--settings", self.settings_path)
        self.assertEqual(proc.returncode, 0)
        lines = Path(log).read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(
            str(self.xdg / "systemd" / "user" / ".secret-drop.")))
        self.assertTrue(lines[0].endswith(".XXXXXX"))
        missing = self.tmp / "mktemp-dry.log"
        dry_env = self.make_env(MKTEMP_LOG=str(missing))
        proc = self.run_install(dry_env, "--settings",
                                self.settings_path, "--dry-run")
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(missing.exists())
        self.assertNotIn("$$", Path(INSTALL).read_text())

    def test_unsafe_slots_dir_refused(self):
        for kind in ("mode", "symlink"):
            with self.subTest(kind=kind):
                slots = self.tmp / ("slots-" + kind)
                if kind == "mode":
                    slots.mkdir(mode=0o700)
                    os.chmod(slots, 0o755)
                else:
                    real = self.tmp / "slots-real"
                    real.mkdir(mode=0o700)
                    os.symlink(real, slots)
                settings = self.tmp / ("settings-" + kind + ".toml")
                self.write_settings(settings, slots_dir=str(slots))
                env = self.make_env()
                for args in (["--settings", str(settings)],
                             ["--settings", str(settings), "--dry-run"]):
                    with self.subTest(args=args):
                        proc = self.run_install(env, *args)
                        self.assertNotEqual(proc.returncode, 0)
                        self.assertEqual(
                            proc.stderr,
                            "secret-drop: slots_dir_unsafe\n")
                        self.assertEqual(proc.stdout, "")
                        self.assertFalse(self.unit_path().exists())
                rendered = self.run_render(SECRET_DROP, str(settings))
                self.assertEqual(rendered.returncode, 1)
                self.assertEqual(
                    rendered.stderr, "secret-drop: slots_dir_unsafe\n")
                self.assertEqual(rendered.stdout, "")

    def test_missing_settings_value_is_usage_error(self):
        env = self.make_env()
        for args in (("--settings", "--dry-run"), ("--settings",)):
            with self.subTest(args=args):
                proc = self.run_install(env, *args)
                self.assertEqual(proc.returncode, 64)
                self.assertIn("usage:", proc.stderr)
                self.assertEqual(proc.stdout, "")
        self.assertFalse(Path(self.slots).exists())
        self.assertFalse((self.xdg / "systemd").exists())

    def test_install_passes_with_current_unit_python(self):
        self.write_settings(self.tmp / "settings.toml",
                            python=sys.executable)
        proc = self.run_install(self.make_env(), "--settings",
                                self.settings_path)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.slots).st_mode), 0o700)
        self.assertTrue(self.unit_path().exists())

    def test_install_refuses_old_unit_python(self):
        old = self.tmp / "old-python"
        old.write_text("#!/bin/sh\nexit 1\n")
        os.chmod(old, 0o700)
        self.write_settings(self.tmp / "settings.toml",
                            python=str(old))
        proc = self.run_install(self.make_env(), "--settings",
                                self.settings_path)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            proc.stderr,
            "install.sh: the settings python must be 3.11 or later\n")
        self.assertEqual(proc.stdout, "")
        self.assertFalse(Path(self.slots).exists())
        self.assertFalse(self.unit_path().exists())

    def test_install_refuses_missing_unit_python(self):
        plain = self.tmp / "plain-file"
        plain.write_bytes(b"not an interpreter\n")
        os.chmod(plain, 0o600)
        cases = (str(self.tmp / "no-such-python"), str(plain))
        for python in cases:
            with self.subTest(python=python):
                self.write_settings(self.tmp / "settings.toml",
                                    python=python)
                for args in (["--settings", self.settings_path],
                             ["--settings", self.settings_path,
                              "--dry-run"]):
                    with self.subTest(args=args):
                        proc = self.run_install(self.make_env(), *args)
                        self.assertEqual(proc.returncode, 1)
                        self.assertEqual(
                            proc.stderr,
                            "install.sh: the settings python must be"
                            " 3.11 or later\n")
                        self.assertEqual(proc.stdout, "")
                        self.assertFalse(Path(self.slots).exists())
                        self.assertFalse(self.unit_path().exists())

    def test_install_refuses_old_path_python(self):
        old = self.bindir / "python3"
        old.write_text("#!/bin/sh\nexit 1\n")
        os.chmod(old, 0o700)
        proc = self.run_install(self.make_env(), "--settings",
                                self.settings_path)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            proc.stderr,
            "install.sh: python3 3.11 or later is required\n")
        self.assertEqual(proc.stdout, "")
        self.assertFalse(Path(self.slots).exists())
        self.assertFalse(self.unit_path().exists())

    def test_render_unit_has_sandbox_binds(self):
        proc = self.run_render(SECRET_DROP, self.settings_path)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, "")
        script = os.path.realpath(SECRET_DROP)
        script_dir = os.path.dirname(script)
        self.assertIn("ProtectHome=tmpfs\n", proc.stdout)
        self.assertIn("BindReadOnlyPaths=%s %s\n" % (
            script_dir, self.settings_path), proc.stdout)
        self.assertIn("BindPaths=%s %s %s\n" % (
            self.slots, self.allowed_one, self.allowed_two),
            proc.stdout)
        self.assertNotIn("ProtectHome=read-only", proc.stdout)
        self.assertNotIn("ReadWritePaths=", proc.stdout)
        self.assertNotIn("@", proc.stdout)

    def test_python_under_home_refused(self):
        under = self.home / "bin" / "python3"
        under.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        under.write_bytes(b"#!/bin/sh\nexit 0\n")
        os.chmod(under, 0o700)
        self.write_settings(self.tmp / "settings.toml",
                            python=str(under))
        env = dict(os.environ)
        env["HOME"] = str(self.home)
        for args in (["check"], ["render-unit"]):
            with self.subTest(args=args):
                proc = subprocess.run(
                    [sys.executable, "-B", SECRET_DROP, "--settings",
                     self.settings_path, *args],
                    capture_output=True, text=True, timeout=60,
                    cwd=str(self.tmp), env=env)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(proc.stderr,
                                 "secret-drop: python_under_home\n")
                self.assertEqual(proc.stdout, "")
        env = self.make_env()
        for args in (["--settings", self.settings_path],
                     ["--settings", self.settings_path, "--dry-run"]):
            with self.subTest(args=args):
                before = self.tree_snapshot()
                proc = self.run_install(env, *args)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(proc.stderr,
                                 "secret-drop: python_under_home\n")
                self.assertEqual(proc.stdout, "")
                self.assertEqual(self.tree_snapshot(), before)

    def test_system_python_outside_home_passes(self):
        proc = subprocess.run(
            [sys.executable, "-B", SECRET_DROP, "--settings",
             self.settings_path, "check"],
            capture_output=True, text=True, timeout=60,
            cwd=str(self.tmp))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main()
