"""Tests for the secret-drop pack wrapper, skill and README.

Fake-only: every check reads files inside this repository and parses
text; values are placeholders, and no test touches the network, a unit,
a real settings file or a real home directory.
"""

import os
import stat
import tomllib
import unittest
from pathlib import Path

import secret_drop

ROOT = Path(__file__).resolve().parent
COMMANDS = ("open", "status", "cancel", "list")
OPEN_FLAGS = ("--name", "--file", "--reason")
SKILL_DESC_START = (
    "Ask the user for a secret (an API key, token or password)"
    " without seeing it"
)


def _read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def _front_matter(text):
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != "---":
        return None
    try:
        end = lines.index("---", 1)
    except ValueError:
        return None
    fields = {}
    for line in lines[1:end]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields


def _settings_table_keys(text):
    lines = text.splitlines()
    try:
        start = next(
            i for i, line in enumerate(lines)
            if line.strip().lower() == "## settings"
        )
    except StopIteration:
        return None
    rows = []
    for line in lines[start + 1:]:
        stripped = line.strip()
        if stripped.startswith("## "):
            break
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells:
            continue
        first = cells[0]
        if first.lower() == "key" or set(first) <= set("-: "):
            continue
        rows.append(first)
    return rows


class PackTomlTest(unittest.TestCase):
    def test_pack_toml_has_name_version_schema(self):
        with open(ROOT / "pack.toml", "rb") as handle:
            data = tomllib.load(handle)
        self.assertEqual(
            set(data["pack"]), {"name", "version", "schema"})
        self.assertEqual(data["pack"]["name"], "secret")
        self.assertEqual(data["pack"]["version"], "0.1.0")
        self.assertEqual(data["pack"]["schema"], 2)


class CommandDirsTest(unittest.TestCase):
    def test_each_command_has_description_and_runner(self):
        for name in COMMANDS:
            with self.subTest(command=name):
                with open(ROOT / "commands" / name / "command.toml",
                          "rb") as handle:
                    command = tomllib.load(handle)
                self.assertTrue(command["description"].strip())
                self.assertEqual(
                    len(command["description"].strip().splitlines()), 1)
                run = ROOT / "commands" / name / "run.sh"
                self.assertEqual(
                    stat.S_IMODE(os.stat(run).st_mode), 0o755)
                lines = [line for line in run.read_text(
                    encoding="utf-8").splitlines() if line.strip()]
                self.assertEqual(lines, [
                    "#!/bin/sh",
                    "set -eu",
                    "pack=$(CDPATH= cd -- \"$(dirname \"$0\")/../..\""
                    " && pwd -P)",
                    "exec python3 \"$pack/secret_drop.py\" %s \"$@\""
                    % name,
                ])

    def test_open_description_names_its_flags(self):
        with open(ROOT / "commands" / "open" / "command.toml",
                  "rb") as handle:
            command = tomllib.load(handle)
        for flag in OPEN_FLAGS:
            self.assertIn(flag, command["description"])

    def test_status_description_names_wait(self):
        with open(ROOT / "commands" / "status" / "command.toml",
                  "rb") as handle:
            command = tomllib.load(handle)
        self.assertIn("--wait", command["description"])


class SkillTest(unittest.TestCase):
    def test_skill_front_matter_names_secret_drop(self):
        fields = _front_matter(
            _read("skills/secret-drop/SKILL.md"))
        self.assertIsNotNone(fields)
        self.assertEqual(fields.get("name"), "secret-drop")
        self.assertTrue(
            fields.get("description", "").startswith(SKILL_DESC_START))


class CitationsTest(unittest.TestCase):
    def test_citations_point_at_defined_symbols(self):
        text = _read("skills/secret-drop/citations.md")
        rows = 0
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("|"):
                continue
            cells = [cell.strip()
                     for cell in stripped.strip("|").split("|")]
            if not cells:
                continue
            if cells[0].lower() == "kind":
                continue
            if set(cells[0]) <= set("-: "):
                continue
            rows += 1
            kind, path, symbol = cells[0], cells[1], cells[2]
            target = ROOT / path
            self.assertTrue(target.is_file(), path)
            if path.endswith(".py"):
                source = target.read_text(encoding="utf-8")
                self.assertTrue(
                    ("def %s" % symbol) in source
                    or ("%s =" % symbol) in source, symbol)
        self.assertGreater(rows, 0)


class ReadmeTest(unittest.TestCase):
    def test_settings_table_names_exactly_the_accepted_keys(self):
        keys = _settings_table_keys(_read("README.md"))
        self.assertIsNotNone(keys)
        self.assertEqual(set(keys), set(secret_drop._KNOWN_KEYS))
        self.assertEqual(len(keys), len(set(keys)))

    def test_readme_has_no_em_or_en_dash(self):
        text = _read("README.md")
        self.assertNotIn("\u2013", text)
        self.assertNotIn("\u2014", text)

    def test_skill_files_have_no_em_or_en_dash(self):
        for name in ("skills/secret-drop/SKILL.md",
                     "skills/secret-drop/citations.md"):
            with self.subTest(file=name):
                text = _read(name)
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)


if __name__ == "__main__":
    unittest.main()
