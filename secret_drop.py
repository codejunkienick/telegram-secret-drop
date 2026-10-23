"""One-time secret drop: slots, a one-form server and the link sender.

An agent opens a slot and the user pastes the secret into a small form this
host serves; the value lands straight in an owner-only file and the agent
learns only whether it was stored and its length.
"""

import argparse
import datetime
import errno
import fcntl
import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import os
import re
import resource
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unicodedata
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass


class SettingsError(Exception):
    """A settings file refusal; the message names the key, never a value."""


class TargetError(Exception):
    """A target path refusal; the message is the reason code only."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SlotError(Exception):
    """A slot refusal; the message is the fixed reason code only."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Settings:
    lan_address: str
    port: int
    allowed_dirs: tuple
    slots_dir: str
    send_command: tuple
    unit: str
    python: str
    settings_path: str


_KNOWN_KEYS = frozenset({
    "lan_address",
    "port",
    "allowed_dirs",
    "slots_dir",
    "send_command",
    "unit",
    "python",
})
_REQUIRED_KEYS = ("lan_address", "port", "allowed_dirs")

_PATH_RE = re.compile(r"[A-Za-z0-9._@+/-]+")
_UNIT_RE = re.compile(r"[A-Za-z0-9_.@-]{1,120}\.service")
_SAFE_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")

_DEFAULT_SLOTS_DIR = "~/.local/state/secret-drop"
_DEFAULT_SEND_COMMAND = ["gc", "telegram", "reply-current"]
_DEFAULT_UNIT = "secret-drop.service"
_DEFAULT_PYTHON = "/usr/bin/python3"

_MAX_SETTINGS_SIZE = 65536
_MAX_RECORD_SIZE = 16384

_SLOT_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_HEX_RE = {
    64: re.compile(r"[0-9a-f]{64}"),
    16: re.compile(r"[0-9a-f]{16}"),
}

_RECORD_KEYS = ("name", "target", "reason", "slot_id", "token_sha256",
                "created_at", "expires_at", "finished_at",
                "overwrite", "state", "length", "error")
_RECORD_STATES = ("open", "stored", "expired", "cancelled", "failed")
_FINISH_STATES = ("stored", "cancelled", "failed")

_PRUNE_AFTER_SECONDS = 7 * 86400

# Largest epoch datetime.fromtimestamp accepts (9999-12-31 23:59:59 UTC).
_MAX_EPOCH = 253402300799


def _settings_file_open(path):
    try:
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise SettingsError("settings: cannot open settings file")
    except OSError:
        raise SettingsError(
            "settings: must be an owner-only regular file (chmod 600)")


def _read_settings_text(fd):
    chunks = []
    try:
        while True:
            chunk = os.read(fd, _MAX_SETTINGS_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        raise SettingsError("settings: not valid TOML")
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError:
        raise SettingsError("settings: not valid TOML")


def _load_lan_address(data):
    lan = data["lan_address"]
    if not isinstance(lan, str):
        raise SettingsError("settings: lan_address must be an IP address string")
    try:
        addr = ipaddress.ip_address(lan)
    except ValueError:
        raise SettingsError(
            "settings: lan_address must be a LAN, VPN or loopback address")
    if addr.is_unspecified or addr.is_multicast or addr.is_global:
        raise SettingsError(
            "settings: lan_address must be a LAN, VPN or loopback address")
    return lan


def _load_port(data):
    port = data["port"]
    if type(port) is not int or not 1024 <= port <= 65535:
        raise SettingsError(
            "settings: port must be an integer from 1024 to 65535")
    return port


def _load_allowed_dirs(data):
    dirs = data["allowed_dirs"]
    if (not isinstance(dirs, list) or not 1 <= len(dirs) <= 32
            or any(not isinstance(d, str) for d in dirs)):
        raise SettingsError(
            "settings: allowed_dirs must be a list of 1 to 32 paths")
    expanded = []
    for raw in dirs:
        path = os.path.expanduser(raw)
        if not os.path.isabs(path) or path != os.path.normpath(path):
            raise SettingsError(
                "settings: allowed_dirs must be absolute normalized paths")
        if not _PATH_RE.fullmatch(path):
            raise SettingsError(
                "settings: allowed_dirs must use only letters,"
                " digits and . _ @ + / -")
        if os.path.realpath(path) != path:
            raise SettingsError(
                "settings: allowed_dirs must not contain a symlink")
        try:
            found = os.stat(path)
        except OSError:
            raise SettingsError(
                "settings: allowed_dirs must be existing directories"
                " you own that group and others cannot write")
        if (not stat.S_ISDIR(found.st_mode)
                or found.st_uid != os.getuid()
                or found.st_mode & 0o022):
            raise SettingsError(
                "settings: allowed_dirs must be existing directories"
                " you own that group and others cannot write")
        expanded.append(path)
    if len(set(expanded)) != len(expanded):
        raise SettingsError("settings: allowed_dirs must not repeat a directory")
    return tuple(expanded)


def _load_optional_path(data, key, default):
    value = data.get(key, default)
    if not isinstance(value, str):
        raise SettingsError(
            "settings: %s must be an absolute normalized path" % key)
    value = os.path.expanduser(value)
    if not os.path.isabs(value) or value != os.path.normpath(value):
        raise SettingsError(
            "settings: %s must be an absolute normalized path" % key)
    if not _PATH_RE.fullmatch(value):
        raise SettingsError(
            "settings: %s must use only letters, digits and . _ @ + / -" % key)
    return value


def _load_send_command(data):
    command = data.get("send_command", _DEFAULT_SEND_COMMAND)
    if (not isinstance(command, list) or not 1 <= len(command) <= 16
            or any(not isinstance(w, str) or not w or "\0" in w
                   for w in command)):
        raise SettingsError(
            "settings: send_command must be a list of 1 to 16 words")
    return tuple(command)


def _load_unit(data):
    unit = data.get("unit", _DEFAULT_UNIT)
    if not isinstance(unit, str) or not _UNIT_RE.fullmatch(unit):
        raise SettingsError("settings: unit must be a name ending in .service")
    return unit


def load_settings(path=None):
    """Read and check the settings file; refuse with SettingsError."""
    if path is None:
        path = (os.environ.get("SECRET_DROP_SETTINGS")
                or os.path.expanduser("~/.config/secret-drop/settings.toml"))
    settings_path = path if os.path.isabs(path) else os.path.abspath(path)
    fd = _settings_file_open(path)
    try:
        found = os.fstat(fd)
        if (not stat.S_ISREG(found.st_mode)
                or found.st_uid != os.getuid()
                or found.st_mode & 0o077
                or found.st_size > _MAX_SETTINGS_SIZE):
            raise SettingsError(
                "settings: must be an owner-only regular file (chmod 600)")
        text = _read_settings_text(fd)
    finally:
        os.close(fd)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise SettingsError("settings: not valid TOML")
    for key in data:
        if key not in _KNOWN_KEYS:
            # Only a plain token is echoed; anything else would let a
            # quoted key smuggle a newline into this one-line message.
            if _SAFE_KEY_RE.fullmatch(key):
                raise SettingsError("settings: unknown key %s" % key)
            raise SettingsError("settings: unknown key")
    for key in _REQUIRED_KEYS:
        if key not in data:
            raise SettingsError("settings: missing required key %s" % key)
    return Settings(
        lan_address=_load_lan_address(data),
        port=_load_port(data),
        allowed_dirs=_load_allowed_dirs(data),
        slots_dir=_load_optional_path(data, "slots_dir", _DEFAULT_SLOTS_DIR),
        send_command=_load_send_command(data),
        unit=_load_unit(data),
        python=_load_optional_path(data, "python", _DEFAULT_PYTHON),
        settings_path=settings_path,
    )


def _find_allowed_dir(settings, path):
    allowed = None
    for candidate in settings.allowed_dirs:
        if path.startswith(candidate + "/") and (
                allowed is None or len(candidate) > len(allowed)):
            allowed = candidate
    if allowed is None:
        raise TargetError("target_outside_allowed_dirs")
    return allowed


def _open_parent_fd(settings, target, overwrite):
    """Check the target path; return (dir, components, name, fd) with fd open.

    Every directory on the way down must be owned by the user, writable
    by neither group nor others, and free of symlinks. Every descriptor
    this opens is closed again on every refusal path; only the returned
    parent fd stays open for the caller to close.
    """
    path = os.path.expanduser(target)
    if not os.path.isabs(path):
        raise TargetError("target_not_absolute")
    if path != os.path.normpath(path) or not _PATH_RE.fullmatch(path):
        raise TargetError("target_bad_path")
    allowed = _find_allowed_dir(settings, path)
    parts = path[len(allowed) + 1:].split("/")
    name = parts[-1]
    if name.startswith(".secret-drop-"):
        raise TargetError("target_bad_path")
    fd = -1
    try:
        try:
            fd = os.open(allowed,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise TargetError("parent_changed")
        if os.path.realpath(allowed) != allowed:
            raise TargetError("parent_changed")
        found = os.fstat(fd)
        if found.st_uid != os.getuid() or found.st_mode & 0o022:
            raise TargetError("parent_changed")
        for component in parts[:-1]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY
                                | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                raise TargetError("parent_missing")
            except OSError:
                raise TargetError("parent_changed")
            os.close(fd)
            fd = child
            found = os.fstat(fd)
            if found.st_uid != os.getuid() or found.st_mode & 0o022:
                raise TargetError("parent_changed")
        try:
            found = os.lstat(name, dir_fd=fd)
        except FileNotFoundError:
            found = None
        except OSError:
            raise TargetError("parent_changed")
        if found is not None:
            if stat.S_ISREG(found.st_mode):
                if not overwrite:
                    raise TargetError("target_exists")
            else:
                raise TargetError("target_not_regular")
        return (allowed, tuple(parts[:-1]), name, fd)
    except BaseException:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def check_target(settings, target, overwrite):
    """Check a target path; return (allowed dir, components, file name)."""
    allowed, components, name, fd = _open_parent_fd(settings, target, overwrite)
    try:
        return (allowed, components, name)
    finally:
        os.close(fd)


def _write_temp_bytes(tmp_fd, value):
    try:
        os.fchmod(tmp_fd, 0o600)
        view = memoryview(value)
        while view:
            written = os.write(tmp_fd, view)
            view = view[written:]
        os.fsync(tmp_fd)
    except OSError:
        raise TargetError("parent_changed")


def write_secret(settings, target, overwrite, value):
    """Write value bytes to target atomically and owner-only."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("value must be bytes")
    allowed, components, name, fd = _open_parent_fd(settings, target, overwrite)
    try:
        try:
            found = os.lstat(name, dir_fd=fd)
        except FileNotFoundError:
            found = None
        except OSError:
            raise TargetError("parent_changed")
        if found is not None:
            if stat.S_ISREG(found.st_mode):
                if not overwrite:
                    raise TargetError("target_exists")
            else:
                raise TargetError("target_not_regular")
        if overwrite:
            tmp_name = ".secret-drop-" + secrets.token_hex(8)
            try:
                tmp_fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                  | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            except OSError:
                raise TargetError("parent_changed")
            try:
                try:
                    _write_temp_bytes(tmp_fd, value)
                finally:
                    os.close(tmp_fd)
                try:
                    os.replace(tmp_name, name, src_dir_fd=fd, dst_dir_fd=fd)
                except OSError:
                    raise TargetError("parent_changed")
                os.fsync(fd)
            except BaseException as exc:
                try:
                    os.unlink(tmp_name, dir_fd=fd)
                except OSError:
                    pass
                if isinstance(exc, OSError):
                    raise TargetError("parent_changed")
                raise
            return len(value)
        o_tmpfile = getattr(os, "O_TMPFILE", None)
        tmp_fd = None
        use_tmpfile = o_tmpfile is not None
        if use_tmpfile:
            try:
                tmp_fd = os.open(".", os.O_WRONLY | o_tmpfile | os.O_CLOEXEC,
                                 0o600, dir_fd=fd)
            except OSError as exc:
                if exc.errno in (errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL):
                    use_tmpfile = False
                    tmp_fd = None
                else:
                    raise TargetError("parent_changed")
        if use_tmpfile:
            try:
                _write_temp_bytes(tmp_fd, value)
                try:
                    os.link("/proc/self/fd/%d" % tmp_fd, name,
                            dst_dir_fd=fd, follow_symlinks=True)
                except FileExistsError:
                    try:
                        current = os.lstat(name, dir_fd=fd)
                    except FileNotFoundError:
                        raise TargetError("target_exists")
                    except OSError:
                        raise TargetError("parent_changed")
                    if not stat.S_ISREG(current.st_mode):
                        raise TargetError("target_not_regular")
                    raise TargetError("target_exists")
                except OSError:
                    raise TargetError("parent_changed")
                os.fsync(fd)
            finally:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            return len(value)
        tmp_name = ".secret-drop-" + secrets.token_hex(8)
        try:
            tmp_fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                              | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        except OSError:
            raise TargetError("parent_changed")
        try:
            try:
                _write_temp_bytes(tmp_fd, value)
            finally:
                os.close(tmp_fd)
            try:
                found = os.lstat(name, dir_fd=fd)
            except FileNotFoundError:
                found = None
            except OSError:
                raise TargetError("parent_changed")
            if found is not None:
                if stat.S_ISREG(found.st_mode):
                    raise TargetError("target_exists")
                raise TargetError("target_not_regular")
            try:
                os.link(tmp_name, name, src_dir_fd=fd, dst_dir_fd=fd)
            except FileExistsError:
                try:
                    current = os.lstat(name, dir_fd=fd)
                except FileNotFoundError:
                    raise TargetError("target_exists")
                except OSError:
                    raise TargetError("parent_changed")
                if not stat.S_ISREG(current.st_mode):
                    raise TargetError("target_not_regular")
                raise TargetError("target_exists")
            except OSError:
                raise TargetError("parent_changed")
            try:
                os.unlink(tmp_name, dir_fd=fd)
            except OSError:
                raise TargetError("target_temp_left")
            os.fsync(fd)
        except BaseException as exc:
            try:
                os.unlink(tmp_name, dir_fd=fd)
            except OSError:
                pass
            if isinstance(exc, OSError):
                raise TargetError("parent_changed")
            raise
        return len(value)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _refuse_unsafe_slots_dir(slots_dir):
    """Refuse a slots dir that serve would refuse; a symlink fails."""
    try:
        found = os.lstat(slots_dir)
    except OSError:
        raise SlotError("slots_dir_unsafe")
    if (not stat.S_ISDIR(found.st_mode)
            or found.st_uid != os.getuid()
            or found.st_mode & 0o077):
        raise SlotError("slots_dir_unsafe")


def ensure_slots_dir(settings):
    """Create the slots dir owner-only when missing; refuse when unsafe."""
    slots_dir = settings.slots_dir
    try:
        os.mkdir(slots_dir, 0o700)
    except FileExistsError:
        pass
    except OSError:
        raise SlotError("slots_dir_unsafe")
    _refuse_unsafe_slots_dir(slots_dir)
    return slots_dir


@contextmanager
def _locked_slots(settings):
    """Hold the slots dir's lock file for one read-modify-write."""
    slots_dir = ensure_slots_dir(settings)
    try:
        fd = os.open(os.path.join(slots_dir, ".lock"),
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise SlotError("slots_dir_unsafe")
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield slots_dir
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _checked_record(obj):
    if not isinstance(obj, dict) or set(obj) != set(_RECORD_KEYS):
        raise SlotError("slot_unreadable")
    if (not isinstance(obj["name"], str)
            or not _SLOT_NAME_RE.fullmatch(obj["name"])):
        raise SlotError("slot_unreadable")
    if not isinstance(obj["target"], str) or not isinstance(obj["reason"], str):
        raise SlotError("slot_unreadable")
    if (not isinstance(obj["slot_id"], str)
            or not _HEX_RE[16].fullmatch(obj["slot_id"])):
        raise SlotError("slot_unreadable")
    if (not isinstance(obj["token_sha256"], str)
            or not _HEX_RE[64].fullmatch(obj["token_sha256"])):
        raise SlotError("slot_unreadable")
    if (type(obj["created_at"]) is not int
            or type(obj["expires_at"]) is not int):
        raise SlotError("slot_unreadable")
    if (obj["finished_at"] is not None
            and type(obj["finished_at"]) is not int):
        raise SlotError("slot_unreadable")
    for field in ("created_at", "expires_at"):
        if not 0 <= obj[field] <= _MAX_EPOCH:
            raise SlotError("slot_unreadable")
    if (obj["finished_at"] is not None
            and not 0 <= obj["finished_at"] <= _MAX_EPOCH):
        raise SlotError("slot_unreadable")
    if type(obj["overwrite"]) is not bool:
        raise SlotError("slot_unreadable")
    if obj["state"] not in _RECORD_STATES:
        raise SlotError("slot_unreadable")
    if (obj["state"] == "open") != (obj["finished_at"] is None):
        raise SlotError("slot_unreadable")
    if obj["state"] == "stored":
        if type(obj["length"]) is not int or obj["length"] < 0:
            raise SlotError("slot_unreadable")
    elif obj["length"] is not None:
        raise SlotError("slot_unreadable")
    if obj["state"] == "failed":
        if not isinstance(obj["error"], str) or not obj["error"]:
            raise SlotError("slot_unreadable")
    elif obj["error"] is not None:
        raise SlotError("slot_unreadable")
    return obj


def _record_path(slots_dir, name):
    return os.path.join(slots_dir, name + ".json")


def _load_record(slots_dir, name):
    """Read one record; None when its file is absent."""
    try:
        # NONBLOCK so a FIFO record never blocks; fstat refuses it below.
        fd = os.open(_record_path(slots_dir, name),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError:
        raise SlotError("slot_unreadable")
    try:
        found = os.fstat(fd)
        if (not stat.S_ISREG(found.st_mode)
                or found.st_uid != os.getuid()
                or found.st_mode & 0o077
                or found.st_size > _MAX_RECORD_SIZE):
            raise SlotError("slot_unreadable")
        chunks = []
        while True:
            chunk = os.read(fd, _MAX_RECORD_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        raise SlotError("slot_unreadable")
    finally:
        os.close(fd)
    try:
        record = _checked_record(json.loads(b"".join(chunks).decode("utf-8")))
    except (UnicodeDecodeError, ValueError):
        raise SlotError("slot_unreadable")
    if record["name"] != name:
        raise SlotError("slot_unreadable")
    return record


def _write_json_atomic(slots_dir, filename, obj, prefix):
    """Write obj as JSON to slots_dir/filename, atomically and owner-only."""
    data = json.dumps(obj, sort_keys=True).encode("utf-8")
    tmp_name = ".%s-%s.tmp" % (prefix, secrets.token_hex(8))
    tmp_path = os.path.join(slots_dir, tmp_name)
    fd = os.open(tmp_path,
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp_path, os.path.join(slots_dir, filename))


def _save_record(slots_dir, record):
    if set(record) != set(_RECORD_KEYS):
        raise AssertionError("record must hold exactly the record keys")
    _write_json_atomic(slots_dir, record["name"] + ".json", record, "slot")


def _read_all(slots_dir):
    records = {}
    for entry in sorted(os.listdir(slots_dir)):
        if not entry.endswith(".json"):
            continue
        if entry == "server.json":
            continue  # the serve handshake file, not a slot
        name = entry[:-len(".json")]
        try:
            record = _load_record(slots_dir, name)
        except SlotError:
            records[name] = {"name": name, "state": "unreadable"}
            continue
        if record is None:
            continue
        records[record["name"]] = record
    return records


def _expire_sweep(slots_dir, records, now):
    """Expire open records past their time; save each one that turns."""
    for record in records.values():
        if record["state"] == "open" and now >= record["expires_at"]:
            record["state"] = "expired"
            record["finished_at"] = record["expires_at"]
            _save_record(slots_dir, record)


def _prune_finished(slots_dir, records, now):
    for record in records.values():
        if record.get("state") == "unreadable":
            continue
        if (record["state"] != "open" and record["finished_at"] is not None
                and now - record["finished_at"] > _PRUNE_AFTER_SECONDS):
            try:
                os.unlink(_record_path(slots_dir, record["name"]))
            except FileNotFoundError:
                pass


def new_slot(settings, name, target, reason, ttl_minutes, overwrite,
             replace, now=None):
    """Open a slot; return the stored record and its one-time token."""
    if (not isinstance(name, str) or not _SLOT_NAME_RE.fullmatch(name)
            or name == "server"):
        raise SlotError("bad_name")
    if (not isinstance(reason, str) or len(reason) > 200
            or not reason.isprintable()):
        raise SlotError("bad_reason")
    if type(ttl_minutes) is not int or not 1 <= ttl_minutes <= 30:
        raise SlotError("bad_ttl")
    expanded = os.path.expanduser(target)
    check_target(settings, expanded, overwrite)
    now = int(time.time()) if now is None else int(now)
    token = secrets.token_urlsafe(32)
    with _locked_slots(settings) as slots_dir:
        records = _read_all(slots_dir)
        _expire_sweep(slots_dir, records, now)
        current = records.get(name)
        if current is not None and current["state"] == "open":
            if not replace:
                raise SlotError("slot_open")
            current["state"] = "cancelled"
            current["finished_at"] = now
            _save_record(slots_dir, current)
        for other in records.values():
            if (other["name"] != name and other["state"] == "open"
                    and other["target"] == expanded):
                raise SlotError("target_in_use")
        _prune_finished(slots_dir, records, now)
        record = {
            "name": name,
            "target": expanded,
            "reason": reason,
            "slot_id": secrets.token_hex(8),
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "created_at": now,
            "expires_at": now + ttl_minutes * 60,
            "finished_at": None,
            "overwrite": bool(overwrite),
            "state": "open",
            "length": None,
            "error": None,
        }
        _save_record(slots_dir, record)
        return (record, token)


def _match_open_token(records, candidate):
    """Return the open record matching a token hash, or None."""
    # No early exit: every open record is compared, so the number of
    # comparisons never shows which record matched.
    matched = None
    for record in records.values():
        if record["state"] == "open" and hmac.compare_digest(
                candidate, record["token_sha256"]):
            matched = record
    return matched


def find_open_by_token(settings, token, now=None):
    """Return the open record matching a token, or None."""
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        return None
    candidate = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time()) if now is None else int(now)
    matched = None
    with _locked_slots(settings) as slots_dir:
        records = _read_all(slots_dir)
        _expire_sweep(slots_dir, records, now)
        matched = _match_open_token(records, candidate)
    return matched


def finish(settings, name, state, length=None, error=None, now=None):
    """Move an open record to stored, cancelled or failed."""
    if state not in _FINISH_STATES:
        raise ValueError("state must be stored, cancelled or failed")
    if state == "stored":
        if type(length) is not int or length < 0:
            raise ValueError("length must be a non-negative int when stored")
        if error is not None:
            raise ValueError("error must be None unless failed")
    elif state == "failed":
        if not isinstance(error, str) or not error:
            raise ValueError("error must be a reason code when failed")
        if length is not None:
            raise ValueError("length must be None unless stored")
    elif length is not None or error is not None:
        raise ValueError("length and error must be None when cancelled")
    now = int(time.time()) if now is None else int(now)
    with _locked_slots(settings) as slots_dir:
        records = _read_all(slots_dir)
        _expire_sweep(slots_dir, records, now)
        record = records.get(name)
        if record is None:
            raise SlotError("no_such_slot")
        if record.get("state") == "unreadable":
            raise SlotError("slot_unreadable")
        if record["state"] != "open":
            raise SlotError("slot_not_open")
        record["state"] = state
        record["finished_at"] = now
        record["length"] = length if state == "stored" else None
        record["error"] = error if state == "failed" else None
        _save_record(slots_dir, record)
        return record


_MAX_BODY_SIZE = 65536
_MAX_VALUE_SIZE = 16384

_NOT_FOUND_BODY = "Not found."
_FORBIDDEN_BODY = "Forbidden."
_INTERNAL_ERROR_BODY = "Internal error."
_PROTOCOL_ERROR_BODY = "Bad request."
_TOO_LARGE_BODY = "Request body too large."
_STORE_OK_BODY = "Stored. You can close this page."
_VALUE_REFUSED_LINE = "The value was not accepted. Try again."

_TOKEN_PATH_RE = re.compile(r"/s/([A-Za-z0-9_-]{43})")
_SAFE_METHOD_RE = re.compile(r"[A-Za-z]{1,16}")

_SECURITY_HEADERS = (
    ("Content-Type", "text/html; charset=utf-8"),
    ("Cache-Control", "no-store"),
    ("Referrer-Policy", "same-origin"),
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", "default-src 'none';"
     " style-src 'unsafe-inline'; form-action 'self';"
     " frame-ancestors 'none'; base-uri 'none'"),
)


def _sync_server_file(settings):
    """Expire records and rewrite the handshake file; return open names."""
    with _locked_slots(settings) as slots_dir:
        records = _read_all(slots_dir)
        _expire_sweep(slots_dir, records, int(time.time()))
        open_records = sorted(
            (record for record in records.values()
             if record.get("state") == "open"),
            key=lambda r: r["name"])
        names = [record["name"] for record in open_records]
        if names:
            ids = [record["slot_id"] for record in open_records]
            _write_json_atomic(slots_dir, "server.json",
                               {"pid": os.getpid(), "open": names,
                                "open_ids": ids,
                                "updated_at": int(time.time())}, "server")
        else:
            try:
                os.unlink(os.path.join(slots_dir, "server.json"))
            except FileNotFoundError:
                pass
        return names


def _local_hhmm(when):
    return datetime.datetime.fromtimestamp(when).astimezone().strftime(
        "%H:%M")


def _read_server_handshake(slots_dir):
    """Return the server.json (pid, open names, open ids), or None absent."""
    try:
        fd = os.open(os.path.join(slots_dir, "server.json"),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        found = os.fstat(fd)
        if (not stat.S_ISREG(found.st_mode)
                or found.st_uid != os.getuid()
                or found.st_mode & 0o077
                or found.st_size > 65536):
            return None
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        obj = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if (not isinstance(obj, dict) or not isinstance(obj.get("open"), list)
            or type(obj.get("pid")) is not int):
        return None
    ids = obj.get("open_ids")
    if ids is not None and (not isinstance(ids, list)
                            or any(not isinstance(v, str) for v in ids)):
        return None
    if ids is None:
        ids = []
    return (obj["pid"], obj["open"], ids)


def _is_served(slots_dir, name, slot_id=None):
    found = _read_server_handshake(slots_dir)
    if found is None:
        return False
    pid, names, ids = found
    if pid <= 0 or name not in names:
        return False
    if slot_id is not None and slot_id not in ids:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return False
    except OSError:
        return False
    return True


def _start_unit(settings, timeout):
    try:
        proc = subprocess.Popen(
            ["systemctl", "--user", "start", settings.unit],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    except OSError:
        return
    if timeout <= 0:
        proc.kill()
        proc.wait()
        return
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _wait_served(settings, name, deadline, slot_id=None):
    """Wait until the serving server lists the slot; False past deadline.

    Deadline is an absolute monotonic time owned by the caller; every
    systemctl call runs with at most the time left under it.
    """
    slots_dir = settings.slots_dir
    if slot_id is None:
        try:
            slot_id = _load_record(slots_dir, name)["slot_id"]
        except (SlotError, TypeError, KeyError):
            slot_id = None
    last_start = None
    while True:
        now = time.monotonic()
        if now >= deadline:
            return False
        if _is_served(slots_dir, name, slot_id):
            return True
        if last_start is None or now - last_start >= 1.0:
            _start_unit(settings, min(deadline - now, 10.0))
            last_start = now
        time.sleep(min(0.1, max(deadline - time.monotonic(), 0.0)))


def _form_page(record, error=None):
    rows = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        '<meta charset="utf-8">',
        "<title>secret-drop</title>",
        "</head>",
        "<body>",
        "<h1>Store a secret</h1>",
        "<p>Slot: %s</p>" % html.escape(record["name"]),
        "<p>Reason: %s</p>" % html.escape(record["reason"]),
        "<p>File: %s</p>" % html.escape(record["target"]),
        "<p>Expires: %s</p>" % html.escape(
            _local_hhmm(record["expires_at"])),
    ]
    if error is not None:
        rows.append("<p>%s</p>" % error)
    rows += [
        '<form method="post">',
        '<label>Value <input type="password" name="value"'
        ' autocomplete="off" autocapitalize="off" spellcheck="false"'
        " required></label>",
        '<button type="submit">Store</button>',
        "</form>",
        "</body>",
        "</html>",
    ]
    return "\n".join(rows) + "\n"


def _is_form_content_type(value):
    if not isinstance(value, str):
        return False
    parts = [part.strip() for part in value.split(";")]
    if parts[0].lower() != "application/x-www-form-urlencoded":
        return False
    for param in parts[1:]:
        if param.replace(" ", "").lower() != "charset=utf-8":
            return False
    return True


_REQUEST_DEADLINE_SECONDS = 15


class _RequestTimeout(Exception):
    """A whole-request deadline expired; the handler closes quietly."""


def _deadline_expired(signum, frame):
    raise _RequestTimeout()


class _SlotHandler(http.server.BaseHTTPRequestHandler):
    server_version = "secret-drop"
    sys_version = ""
    timeout = 10
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self._old_sigalrm = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, _deadline_expired)
        self._deadline = time.monotonic() + _REQUEST_DEADLINE_SECONDS
        signal.setitimer(signal.ITIMER_REAL, _REQUEST_DEADLINE_SECONDS)

    def finish(self):
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self._old_sigalrm)
        finally:
            super().finish()

    def _arm_remaining(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise _RequestTimeout()
        signal.setitimer(signal.ITIMER_REAL, remaining)

    def _disarm_deadline(self):
        signal.setitimer(signal.ITIMER_REAL, 0)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except _RequestTimeout:
            self.close_connection = True

    def version_string(self):
        return "secret-drop"

    def log_message(self, *args):
        pass

    def log_error(self, *args):
        pass

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._unknown_method
        raise AttributeError(name)

    def _log_request(self, code, log_extra):
        # Parser-safe: the request line may not have parsed, and a
        # method token outside this shape is never echoed.
        command = getattr(self, "command", None)
        if (not isinstance(command, str)
                or not _SAFE_METHOD_RE.fullmatch(command)):
            command = "UNKNOWN"
        path = getattr(self, "path", None)
        if isinstance(path, str) and path.startswith("/s/"):
            kind = "/s/..."
        else:
            kind = "other"
        line = "%s %s %d %s" % (command, kind, int(code),
                                self.client_address[0])
        if log_extra:
            line += " " + log_extra
        sys.stderr.write(line + "\n")
        sys.stderr.flush()

    def _send_headers(self, code, length):
        self.send_response(code)
        for header, value in _SECURITY_HEADERS:
            self.send_header(header, value)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(length))
        self.end_headers()

    def _respond(self, code, body, log_extra):
        # Every answer closes the connection, so the serving loop
        # always reaches its exit check after the request.
        self._log_request(code, log_extra)
        self.close_connection = True
        data = body.encode("utf-8")
        try:
            self._send_headers(code, len(data))
            self.wfile.write(data)
        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            pass

    def send_error(self, code, message=None, explain=None):
        self._log_request(code, "")
        try:
            data = _PROTOCOL_ERROR_BODY.encode("utf-8")
            self._send_headers(code, len(data))
            self.wfile.write(data)
        except Exception:
            pass
        finally:
            self.close_connection = True

    def _send_500(self):
        try:
            sys.stderr.write("secret-drop: internal_error\n")
            sys.stderr.flush()
            self.close_connection = True
            data = _INTERNAL_ERROR_BODY.encode("utf-8")
            self._send_headers(500, len(data))
            self.wfile.write(data)
        except Exception:
            pass

    def _unknown_method(self):
        self._respond(404, _NOT_FOUND_BODY, "")

    def _routed_token(self):
        if self.headers.get("Host") != self.server._expected_host:
            return None
        if "?" in self.path:
            return None
        match = _TOKEN_PATH_RE.fullmatch(self.path)
        if match is None:
            return None
        return match.group(1)

    def do_GET(self):
        try:
            self._disarm_deadline()
            token = self._routed_token()
            record = None
            if token is not None:
                record = find_open_by_token(self.server._slot_settings, token)
            if record is None:
                self._respond(404, _NOT_FOUND_BODY, "")
            else:
                self._respond(200, _form_page(record), "")
        except (_RequestTimeout, TimeoutError):
            self.close_connection = True
        except Exception:
            self._send_500()

    def do_POST(self):
        try:
            self._respond(*self._post_outcome())
        except (_RequestTimeout, TimeoutError):
            self.close_connection = True
        except Exception:
            self._send_500()

    def _refuse(self, record):
        return (400, _form_page(record, _VALUE_REFUSED_LINE), "")

    def _post_outcome(self):
        settings = self.server._slot_settings
        expected = self.server._expected_host
        token = self._routed_token()
        record = None
        if token is not None:
            self._disarm_deadline()
            try:
                record = find_open_by_token(settings, token)
            finally:
                self._arm_remaining()
        if record is None:
            return (404, _NOT_FOUND_BODY, "")
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + expected:
            return (403, _FORBIDDEN_BODY, "")
        if self.headers.get("Transfer-Encoding") is not None:
            return self._refuse(record)
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length)
            if length < 0:
                raise ValueError("negative length")
        except (TypeError, ValueError):
            return (411, _form_page(record, _VALUE_REFUSED_LINE), "")
        if length > _MAX_BODY_SIZE:
            return (413, _TOO_LARGE_BODY, "")
        body = self.rfile.read(length)
        self._disarm_deadline()
        if not _is_form_content_type(self.headers.get("Content-Type")):
            return self._refuse(record)
        try:
            text = body.decode("ascii")
            fields = urllib.parse.parse_qsl(
                text, keep_blank_values=True, strict_parsing=True,
                encoding="utf-8", errors="strict", max_num_fields=1)
        except ValueError:
            return self._refuse(record)
        if len(fields) != 1 or fields[0][0] != "value":
            return self._refuse(record)
        value = fields[0][1].strip()
        if any(unicodedata.category(char) == "Cc" for char in value):
            return self._refuse(record)
        encoded = value.encode("utf-8")
        if not 1 <= len(encoded) <= _MAX_VALUE_SIZE:
            return self._refuse(record)
        return self._store(token, encoded)

    def _store(self, token, encoded):
        """Find the slot, write the value and finish it under one lock."""
        settings = self.server._slot_settings
        now = int(time.time())
        with _locked_slots(settings) as slots_dir:
            records = _read_all(slots_dir)
            _expire_sweep(slots_dir, records, now)
            candidate = hashlib.sha256(token.encode()).hexdigest()
            current = _match_open_token(records, candidate)
            if current is None:
                return (404, _NOT_FOUND_BODY, "")
            try:
                write_secret(settings, current["target"],
                             current["overwrite"], encoded)
            except TargetError as exc:
                current["state"] = "failed"
                current["finished_at"] = now
                current["length"] = None
                current["error"] = exc.code
                _save_record(slots_dir, current)
                return (409, "Not stored (%s). Ask the agent for a new link."
                        % exc.code,
                        "failed %s %s" % (current["name"], exc.code))
            current["state"] = "stored"
            current["finished_at"] = now
            current["length"] = len(encoded)
            current["error"] = None
            _save_record(slots_dir, current)
            return (200, _STORE_OK_BODY,
                    "stored %s (%d bytes)" % (current["name"], len(encoded)))


class _SlotServer(http.server.HTTPServer):
    allow_reuse_address = True

    def __init__(self, settings):
        self._slot_settings = settings
        self._expected_host = _expected_host(settings)
        if ipaddress.ip_address(settings.lan_address).version == 6:
            self.address_family = socket.AF_INET6
        super().__init__((settings.lan_address, settings.port),
                         _SlotHandler)


def _expected_host(settings):
    if ipaddress.ip_address(settings.lan_address).version == 6:
        return "[%s]:%d" % (settings.lan_address, settings.port)
    return "%s:%d" % (settings.lan_address, settings.port)


def _run_server(settings, slots_dir):
    try:
        lock_fd = os.open(os.path.join(slots_dir, "server.lock"),
                          os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise SlotError("slots_dir_unsafe")
    try:
        os.fchmod(lock_fd, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print("secret-drop: already_serving", file=sys.stderr)
            return 0
        stopped = False

        def _stop(signum, frame):
            nonlocal stopped
            stopped = True

        old_term = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, _stop)
        try:
            with _locked_slots(settings) as locked:
                records = _read_all(locked)
                _expire_sweep(locked, records, int(time.time()))
                names = sorted(name for name, record in records.items()
                               if record.get("state") == "open")
            if not names:
                try:
                    os.unlink(os.path.join(slots_dir, "server.json"))
                except FileNotFoundError:
                    pass
                return 0
            try:
                server = _SlotServer(settings)
            except OSError:
                print("secret-drop: bind_failed", file=sys.stderr)
                return 1
            try:
                if not _sync_server_file(settings):
                    server.server_close()
                    return 0
                server.timeout = 1.0
                while True:
                    if stopped:
                        try:
                            os.unlink(
                                os.path.join(slots_dir, "server.json"))
                        except FileNotFoundError:
                            pass
                        server.server_close()
                        return 0
                    server.handle_request()
                    if stopped:
                        try:
                            os.unlink(
                                os.path.join(slots_dir, "server.json"))
                        except FileNotFoundError:
                            pass
                        server.server_close()
                        return 0
                    if not _sync_server_file(settings):
                        server.server_close()
                        return 0
            finally:
                server.server_close()
        finally:
            try:
                signal.signal(signal.SIGTERM, old_term)
            except OSError:
                pass
    finally:
        os.close(lock_fd)


def _serve_command(args):
    settings = load_settings(args.settings)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    slots_dir = ensure_slots_dir(settings)
    try:
        return _run_server(settings, slots_dir)
    except (SettingsError, TargetError, SlotError):
        raise
    except Exception:
        print("secret-drop: internal_error", file=sys.stderr)
        return 1


def _is_python_under_home(python_path):
    real = os.path.realpath(python_path)
    if real == "/home" or real.startswith("/home/"):
        return True
    if real == "/root" or real.startswith("/root/"):
        return True
    home = os.environ.get("HOME")
    if home:
        try:
            home_real = os.path.realpath(home)
        except OSError:
            home_real = home
        if real == home_real or real.startswith(home_real + "/"):
            return True
    return False


def _check_command(args):
    try:
        settings = load_settings(args.settings)
    except SettingsError as exc:
        print("secret-drop: %s" % exc, file=sys.stderr)
        return 1
    if _is_python_under_home(settings.python):
        print("secret-drop: python_under_home", file=sys.stderr)
        return 1
    sys.stdout.write("settings ok\nunit=%s\nslots_dir=%s\npython=%s\n"
                     % (settings.unit, settings.slots_dir, settings.python))
    return 0


_TEMPLATE_FILE = "secret-drop.service.in"
_TEMPLATE_NAMES = ("PYTHON", "SCRIPT", "SCRIPT_DIR", "SETTINGS",
                   "SLOTS_DIR", "ALLOWED_DIRS")


def _read_template_text():
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                         _TEMPLATE_FILE)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        found = os.fstat(fd)
        if (not stat.S_ISREG(found.st_mode)
                or found.st_size > _MAX_SETTINGS_SIZE):
            raise OSError("bad template")
        chunks = []
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")
    finally:
        os.close(fd)


def _render_unit_command(args):
    try:
        settings = load_settings(args.settings)
    except SettingsError as exc:
        print("secret-drop: %s" % exc, file=sys.stderr)
        return 1
    if _is_python_under_home(settings.python):
        print("secret-drop: python_under_home", file=sys.stderr)
        return 1
    script_real = os.path.realpath(__file__)
    values = {"PYTHON": settings.python,
              "SCRIPT": script_real,
              "SCRIPT_DIR": os.path.dirname(script_real),
              "SETTINGS": settings.settings_path,
              "SLOTS_DIR": settings.slots_dir,
              "ALLOWED_DIRS": " ".join(settings.allowed_dirs)}
    for key in ("SCRIPT", "SCRIPT_DIR", "SETTINGS"):
        if not _PATH_RE.fullmatch(values[key]):
            print("secret-drop: unsafe_path", file=sys.stderr)
            return 1
    if os.path.lexists(settings.slots_dir):
        _refuse_unsafe_slots_dir(settings.slots_dir)
    try:
        text = _read_template_text()
    except (OSError, UnicodeDecodeError):
        print("secret-drop: internal_error", file=sys.stderr)
        return 1
    for key in _TEMPLATE_NAMES:
        text = text.replace("@%s@" % key, values[key])
    sys.stdout.write(text)
    return 0


def _iso(when):
    return datetime.datetime.fromtimestamp(when).astimezone().isoformat(
        timespec="seconds")


def _message_body(record, link):
    lines = ["<b>Secret requested</b>: <code>"
             + html.escape(record["name"], quote=True) + "</code>"]
    if record["reason"]:
        lines.append(html.escape(record["reason"], quote=True))
    lines.append('<a href="' + link + '">Open the form</a>'
                 " on the home network before "
                 + _local_hhmm(record["expires_at"])
                 + ". The link works once.")
    return "\n".join(lines)


_SEND_TIMEOUT = 60


def _run_send(settings, body_path, slot_id):
    """Run the send command; return (True, None, None) or (False, ...).

    Output is captured as bytes and never decoded strictly. On timeout
    the whole process group dies and only a temp file is drained, so a
    grandchild holding a pipe cannot block the caller.
    """
    argv = list(settings.send_command) + [
        "--format", "html", "--body-file", body_path,
        "--idempotency-key", "secret-drop:" + slot_id]
    err_file = tempfile.TemporaryFile(mode="w+b")
    try:
        try:
            proc = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=err_file, start_new_session=True)
        except OSError:
            return (False, "exit not_started", None)
        try:
            proc.wait(timeout=_SEND_TIMEOUT)
        except KeyboardInterrupt:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
            raise
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
            err_file.seek(0)
            return (False, "exit timeout", err_file.read())
        if proc.returncode != 0:
            err_file.seek(0)
            return (False, "exit %s" % proc.returncode, err_file.read())
        return (True, None, None)
    finally:
        err_file.close()


def _send_error_detail(err, token):
    if not err:
        return None
    lines = [line for line in err.splitlines() if line.strip()]
    if not lines:
        return None
    last = lines[-1]
    if token.encode() in last or b"/s/" in last:
        return None
    try:
        return last.decode("utf-8")[:200]
    except UnicodeDecodeError:
        return None


def _cancel_quietly(settings, name):
    # Best effort: the outcome line is decided before this runs, so a
    # cancel that cannot reach the slots dir must not replace it.
    try:
        finish(settings, name, "cancelled")
    except (SlotError, OSError):
        pass


def _status_object(record):
    return {"name": record["name"],
            "state": record["state"],
            "path": record["target"],
            "length": record["length"],
            "stored_at": _iso(record["finished_at"])
            if record["state"] == "stored" else None,
            "expires_at": _iso(record["expires_at"]),
            "error": record["error"]}


# Only _send_link creates, writes, sends or removes the send file, and
# its removal is proven with unlink plus lstat; an unproven removal
# cancels the slot.
def _send_link(settings, record, link, token):
    """Create the link file, run the send command, remove the file.

    Return (True, None, None) on success, else (False, kind, err) with
    kind "exit cleanup", "exit error" or the send's "exit N" reason.
    """
    name = "send-%s.html" % record["slot_id"]
    try:
        dir_fd = os.open(settings.slots_dir,
                          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                          | os.O_CLOEXEC)
    except OSError:
        return (False, "exit body", None)
    try:
        try:
            body_fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
        except OSError:
            return (False, "exit body", None)
        outcome = (False, "exit error", None)
        try:
            try:
                os.fchmod(body_fd, 0o600)
                data = _message_body(record, link).encode("utf-8")
                view = memoryview(data)
                while view:
                    written = os.write(body_fd, view)
                    view = view[written:]
                os.fsync(body_fd)
            finally:
                os.close(body_fd)
            outcome = _run_send(settings,
                                os.path.join(settings.slots_dir, name),
                                record["slot_id"])
        except KeyboardInterrupt:
            outcome = (False, "exit error", None)
        except Exception:
            outcome = (False, "exit error", None)
        finally:
            try:
                try:
                    os.unlink(name, dir_fd=dir_fd)
                except FileNotFoundError:
                    proven = True
                else:
                    try:
                        os.lstat(name, dir_fd=dir_fd)
                    except FileNotFoundError:
                        proven = True
                    except OSError:
                        proven = False
                    else:
                        proven = False
            except BaseException:
                proven = False
        if not proven:
            return (False, "exit cleanup", None)
        return outcome
    finally:
        os.close(dir_fd)


def _open_command(args):
    settings = load_settings(args.settings)
    record, token = new_slot(settings, args.name, args.file, args.reason,
                             args.ttl_minutes, args.overwrite, args.replace)
    deadline = time.monotonic() + 5.0
    try:
        if not _wait_served(settings, record["name"], deadline,
                             record["slot_id"]):
            _cancel_quietly(settings, record["name"])
            print("secret-drop: server_not_running", file=sys.stderr)
            return 1
        link = "http://" + _expected_host(settings) + "/s/" + token
        ok, kind, err = _send_link(settings, record, link, token)
        if not ok:
            _cancel_quietly(settings, record["name"])
            message = "secret-drop: send_failed (%s)" % kind
            detail = _send_error_detail(err, token)
            if detail is not None:
                message += ": " + detail
            print(message, file=sys.stderr)
            return 1
        sys.stdout.write(json.dumps(
            {"name": record["name"], "state": "open",
             "expires_at": _iso(record["expires_at"]), "link": "sent"},
            sort_keys=True) + "\n")
        return 0
    except (SettingsError, TargetError, SlotError):
        raise
    except KeyboardInterrupt:
        _cancel_quietly(settings, record["name"])
        print("secret-drop: interrupted", file=sys.stderr)
        return 130
    except Exception:
        _cancel_quietly(settings, record["name"])
        print("secret-drop: send_failed (exit error)", file=sys.stderr)
        return 1


def _read_status_record(args):
    settings = load_settings(args.settings)
    with _locked_slots(settings) as slots_dir:
        records = _read_all(slots_dir)
        _expire_sweep(slots_dir, records, int(time.time()))
        record = records.get(args.name)
        if record is None:
            raise SlotError("no_such_slot")
        if record.get("state") == "unreadable":
            raise SlotError("slot_unreadable")
        return record


def _status_command(args):
    if not 0 <= args.wait <= 3600:
        raise SlotError("bad_wait")
    deadline = time.monotonic() + args.wait
    while True:
        record = _read_status_record(args)
        if record["state"] != "open" or time.monotonic() >= deadline:
            break
        time.sleep(1)
    sys.stdout.write(json.dumps(_status_object(record), sort_keys=True)
                     + "\n")
    if record["state"] == "stored":
        return 0
    if record["state"] == "open":
        return 4
    return 3


def _cancel_command(args):
    settings = load_settings(args.settings)
    record = finish(settings, args.name, "cancelled")
    sys.stdout.write(json.dumps(_status_object(record), sort_keys=True)
                     + "\n")
    return 0


def _list_command(args):
    settings = load_settings(args.settings)
    with _locked_slots(settings) as slots_dir:
        records = _read_all(slots_dir)
        _expire_sweep(slots_dir, records, int(time.time()))
        shown = []
        for record in sorted(records.values(), key=lambda r: r["name"]):
            if record.get("state") == "unreadable":
                shown.append({"name": record["name"],
                              "state": "unreadable"})
            else:
                shown.append({"name": record["name"],
                              "state": record["state"],
                              "expires_at": _iso(record["expires_at"])})
    sys.stdout.write(json.dumps(shown, sort_keys=True) + "\n")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Take in one secret without ever seeing it.")
    parser.add_argument("--settings", default=None,
                        help="settings file (else $SECRET_DROP_SETTINGS,"
                        " else ~/.config/secret-drop/settings.toml)")
    sub = parser.add_subparsers(dest="subcommand", required=True)
    check = sub.add_parser("check", help="check the settings file")
    check.set_defaults(run=_check_command)
    slot_open = sub.add_parser("open", help="open a slot for one secret")
    slot_open.add_argument("--name", required=True)
    slot_open.add_argument("--file", required=True)
    slot_open.add_argument("--reason", default="")
    slot_open.add_argument("--ttl-minutes", type=int, default=10)
    slot_open.add_argument("--overwrite", action="store_true")
    slot_open.add_argument("--replace", action="store_true")
    slot_open.set_defaults(run=_open_command)
    status = sub.add_parser("status", help="show one slot, waiting if open")
    status.add_argument("name")
    status.add_argument("--wait", type=int, default=0)
    status.set_defaults(run=_status_command)
    cancel = sub.add_parser("cancel", help="cancel one open slot")
    cancel.add_argument("name")
    cancel.set_defaults(run=_cancel_command)
    shown = sub.add_parser("list", help="list slots by name")
    shown.set_defaults(run=_list_command)
    serve = sub.add_parser("serve", help="serve the one-form page")
    serve.set_defaults(run=_serve_command)
    render = sub.add_parser("render-unit",
                            help="print the systemd user unit")
    render.set_defaults(run=_render_unit_command)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (SettingsError, TargetError, SlotError) as exc:
        print("secret-drop: %s" % exc, file=sys.stderr)
        return 1
    except OSError:
        print("secret-drop: internal_error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
