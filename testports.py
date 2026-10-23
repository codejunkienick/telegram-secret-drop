"""Loopback port picker shared by the fake-only test suite.

With TEST_PORT_RANGE unset, free_port keeps the old bind-to-0 probe and
the kernel picks the port. With TEST_PORT_RANGE set to LOW-HIGH,
free_port returns a port inside that range, so a host with a loopback
firewall can point the suite at its allowed ports.
"""

import os
import re
import socket

_NAME = "TEST_PORT_RANGE"

_RANGE = re.compile(r"([0-9]+)-([0-9]+)")


def _parse_range(text):
    match = _RANGE.fullmatch(text)
    if match is None:
        raise RuntimeError(
            "%s=%r: want LOW-HIGH with 1024 <= LOW <= HIGH <= 65535"
            % (_NAME, text))
    low, high = int(match.group(1)), int(match.group(2))
    if not 1024 <= low <= high <= 65535:
        raise RuntimeError(
            "%s=%r: want LOW-HIGH with 1024 <= LOW <= HIGH <= 65535"
            % (_NAME, text))
    return low, high


def free_port():
    """Return a free loopback port for a test server to bind."""
    raw = os.environ.get(_NAME)
    if raw is None:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port
    low, high = _parse_range(raw)
    size = high - low + 1
    start = os.getpid() % size
    for step in range(size):
        port = low + (start + step) % size
        sock = socket.socket()
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            sock.close()
            continue
        sock.close()
        assert low <= port <= high, "%s=%r: picked %d outside range" % (
            _NAME, raw, port)
        return port
    raise RuntimeError(
        "%s=%r: no free port in %d-%d" % (_NAME, raw, low, high))
