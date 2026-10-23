"""Unit tests for the testports loopback port picker.

Fake-only: the helper only probes 127.0.0.1 and the tests only bind
ports the helper returns. No settings file, no unit, no other host.
"""

import os
import socket
import unittest
import unittest.mock

from testports import free_port


def _style_range():
    """A LOW-HIGH range that stays inside the ambient one when set."""
    ambient = os.environ.get("TEST_PORT_RANGE")
    try:
        low, high = (int(part) for part in ambient.split("-"))
    except (AttributeError, ValueError):
        return "9300-9399"
    if ambient == "9300-9399" or not 1024 <= low <= high <= 65535:
        return "9300-9399"
    mid = (low + high) // 2
    return "%d-%d" % (mid, min(mid + 24, high))


def _hold(port):
    hold = socket.socket()
    hold.bind(("127.0.0.1", port))
    hold.listen(1)
    return hold


class FreePortCase(unittest.TestCase):
    def test_unset_probes_a_free_port(self):
        env = dict(os.environ)
        env.pop("TEST_PORT_RANGE", None)
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            port = free_port()
        self.assertTrue(1024 <= port <= 65535)
        hold = _hold(port)
        self.addCleanup(hold.close)

    def test_range_returns_port_inside(self):
        wanted = _style_range()
        low, high = (int(part) for part in wanted.split("-"))
        with unittest.mock.patch.dict(
                os.environ, {"TEST_PORT_RANGE": wanted}):
            port = free_port()
        self.assertTrue(low <= port <= high)
        hold = _hold(port)
        self.addCleanup(hold.close)

    def test_malformed_range_fails(self):
        for bad in ("", "9300", "9399-9300", "80-90", "a-b",
                    "\u00b2-\u00b3",
                    "\u0661\u0662\u0663\u0664-\u0661\u0662\u0663\u0665",
                    " 9300-9399"):
            with self.subTest(value=bad):
                with unittest.mock.patch.dict(
                        os.environ, {"TEST_PORT_RANGE": bad}):
                    with self.assertRaisesRegex(
                            RuntimeError, "TEST_PORT_RANGE"):
                        free_port()

    def test_taken_single_port_range_fails(self):
        env = dict(os.environ)
        env.pop("TEST_PORT_RANGE", None)
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            port = free_port()
        hold = _hold(port)
        self.addCleanup(hold.close)
        with unittest.mock.patch.dict(
                os.environ,
                {"TEST_PORT_RANGE": "%d-%d" % (port, port)}):
            with self.assertRaisesRegex(RuntimeError, "TEST_PORT_RANGE"):
                free_port()


if __name__ == "__main__":
    unittest.main()
