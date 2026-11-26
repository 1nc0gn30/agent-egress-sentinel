"""Only local pages (strict regex + valid port) or explicit Studio origin may call this server."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from agent_egress_sentinel.server import _is_local_origin, _is_valid_host


class TestOriginGuard(unittest.TestCase):
    def test_allowed_origins(self):
        for o in (
            None,
            "",
            "http://127.0.0.1:8095",
            "http://127.0.0.1:3000",
            "http://localhost:3000",
            "https://localhost:8443",
            "http://[::1]:1",
            "http://[::1]:65535",
            "https://zoth.nullai.tech",
        ):
            self.assertTrue(_is_local_origin(o), f"Expected allowed: {o}")

    def test_blocked_origins(self):
        for o in (
            "https://evil.example",
            "null",
            "http://127.0.0.1.evil.com",
            "http://127.0.0.1:8095.example.invalid",
            "http://localhost:3000.attacker.test",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:0",
            "http://127.0.0.1:8095/path",
            "http://user@127.0.0.1:8095",
            "http://127.0.0.1:8095?foo=bar",
            "http://127.0.0.1:8095#frag",
            "file://",
            "chrome-extension://abc",
        ):
            self.assertFalse(_is_local_origin(o), f"Expected blocked: {o}")

    def test_host_validation(self):
        for h in ("127.0.0.1:8095", "localhost:8095", "[::1]:8095", "127.0.0.1", "localhost"):
            self.assertTrue(_is_valid_host(h, server_port=8095), f"Expected valid host: {h}")

        for h in ("", None, "evil.example:8095", "127.0.0.1:8095.evil.com", "127.0.0.1:9999", "evil.example"):
            self.assertFalse(_is_valid_host(h, server_port=8095), f"Expected invalid host: {h}")


if __name__ == "__main__":
    unittest.main()
