"""Security, Proxy SSRF, SNI Pre-Relay, API Validation, and Stdio MCP Tests (v2.6.0)."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_egress_sentinel import __version__
from agent_egress_sentinel.collector import EgressCollector
from agent_egress_sentinel.mcp_server import EgressMCPServer
from agent_egress_sentinel.proxy import EgressProxy, parse_host_port
from agent_egress_sentinel.rules_engine import DomainCategory, RulesEngine
from agent_egress_sentinel.server import EgressServer


def make_tls_client_hello(hostname: str) -> bytes:
    host_bytes = hostname.encode("ascii")
    sni_data = struct.pack("!H", len(host_bytes) + 3) + b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
    ext_data = struct.pack("!HH", 0x0000, len(sni_data)) + sni_data
    body = b"\x03\x03" + (b"\xaa" * 32) + b"\x00" + struct.pack("!H", 2) + b"\x00\x2f" + b"\x01\x00" + struct.pack("!H", len(ext_data)) + ext_data
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class TestSecurityAndAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "sec_test.db")
        cls.api_token = "test-sentinel-token-0123456789abcdef"
        cls.collector = EgressCollector(db_path=cls.db_path, neuro_sync_enabled=False)
        cls.rules = RulesEngine(quarantine_mode="allow_all")

        cls.proxy = EgressProxy(host="127.0.0.1", port=0, collector=cls.collector, rules_engine=cls.rules)
        cls.proxy.start()
        cls.proxy_port = cls.proxy.port

        cls.server = EgressServer(
            ("127.0.0.1", 0),
            collector=cls.collector,
            rules=cls.rules,
            proxy=cls.proxy,
            api_token=cls.api_token,
        )
        cls.web_port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.collector.close()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _raw_request(self, method: str, path: str, headers=None, body: bytes | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.web_port, timeout=3.0)
        hdrs = dict(headers or {})
        if "Host" not in hdrs:
            hdrs["Host"] = f"127.0.0.1:{self.web_port}"
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, resp_headers, data

    def test_version_and_server_header(self):
        status, hdrs, body = self._raw_request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertIn(f"AgentEgressSentinel/{__version__}", hdrs.get("server", ""))
        self.assertEqual(hdrs.get("vary"), "Origin")
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(payload["version"], "2.6.0")
        self.assertEqual(payload["proxy_port"], self.proxy_port)

    def test_get_root_has_no_acao(self):
        status, hdrs, _ = self._raw_request("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn("access-control-allow-origin", hdrs)

    def test_malformed_origin_bypass_rejected_403(self):
        spoof = f"http://127.0.0.1:{self.web_port}.example.invalid"
        status, hdrs, _ = self._raw_request(
            "POST",
            "/api/quarantine",
            headers={"Origin": spoof, "Content-Type": "application/json"},
            body=json.dumps({"mode": "zero_egress"}).encode("utf-8"),
        )
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", hdrs)

        opt_status, opt_hdrs, _ = self._raw_request("OPTIONS", "/api/quarantine", headers={"Origin": spoof})
        self.assertEqual(opt_status, 403)
        self.assertNotIn("access-control-allow-origin", opt_hdrs)

    def test_foreign_host_header_rejected_403(self):
        status, _, _ = self._raw_request("GET", "/api/stats", headers={"Host": f"evil.example:{self.web_port}"})
        self.assertEqual(status, 403)

    def test_api_run_requires_token(self):
        # Missing token -> 401
        status, _, body = self._raw_request(
            "POST",
            "/api/run",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"command": "python3 -c 'print(1)'"}).encode("utf-8"),
        )
        self.assertEqual(status, 401)
        self.assertNotIn("/home/", body.decode("utf-8"))

        # Wrong token -> 401
        status_bad, _, _ = self._raw_request(
            "POST",
            "/api/run",
            headers={"Content-Type": "application/json", "X-Sentinel-Token": "wrong-token"},
            body=json.dumps({"command": "python3 -c 'print(1)'"}).encode("utf-8"),
        )
        self.assertEqual(status_bad, 401)

        # Valid Bearer token -> 200
        status_ok, _, body_ok = self._raw_request(
            "POST",
            "/api/run",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_token}"},
            body=json.dumps({"command": "python3 -c 'print(42)'", "agent_name": "pytest_runner"}).encode("utf-8"),
        )
        self.assertEqual(status_ok, 200)
        self.assertEqual(json.loads(body_ok)["status"], "spawned")

    def test_api_record_without_category_does_not_crash(self):
        status, _, body = self._raw_request(
            "POST",
            "/api/record",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"domain": "api.openai.com", "agent_name": "unit_test"}).encode("utf-8"),
        )
        self.assertEqual(status, 200)
        parsed = json.loads(body)
        self.assertEqual(parsed["event"]["category"], "llm_api")

    def test_api_traffic_bad_limit_returns_400(self):
        status, _, body = self._raw_request("GET", "/api/traffic?limit=abc")
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(body))

        status_neg, _, _ = self._raw_request("GET", "/api/traffic?limit=-5")
        self.assertEqual(status_neg, 400)

    def test_non_dict_json_body_returns_400(self):
        status, _, _ = self._raw_request(
            "POST",
            "/api/quarantine",
            headers={"Content-Type": "application/json"},
            body=b'["not-an-object"]',
        )
        self.assertEqual(status, 400)

    def test_unknown_api_route_returns_404_json(self):
        status, hdrs, body = self._raw_request("GET", "/api/events")
        self.assertEqual(status, 404)
        self.assertIn("application/json", hdrs.get("content-type", ""))
        self.assertEqual(json.loads(body)["error"], "Unknown API route")

    def test_static_path_traversal_returns_404(self):
        for raw_path in ("/../server.py", "/%2e%2e/server.py", "/..%2fserver.py", "/%2e%2e%2fpyproject.toml"):
            status, _, body = self._raw_request("GET", raw_path)
            self.assertEqual(status, 404, f"Expected 404 for {raw_path}, got {status}")
            self.assertNotIn(b"AGENT EGRESS SENTINEL", body)

    def test_rules_add_and_delete_endpoints(self):
        st_add, _, _ = self._raw_request(
            "POST",
            "/api/rules/block",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"domain": "tracker.bad.invalid"}).encode("utf-8"),
        )
        self.assertEqual(st_add, 200)

        st_allow, _, _ = self._raw_request(
            "POST",
            "/api/rules/allow",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"domain": "safe.good.invalid"}).encode("utf-8"),
        )
        self.assertEqual(st_allow, 200)

        _, _, rules_raw = self._raw_request("GET", "/api/rules")
        rules = json.loads(rules_raw)
        self.assertIn("tracker.bad.invalid", rules["blocked_domains"])
        self.assertIn("safe.good.invalid", rules["allowed_domains"])

        st_del_b, _, _ = self._raw_request("DELETE", "/api/rules/block?domain=tracker.bad.invalid")
        self.assertEqual(st_del_b, 200)
        st_del_a, _, _ = self._raw_request("DELETE", "/api/rules/allow?domain=safe.good.invalid")
        self.assertEqual(st_del_a, 200)

        _, _, rules_after = self._raw_request("GET", "/api/rules")
        parsed_after = json.loads(rules_after)
        self.assertNotIn("tracker.bad.invalid", parsed_after["blocked_domains"])
        self.assertNotIn("safe.good.invalid", parsed_after["allowed_domains"])

    def test_proxy_ssrf_and_zero_egress_self_escape_blocked(self):
        # 1. Under zero_egress, proxy MUST block 127.0.0.1:<web_port> (self-escape!)
        self.rules.set_quarantine_mode("zero_egress")
        s = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3.0)
        s.sendall(
            f"GET http://127.0.0.1:{self.web_port}/health HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.web_port}\r\n"
            f"Connection: close\r\n\r\n".encode("ascii")
        )
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        self.assertIn("403 Forbidden", resp)

        # 2. Under allow_all, proxy MUST still block RFC1918 & cloud metadata 169.254.169.254
        self.rules.set_quarantine_mode("allow_all")
        for target in ("169.254.169.254:80", "10.0.0.1:80", "172.16.0.1:80", "192.168.1.1:80", "[fc00::1]:80", "[fe80::1]:80"):
            sock = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3.0)
            sock.sendall(
                f"GET http://{target}/latest/meta-data/ HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
            r = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()
            self.assertIn("403 Forbidden", r, f"Expected SSRF 403 for {target}, got: {r[:80]}")

        # 3. Unsupported scheme & missing host rejected with 400
        sock = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3.0)
        sock.sendall(b"GET ftp://example.invalid/file HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n")
        r_ftp = sock.recv(4096).decode("utf-8", errors="replace")
        sock.close()
        self.assertIn("400 Bad Request", r_ftp)

    def test_connect_sni_re_evaluation_blocks_before_relaying(self):
        # Start a local dummy TCP listener that records any bytes it receives
        received_chunks = []
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener_port = listener.getsockname()[1]
        listener.listen(2)
        listener.settimeout(3.0)

        def _accept_one():
            try:
                conn, _ = listener.accept()
                conn.settimeout(1.0)
                try:
                    data = conn.recv(4096)
                    if data:
                        received_chunks.append(data)
                except Exception:
                    pass
                conn.close()
            except Exception:
                pass

        t = threading.Thread(target=_accept_one, daemon=True)
        t.start()

        # Enable block_telemetry; CONNECT to 127.0.0.1:<listener_port> is allowed,
        # but TLS ClientHello advertises SNI api.segment.io (telemetry -> BLOCKED before relay!)
        self.rules.set_quarantine_mode("block_telemetry")
        client = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3.0)
        client.sendall(f"CONNECT 127.0.0.1:{listener_port} HTTP/1.1\r\nHost: 127.0.0.1:{listener_port}\r\n\r\n".encode("ascii"))
        connect_resp = client.recv(1024)
        self.assertIn(b"200 Connection Established", connect_resp)

        # Send ClientHello with telemetry SNI
        client.sendall(make_tls_client_hello("api.segment.io"))
        time.sleep(0.35)
        client.close()
        t.join(timeout=2.0)
        listener.close()

        # Zero bytes must have been relayed to upstream listener!
        self.assertEqual(received_chunks, [], "Blocked SNI payload must NEVER be relayed upstream")

        # Verify quarantined SNI event was logged
        events = self.collector.get_events(domain="api.segment.io", limit=5)
        self.assertTrue(any(e["quarantined"] and "SNI" in e["notes"] for e in events))
        self.rules.set_quarantine_mode("allow_all")

    def test_mcp_server_jsonrpc(self):
        mcp = EgressMCPServer(base_url=f"http://127.0.0.1:{self.web_port}")

        init_resp = mcp.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(init_resp["result"]["serverInfo"]["version"], "2.6.0")

        list_resp = mcp.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tool_names = [t["name"] for t in list_resp["result"]["tools"]]
        self.assertEqual(tool_names, ["egress_audit_status", "egress_set_quarantine", "egress_manage_rules"])

        call_status = mcp.handle_message({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "egress_audit_status", "arguments": {}},
        })
        self.assertFalse(call_status["result"]["isError"])
        sc = call_status["result"]["structuredContent"]
        self.assertTrue(sc["daemonOnline"])
        self.assertEqual(sc["proxyPort"], self.proxy_port)

        call_q = mcp.handle_message({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "egress_set_quarantine", "arguments": {"mode": "block_telemetry"}},
        })
        self.assertEqual(call_q["result"]["structuredContent"]["quarantineMode"], "block_telemetry")

        call_rule = mcp.handle_message({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "egress_manage_rules", "arguments": {"action": "add_block", "domain": "mcp-test.invalid"}},
        })
        self.assertIn("mcp-test.invalid", call_rule["result"]["structuredContent"]["rules"]["blocked_domains"])

        mcp.handle_message({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "egress_manage_rules", "arguments": {"action": "remove_block", "domain": "mcp-test.invalid"}},
        })
        mcp.handle_message({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "egress_set_quarantine", "arguments": {"mode": "allow_all"}},
        })

    def test_ipv6_parse_host_port(self):
        self.assertEqual(parse_host_port("[::1]:8095", 80), ("::1", 8095))
        self.assertEqual(parse_host_port("[::1]", 443), ("::1", 443))
        self.assertIsNone(parse_host_port("example.com:99999", 80))
        self.assertIsNone(parse_host_port("example.com:notaport", 80))


if __name__ == "__main__":
    unittest.main()
