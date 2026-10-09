"""Comprehensive Unit and Integration Tests for Agent Egress Sentinel.

Tests Collector, Rules Engine, TLS SNI Parser, Egress Proxy, Server APIs, and Process Runner.
Zero external test dependencies (uses standard library unittest / pytest).
"""

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
import urllib.request
from pathlib import Path
from urllib.error import HTTPError

# Ensure src is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_egress_sentinel.collector import EgressCollector, NetworkEvent
from agent_egress_sentinel.process_runner import AgentProcessRunner
from agent_egress_sentinel.proxy import EgressProxy, extract_sni_hostname
from agent_egress_sentinel.rules_engine import DomainCategory, RulesEngine
from agent_egress_sentinel.server import EgressServer


def make_tls_client_hello(hostname: str) -> bytes:
    """Synthesize a real TLS 1.2 ClientHello packet with SNI extension."""
    host_bytes = hostname.encode("ascii")
    # server_name extension (type 0x0000)
    sni_data = (
        struct.pack("!H", len(host_bytes) + 3)  # list length
        + b"\x00"  # name_type: host_name
        + struct.pack("!H", len(host_bytes))
        + host_bytes
    )
    ext_data = struct.pack("!HH", 0x0000, len(sni_data)) + sni_data

    # ClientHello body
    session_id = b"\x00"
    ciphers = struct.pack("!H", 2) + b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
    compression = b"\x01\x00"
    extensions = struct.pack("!H", len(ext_data)) + ext_data

    client_hello_payload = (
        b"\x03\x03"  # TLS 1.2
        + (b"\xaa" * 32)  # 32 bytes random
        + session_id
        + ciphers
        + compression
        + extensions
    )

    # Handshake header: type 0x01 (ClientHello), 3 bytes length
    handshake_msg = b"\x01" + struct.pack("!I", len(client_hello_payload))[1:] + client_hello_payload

    # TLS Record header: type 0x16 (Handshake), version 0x0301, 2 bytes length
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake_msg)) + handshake_msg
    return record


class TestCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_egress.db")
        self.collector = EgressCollector(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_record_and_get_events(self):
        event = NetworkEvent(
            agent_name="test_agent",
            domain="api.openai.com",
            remote_ip="104.18.2.1",
            remote_port=443,
            protocol="HTTPS",
            method="CONNECT",
            url_path="/v1/chat/completions",
            bytes_sent=1500,
            bytes_recv=4200,
            category="llm_api",
        )
        self.collector.record(event)

        events = self.collector.get_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["domain"], "api.openai.com")
        self.assertEqual(events[0]["bytes_sent"], 1500)
        self.assertEqual(events[0]["category"], "llm_api")

    def test_domain_aggregation_and_stats(self):
        self.collector.record(NetworkEvent(domain="api.anthropic.com", bytes_sent=100, bytes_recv=200, category="llm_api"))
        self.collector.record(NetworkEvent(domain="api.anthropic.com", bytes_sent=300, bytes_recv=400, category="llm_api"))
        self.collector.record(NetworkEvent(domain="segment.io", bytes_sent=50, bytes_recv=50, category="telemetry_tracker", quarantined=True))

        domains = self.collector.get_domains()
        self.assertEqual(len(domains), 2)

        anthropic_stat = next(d for d in domains if d["domain"] == "api.anthropic.com")
        self.assertEqual(anthropic_stat["request_count"], 2)
        self.assertEqual(anthropic_stat["total_bytes_sent"], 400)
        self.assertEqual(anthropic_stat["total_bytes_recv"], 600)

        stats = self.collector.get_stats()
        self.assertEqual(stats["total_requests"], 3)
        self.assertEqual(stats["total_domains"], 2)
        self.assertEqual(stats["total_quarantined"], 1)

    def test_export_har(self):
        self.collector.record(NetworkEvent(domain="api.groq.com", bytes_sent=500, bytes_recv=1200, category="llm_api"))
        har = self.collector.export_har()
        self.assertIn("log", har)
        self.assertEqual(har["log"]["version"], "1.2")
        self.assertEqual(len(har["log"]["entries"]), 1)
        self.assertIn("api.groq.com", har["log"]["entries"][0]["request"]["url"])

    def test_clear_logs(self):
        self.collector.record(NetworkEvent(domain="huggingface.co"))
        self.assertEqual(len(self.collector.get_events()), 1)
        self.collector.clear()
        self.assertEqual(len(self.collector.get_events()), 0)


class TestRulesEngine(unittest.TestCase):
    def setUp(self):
        self.rules = RulesEngine()

    def test_taxonomy_classification(self):
        # LLM APIs
        self.assertEqual(self.rules.classify("api.openai.com"), DomainCategory.LLM_API)
        self.assertEqual(self.rules.classify("api.anthropic.com"), DomainCategory.LLM_API)
        self.assertEqual(self.rules.classify("generativelanguage.googleapis.com"), DomainCategory.LLM_API)
        self.assertEqual(self.rules.classify("api.deepseek.com"), DomainCategory.LLM_API)
        self.assertEqual(self.rules.classify("api.groq.com"), DomainCategory.LLM_API)

        # Model Hubs
        self.assertEqual(self.rules.classify("huggingface.co"), DomainCategory.MODEL_HUB)
        self.assertEqual(self.rules.classify("replicate.com"), DomainCategory.MODEL_HUB)

        # Telemetry
        self.assertEqual(self.rules.classify("api.segment.io"), DomainCategory.TELEMETRY_TRACKER)
        self.assertEqual(self.rules.classify("telemetry.sentry.io"), DomainCategory.TELEMETRY_TRACKER)
        self.assertEqual(self.rules.classify("posthog.com"), DomainCategory.TELEMETRY_TRACKER)

        # Local
        self.assertEqual(self.rules.classify("localhost"), DomainCategory.LOCAL_SERVICE)
        self.assertEqual(self.rules.classify("127.0.0.1"), DomainCategory.LOCAL_SERVICE)

    def test_quarantine_policy_enforcement(self):
        # Allow all policy
        self.rules.set_quarantine_mode("allow_all")
        allowed, _ = self.rules.is_allowed("api.segment.io")
        self.assertTrue(allowed)

        # Block telemetry policy
        self.rules.set_quarantine_mode("block_telemetry")
        allowed, reason = self.rules.is_allowed("api.segment.io")
        self.assertFalse(allowed)
        self.assertIn("telemetry", reason.lower())

        allowed_llm, _ = self.rules.is_allowed("api.openai.com")
        self.assertTrue(allowed_llm)

        # Zero egress policy (only local permitted)
        self.rules.set_quarantine_mode("zero_egress")
        allowed_external, _ = self.rules.is_allowed("api.openai.com")
        self.assertFalse(allowed_external)
        allowed_local, _ = self.rules.is_allowed("localhost")
        self.assertTrue(allowed_local)

    def test_custom_allow_and_block_lists(self):
        self.rules.set_quarantine_mode("allow_all")
        self.rules.add_blocked_domain("bad-actor.net")
        allowed, reason = self.rules.is_allowed("bad-actor.net")
        self.assertFalse(allowed)

        self.rules.remove_blocked_domain("bad-actor.net")
        allowed, _ = self.rules.is_allowed("bad-actor.net")
        self.assertTrue(allowed)


class TestTLSParser(unittest.TestCase):
    def test_sni_extraction(self):
        packet = make_tls_client_hello("api.deepseek.com")
        sni = extract_sni_hostname(packet)
        self.assertEqual(sni, "api.deepseek.com")

    def test_sni_extraction_invalid(self):
        invalid_data = b"NOT_TLS_DATA_1234567890"
        self.assertIsNone(extract_sni_hostname(invalid_data))


class TestProxyAndServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test_srv.db")
        cls.collector = EgressCollector(db_path=cls.db_path)
        cls.rules = RulesEngine(quarantine_mode="allow_all")

        # Bind to ephemeral test ports
        cls.proxy = EgressProxy(host="127.0.0.1", port=18096, collector=cls.collector, rules_engine=cls.rules)
        cls.proxy.start()

        cls.server = EgressServer(("127.0.0.1", 18095), collector=cls.collector, rules=cls.rules, proxy=cls.proxy)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.server.shutdown()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_server_rest_stats_and_domains(self):
        url = "http://127.0.0.1:18095/api/stats"
        req = urllib.request.urlopen(url, timeout=3.0)
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode("utf-8"))
        self.assertIn("total_requests", data)
        self.assertTrue(data["proxy_running"])

    def test_quarantine_api_endpoint(self):
        url = "http://127.0.0.1:18095/api/quarantine"
        payload = json.dumps({"mode": "block_telemetry"}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(data["quarantine_mode"], "block_telemetry")

        # Reset to allow_all
        payload = json.dumps({"mode": "allow_all"}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3.0)


class TestProcessRunner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.collector = EgressCollector(db_path=os.path.join(self.temp_dir, "runner.db"))
        self.runner = AgentProcessRunner(
            proxy_host="127.0.0.1",
            proxy_port=18096,
            collector=self.collector,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_run_command_execution(self):
        cmd = ["python3", "-c", "import os; print('AGENT_READY:' + os.environ.get('HTTP_PROXY', 'none'))"]
        result = self.runner.run(cmd=cmd, agent_name="test_runner_agent")

        self.assertEqual(result["exit_code"], 0)
        self.assertIn("AGENT_READY:http://127.0.0.1:18096", result["stdout"])
        self.assertGreater(result["elapsed_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
