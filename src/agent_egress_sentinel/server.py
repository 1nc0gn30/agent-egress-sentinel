"""HTTP REST & SSE Radar Server for Agent Egress Sentinel.

Serves the visual domain radar dashboard and provides real-time REST/SSE APIs
for traffic inspection, quarantine policy control, and agent execution.
100% Python Standard Library.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import queue
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .collector import EgressCollector, NetworkEvent, get_default_collector
from .process_runner import AgentProcessRunner
from .proxy import EgressProxy
from .rules_engine import RulesEngine

logger = logging.getLogger("agent_egress.server")


class EgressRequestHandler(SimpleHTTPRequestHandler):
    """Custom request handler dispatching API endpoints and static assets."""

    server_version = "AgentEgressSentinel/0.1.0"

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Agent-Name")

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        # SSE Real-Time Stream
        if path == "/api/stream":
            self._handle_sse_stream()
            return

        # REST Endpoints
        if path == "/api/stats":
            stats = self.server.collector.get_stats()
            stats["proxy_running"] = self.server.proxy.is_running if self.server.proxy else False
            stats["proxy_port"] = self.server.proxy.port if self.server.proxy else None
            stats["quarantine_mode"] = self.server.rules.quarantine_mode
            self._send_json(stats)
            return

        if path == "/api/domains":
            domains = self.server.collector.get_domains()
            self._send_json({"domains": domains, "total": len(domains)})
            return

        if path == "/api/traffic":
            limit = int(query.get("limit", [100])[0])
            offset = int(query.get("offset", [0])[0])
            domain = query.get("domain", [None])[0]
            category = query.get("category", [None])[0]
            agent_name = query.get("agent", [None])[0]

            events = self.server.collector.get_events(
                domain=domain,
                agent_name=agent_name,
                category=category,
                limit=limit,
                offset=offset,
            )
            self._send_json({"events": events, "count": len(events)})
            return

        if path == "/api/rules":
            self._send_json(self.server.rules.get_summary())
            return

        if path == "/api/export":
            har_data = self.server.collector.export_har()
            payload = json.dumps(har_data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'attachment; filename="agent-egress.har"')
            self.send_header("Content-Length", str(len(payload)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(payload)
            return

        if path in ("/api/export/openapi", "/api/openapi"):
            spec = self.server.collector.export_openapi()
            payload = json.dumps(spec, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'attachment; filename="openapi-spec.json"')
            self.send_header("Content-Length", str(len(payload)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(payload)
            return

        # Static Assets from public/ directory
        self._serve_static(path)

    def do_POST(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            data = json.loads(body) if body.strip() else {}
        except Exception:
            data = {}

        if path == "/api/quarantine":
            mode = data.get("mode")
            if not mode:
                self._send_json({"error": "Missing 'mode' field"}, 400)
                return
            try:
                self.server.rules.set_quarantine_mode(mode)
                self._send_json({"status": "ok", "quarantine_mode": self.server.rules.quarantine_mode})
            except ValueError as e:
                self._send_json({"error": str(e)}, 400)
            return

        if path == "/api/rules/block":
            domain = data.get("domain")
            if not domain:
                self._send_json({"error": "Missing 'domain' field"}, 400)
                return
            self.server.rules.add_blocked_domain(domain)
            self._send_json({"status": "ok", "blocked": domain})
            return

        if path == "/api/rules/allow":
            domain = data.get("domain")
            if not domain:
                self._send_json({"error": "Missing 'domain' field"}, 400)
                return
            self.server.rules.add_allowed_domain(domain)
            self._send_json({"status": "ok", "allowed": domain})
            return

        if path == "/api/clear":
            self.server.collector.clear()
            self._send_json({"status": "ok", "message": "Egress logs cleared"})
            return

        if path == "/api/run":
            cmd = data.get("command")
            agent_name = data.get("agent_name", "web_triggered_agent")
            if not cmd:
                self._send_json({"error": "Missing 'command' string"}, 400)
                return

            runner = AgentProcessRunner(
                proxy_host=self.server.proxy.host,
                proxy_port=self.server.proxy.port,
                collector=self.server.collector,
                rules=self.server.rules,
            )
            import shlex
            cmd_args = shlex.split(cmd)
            # Run in worker thread to prevent blocking
            def _async_exec():
                runner.run(cmd_args, agent_name=agent_name)

            t = threading.Thread(target=_async_exec, daemon=True)
            t.start()
            self._send_json({"status": "spawned", "command": cmd, "agent_name": agent_name})
            return

        self._send_json({"error": "Endpoint not found"}, 404)

    def _serve_static(self, path: str) -> None:
        """Serve files from the public folder."""
        public_dir = Path(__file__).resolve().parent.parent.parent / "public"
        if not public_dir.exists():
            public_dir = Path.cwd() / "public"

        if path in ("/", ""):
            req_file = public_dir / "index.html"
        else:
            clean_rel = path.lstrip("/")
            req_file = public_dir / clean_rel

        if req_file.exists() and req_file.is_file():
            mime, _ = mimetypes.guess_type(str(req_file))
            mime = mime or "application/octet-stream"
            try:
                content = req_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_error(500, f"Error reading file: {e}")
        else:
            # SPA Fallback
            index_file = public_dir / "index.html"
            if index_file.exists():
                content = index_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "File not found")

    def _handle_sse_stream(self) -> None:
        """Stream real-time network events using Server-Sent Events (SSE)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        # Stream initial ping
        self.wfile.write(b": connected to agent-egress-sentinel sse\n\n")
        self.wfile.flush()

        # Poll for new events from collector
        last_seen_time = time.time() - 5.0
        try:
            while True:
                events = self.server.collector.get_events(limit=20)
                new_events = [e for e in events if e["timestamp"] > last_seen_time]
                if new_events:
                    for e in reversed(new_events):
                        data_line = f"data: {json.dumps(e)}\n\n"
                        self.wfile.write(data_line.encode("utf-8"))
                        if e["timestamp"] > last_seen_time:
                            last_seen_time = e["timestamp"]
                    self.wfile.flush()

                # Heartbeat keep-alive every 2 seconds
                self.wfile.write(b": heartbeat\n\n")
                self.wfile.flush()
                time.sleep(1.0)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class EgressServer(ThreadingHTTPServer):
    """Custom ThreadingHTTPServer holding collector, rules, and proxy references."""

    def __init__(
        self,
        server_address: Tuple[str, int],
        collector: Optional[EgressCollector] = None,
        rules: Optional[RulesEngine] = None,
        proxy: Optional[EgressProxy] = None,
    ):
        self.collector = collector or get_default_collector()
        self.rules = rules or RulesEngine()
        self.proxy = proxy
        super().__init__(server_address, EgressRequestHandler)


def run_server(
    web_host: str = "0.0.0.0",
    web_port: int = 8095,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8096,
    collector: Optional[EgressCollector] = None,
    rules: Optional[RulesEngine] = None,
) -> Tuple[EgressServer, EgressProxy]:
    """Start both the EgressProxy and the Web/API EgressServer."""
    collector = collector or get_default_collector()
    rules = rules or RulesEngine()

    proxy = EgressProxy(host=proxy_host, port=proxy_port, collector=collector, rules_engine=rules)
    proxy.start()

    server = EgressServer((web_host, web_port), collector=collector, rules=rules, proxy=proxy)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="EgressServerThread")
    server_thread.start()

    logger.info("Agent Egress Sentinel UI running at http://%s:%d", web_host, web_port)
    logger.info("Agent Egress Proxy running at %s:%d", proxy_host, proxy_port)

    return server, proxy
