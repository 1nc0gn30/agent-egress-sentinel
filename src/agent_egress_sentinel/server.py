"""HTTP REST & SSE Radar Server for Agent Egress Sentinel.

Serves the visual domain radar dashboard and provides real-time REST/SSE APIs
for traffic inspection, quarantine policy control, rule editing, and token-gated
agent execution. 100% Python Standard Library.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import re
import secrets
import shlex
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__
from .collector import EgressCollector, NetworkEvent, get_default_collector
from .process_runner import AgentProcessRunner
from .proxy import EgressProxy
from .rules_engine import RulesEngine

logger = logging.getLogger("agent_egress.server")

MAX_JSON_BODY_BYTES = 1_048_576  # 1 MiB
_LOCAL_ORIGIN_RE = re.compile(
    r"^https?://(127\.0\.0\.1|localhost|\[::1\])(?::(\d{1,5}))?$",
    re.IGNORECASE,
)
_LOCAL_HOST_RE = re.compile(
    r"^(127\.0\.0\.1|localhost|\[::1\])(?::(\d{1,5}))?$",
    re.IGNORECASE,
)
_EXPLICIT_ALLOWED_ORIGINS = frozenset({
    "https://zoth.nullai.tech",
})


def _safe_rel(raw: str) -> str:
    """Request path -> safe relative path inside a static dir; '' if traversal or absolute."""
    rel = unquote(str(raw or "")).replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts) or ":" in (parts[0] if parts else ""):
        return ""
    return "/".join(parts)


def _has_traversal_attempt(raw_path: str) -> bool:
    """Detect path traversal attempts (raw or percent-encoded) so they return 404 instead of SPA fallback."""
    decoded = unquote(str(raw_path or ""))
    if "\\" in decoded:
        return True
    segments = [s for s in decoded.split("/") if s]
    if any(s == ".." for s in segments):
        return True
    if segments and ":" in segments[0]:
        return True
    return False


def _is_local_origin(origin: Optional[str]) -> bool:
    """Strict Origin check for CSRF protection.

    No Origin header = non-browser client (CLI/agent): allowed.
    Otherwise ONLY exact http(s)://(127.0.0.1|localhost|[::1])[:valid_port] with no path,
    userinfo, query, or fragment, or explicit trusted Studio origin https://zoth.nullai.tech.
    """
    if not origin:
        return True
    if not isinstance(origin, str) or any(c.isspace() for c in origin):
        return False
    if origin in _EXPLICIT_ALLOWED_ORIGINS:
        return True
    m = _LOCAL_ORIGIN_RE.fullmatch(origin)
    if not m:
        return False
    port_str = m.group(2)
    if port_str is not None:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return False
    return True


def _is_valid_host(host_header: Optional[str], server_port: Optional[int] = None) -> bool:
    """Strict HTTP Host header check to prevent DNS rebinding."""
    if not host_header:
        return False
    if any(c.isspace() for c in host_header):
        return False
    m = _LOCAL_HOST_RE.fullmatch(host_header.strip())
    if not m:
        return False
    port_str = m.group(2)
    if port_str is not None:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return False
        if server_port is not None and port != server_port:
            return False
    return True


def get_token_file_path() -> Path:
    override = os.environ.get("EGRESS_TOKEN_FILE", "").strip()
    if override:
        return Path(override)
    return Path.home() / ".config" / "agent-egress-sentinel" / "token"


def get_or_create_api_token() -> str:
    """Return the per-user 0600 API token used to authorize POST /api/run."""
    env_token = os.environ.get("EGRESS_SENTINEL_TOKEN", "").strip()
    if env_token:
        return env_token

    token_path = get_token_file_path()
    try:
        if token_path.exists():
            existing = token_path.read_text(encoding="utf-8").strip()
            if len(existing) >= 16:
                try:
                    os.chmod(token_path, 0o600)
                except OSError:
                    pass
                return existing
    except OSError as exc:
        logger.warning("Could not read sentinel token file: %s", exc)

    token = secrets.token_urlsafe(32)
    try:
        token_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(token_path.parent, 0o700)
        except OSError:
            pass
        fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(token + "\n")
        os.chmod(token_path, 0o600)
    except OSError as exc:
        logger.warning("Could not persist sentinel token file: %s", exc)
    return token


class EgressRequestHandler(SimpleHTTPRequestHandler):
    """Custom request handler dispatching API endpoints and static assets."""

    server_version = f"AgentEgressSentinel/{__version__}"

    def _validate_host(self) -> bool:
        server_port = self.server.server_address[1] if hasattr(self.server, "server_address") else None
        host_hdr = self.headers.get("Host")
        if not _is_valid_host(host_hdr, server_port=server_port):
            self._send_json({"error": "Forbidden: invalid Host header"}, status=403, include_cors=False)
            return False
        return True

    def _send_cors_headers(self, allow_origin: bool = True) -> None:
        self.send_header("Vary", "Origin")
        origin = self.headers.get("Origin")
        if allow_origin and origin and _is_local_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Agent-Name, X-Sentinel-Token")

    def _send_json(self, data: Any, status: int = 200, include_cors: bool = True) -> None:
        payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        if include_cors:
            self._send_cors_headers(allow_origin=True)
        else:
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_dict(self) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[int, str]]]:
        raw_cl = self.headers.get("Content-Length", "0")
        try:
            content_len = int(raw_cl)
        except (ValueError, TypeError):
            return None, (400, "Invalid Content-Length header")
        if content_len < 0:
            return None, (400, "Negative Content-Length header")
        if content_len > MAX_JSON_BODY_BYTES:
            return None, (413, "Request body exceeds 1 MiB limit")

        if content_len == 0:
            return {}, None

        raw_body = self.rfile.read(content_len)
        try:
            body_text = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            return None, (400, "Request body must be valid UTF-8")
        if not body_text.strip():
            return {}, None
        try:
            parsed = json.loads(body_text)
        except json.JSONDecodeError:
            return None, (400, "Invalid JSON payload")
        if not isinstance(parsed, dict):
            return None, (400, "JSON body must be an object")
        return parsed, None

    def _verify_run_token(self) -> bool:
        expected = getattr(self.server, "api_token", "") or get_or_create_api_token()
        provided = (self.headers.get("X-Sentinel-Token") or "").strip()
        if not provided:
            auth = (self.headers.get("Authorization") or "").strip()
            if auth.lower().startswith("bearer "):
                provided = auth[7:].strip()
        if not provided or not expected:
            return False
        return secrets.compare_digest(provided, expected)

    def do_OPTIONS(self) -> None:
        if not self._validate_host():
            return
        origin = self.headers.get("Origin")
        if origin and not _is_local_origin(origin):
            self._send_json({"error": "Cross-origin preflight blocked"}, status=403, include_cors=False)
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers(allow_origin=True)
        self.end_headers()

    def do_GET(self) -> None:
        if not self._validate_host():
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        # Health & Status
        if path in ("/health", "/api/health", "/status", "/api/status"):
            stats = self.server.collector.get_stats()
            self._send_json({
                "status": "ok",
                "service": "agent-egress-sentinel",
                "version": __version__,
                "web_port": self.server.server_address[1],
                "proxy_port": self.server.proxy.port if self.server.proxy else 8195,
                "proxy_running": self.server.proxy.is_running if self.server.proxy else False,
                "quarantine_mode": self.server.rules.quarantine_mode,
                "protected_ports": sorted(self.server.rules.protected_ports),
                "total_requests": stats.get("total_requests", 0),
                "total_domains": stats.get("total_domains", 0),
                "total_quarantined": stats.get("total_quarantined", 0),
                "license": "100% Free & Open Access (Zero Paywalls)",
            })
            return

        # SSE Real-Time Stream
        if path == "/api/stream":
            self._handle_sse_stream()
            return

        # REST Endpoints
        if path == "/api/stats":
            stats = self.server.collector.get_stats()
            stats["version"] = __version__
            stats["proxy_running"] = self.server.proxy.is_running if self.server.proxy else False
            stats["proxy_port"] = self.server.proxy.port if self.server.proxy else 8195
            stats["web_port"] = self.server.server_address[1]
            stats["quarantine_mode"] = self.server.rules.quarantine_mode
            self._send_json(stats)
            return

        if path == "/api/domains":
            domains = self.server.collector.get_domains()
            self._send_json({"domains": domains, "total": len(domains)})
            return

        if path == "/api/traffic":
            try:
                raw_limit = query.get("limit", ["100"])[0]
                raw_offset = query.get("offset", ["0"])[0]
                limit = int(raw_limit)
                offset = int(raw_offset)
            except (ValueError, TypeError):
                self._send_json({"error": "Invalid 'limit' or 'offset' integer query parameter"}, status=400)
                return

            if limit < 1 or offset < 0:
                self._send_json({"error": "'limit' must be >= 1 and 'offset' must be >= 0"}, status=400)
                return
            limit = min(limit, 500)

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
            self._send_json({"events": events, "count": len(events), "limit": limit, "offset": offset})
            return

        if path == "/api/rules":
            self._send_json(self.server.rules.get_summary())
            return

        if path == "/api/export":
            har_data = self.server.collector.export_har()
            payload = json.dumps(har_data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="agent-egress.har"')
            self.send_header("Content-Length", str(len(payload)))
            self._send_cors_headers(allow_origin=True)
            self.end_headers()
            self.wfile.write(payload)
            return

        if path in ("/api/export/openapi", "/api/openapi"):
            spec = self.server.collector.export_openapi()
            payload = json.dumps(spec, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="openapi-spec.json"')
            self.send_header("Content-Length", str(len(payload)))
            self._send_cors_headers(allow_origin=True)
            self.end_headers()
            self.wfile.write(payload)
            return

        # Unknown /api/* routes MUST return 404 JSON (never SPA fallback)
        if path == "/api" or path.startswith("/api/"):
            self._send_json({"error": "Unknown API route", "path": path}, status=404)
            return

        # Static Assets from public/ directory
        self._serve_static(path)

    def do_POST(self) -> None:
        if not self._validate_host():
            return
        if not _is_local_origin(self.headers.get("Origin")):
            self._send_json({"error": "Cross-origin request blocked"}, status=403, include_cors=False)
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        data, err = self._read_json_dict()
        if err is not None:
            self._send_json({"error": err[1]}, status=err[0])
            return
        assert data is not None

        if path == "/api/quarantine":
            mode = data.get("mode")
            if not mode or not isinstance(mode, str):
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
            if not domain or not isinstance(domain, str) or not domain.strip():
                self._send_json({"error": "Missing 'domain' field"}, 400)
                return
            try:
                norm = self.server.rules.add_blocked_domain(domain)
                self._send_json({"status": "ok", "blocked": norm, "rules": self.server.rules.get_summary()})
            except ValueError as e:
                self._send_json({"error": str(e)}, 400)
            return

        if path == "/api/rules/allow":
            domain = data.get("domain")
            if not domain or not isinstance(domain, str) or not domain.strip():
                self._send_json({"error": "Missing 'domain' field"}, 400)
                return
            try:
                norm = self.server.rules.add_allowed_domain(domain)
                self._send_json({"status": "ok", "allowed": norm, "rules": self.server.rules.get_summary()})
            except ValueError as e:
                self._send_json({"error": str(e)}, 400)
            return

        if path == "/api/rules/remove":
            domain = data.get("domain")
            target_list = str(data.get("list") or "both").lower()
            if not domain or not isinstance(domain, str) or not domain.strip():
                self._send_json({"error": "Missing 'domain' field"}, 400)
                return
            removed_block = False
            removed_allow = False
            if target_list in ("block", "blocked", "both"):
                removed_block = self.server.rules.remove_blocked_domain(domain)
            if target_list in ("allow", "allowed", "both"):
                removed_allow = self.server.rules.remove_allowed_domain(domain)
            self._send_json({
                "status": "ok",
                "domain": domain.strip().lower(),
                "removed_from_block": removed_block,
                "removed_from_allow": removed_allow,
                "rules": self.server.rules.get_summary(),
            })
            return

        if path == "/api/clear":
            self.server.collector.clear()
            self._send_json({"status": "ok", "message": "Egress logs cleared"})
            return

        if path == "/api/record":
            try:
                domain_val = str(data.get("domain") or "api.openai.com")
                remote_port_val = int(data.get("remote_port", 443))
                status_code_val = int(data.get("status_code", 200))
                bytes_sent_val = int(data.get("bytes_sent", 0))
                bytes_recv_val = int(data.get("bytes_recv", 0))
                latency_val = float(data.get("latency_ms", 42.0))
                ts_val = float(data.get("timestamp") or time.time())
            except (ValueError, TypeError):
                self._send_json({"error": "Invalid numeric field in event payload"}, 400)
                return

            cat_val = data.get("category")
            if not cat_val:
                cat_val = self.server.rules.classify(domain_val, remote_port_val).value

            ev = NetworkEvent(
                id=str(data.get("id") or f"ev-{int(time.time() * 1000)}"),
                timestamp=ts_val,
                agent_name=str(data.get("agent_name", "autonomous_planner")),
                domain=domain_val,
                remote_ip=str(data.get("remote_ip", "104.18.24.1")),
                remote_port=remote_port_val,
                protocol=str(data.get("protocol", "HTTPS")),
                method=str(data.get("method", "POST")),
                url_path=str(data.get("url_path", "/v1/chat/completions")),
                status_code=status_code_val,
                bytes_sent=bytes_sent_val,
                bytes_recv=bytes_recv_val,
                latency_ms=latency_val,
                category=str(cat_val),
                quarantined=bool(data.get("quarantined", False)),
                request_sample=str(data.get("request_sample", '{"model":"gpt-4o","stream":true}')),
                response_sample=str(data.get("response_sample", '{"id":"chatcmpl-99","status":"ok"}')),
                notes=str(data.get("notes", "")),
            )
            self.server.collector.record(ev)
            self._send_json({"status": "ok", "event": ev.to_dict()})
            return

        if path == "/api/run":
            if not self._verify_run_token():
                self._send_json(
                    {
                        "error": "Unauthorized: X-Sentinel-Token or Bearer token required for /api/run. Run 'agent-egress-sentinel token' to view your local token."
                    },
                    status=401,
                )
                return

            cmd = data.get("command")
            agent_name = str(data.get("agent_name") or "web_triggered_agent")
            if not cmd or not isinstance(cmd, str) or not cmd.strip():
                self._send_json({"error": "Missing 'command' string"}, 400)
                return
            try:
                cmd_args = shlex.split(cmd)
            except ValueError as exc:
                self._send_json({"error": f"Invalid command syntax: {exc}"}, 400)
                return
            if not cmd_args:
                self._send_json({"error": "Empty command"}, 400)
                return

            proxy_host = self.server.proxy.host if self.server.proxy else "127.0.0.1"
            proxy_port = self.server.proxy.port if self.server.proxy else 8195
            runner = AgentProcessRunner(
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                collector=self.server.collector,
                rules=self.server.rules,
            )

            def _async_exec() -> None:
                try:
                    runner.run(cmd_args, agent_name=agent_name)
                except Exception as exc:
                    logger.warning("Supervised command failed: %s", exc)

            t = threading.Thread(target=_async_exec, daemon=True)
            t.start()
            self._send_json({"status": "spawned", "command": cmd, "agent_name": agent_name})
            return

        self._send_json({"error": "Unknown API route", "path": path}, 404)

    def do_DELETE(self) -> None:
        if not self._validate_host():
            return
        if not _is_local_origin(self.headers.get("Origin")):
            self._send_json({"error": "Cross-origin request blocked"}, status=403, include_cors=False)
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        data, err = self._read_json_dict()
        if err is not None:
            self._send_json({"error": err[1]}, status=err[0])
            return
        assert data is not None

        domain = query.get("domain", [None])[0] or data.get("domain")

        if path == "/api/rules/block":
            if not domain or not isinstance(domain, str) or not domain.strip():
                self._send_json({"error": "Missing 'domain' parameter"}, 400)
                return
            removed = self.server.rules.remove_blocked_domain(domain)
            self._send_json({"status": "ok", "removed": removed, "domain": domain.strip().lower(), "rules": self.server.rules.get_summary()})
            return

        if path == "/api/rules/allow":
            if not domain or not isinstance(domain, str) or not domain.strip():
                self._send_json({"error": "Missing 'domain' parameter"}, 400)
                return
            removed = self.server.rules.remove_allowed_domain(domain)
            self._send_json({"status": "ok", "removed": removed, "domain": domain.strip().lower(), "rules": self.server.rules.get_summary()})
            return

        self._send_json({"error": "Unknown API route", "path": path}, 404)

    def _serve_static(self, path: str) -> None:
        """Serve files from the public folder with strict path traversal rejection (404)."""
        public_dir = (Path(__file__).resolve().parent.parent.parent / "public").resolve()
        if not public_dir.exists():
            public_dir = (Path.cwd() / "public").resolve()

        if _has_traversal_attempt(path):
            self._send_json({"error": "Not found"}, status=404, include_cors=False)
            return

        if path in ("/", ""):
            req_file = public_dir / "index.html"
        else:
            clean_rel = _safe_rel(path)
            if not clean_rel:
                self._send_json({"error": "Not found"}, status=404, include_cors=False)
                return
            req_file = (public_dir / clean_rel).resolve()
            if not req_file.is_relative_to(public_dir):
                self._send_json({"error": "Not found"}, status=404, include_cors=False)
                return

        if req_file.exists() and req_file.is_file():
            mime, _ = mimetypes.guess_type(str(req_file))
            mime = mime or "application/octet-stream"
            if mime == "text/html":
                mime = "text/html; charset=utf-8"
            try:
                content = req_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_error(500, f"Error reading file: {e}")
        else:
            self._send_json({"error": "File not found", "path": path}, status=404, include_cors=False)

    def _handle_sse_stream(self) -> None:
        """Stream real-time network events using Server-Sent Events (SSE)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers(allow_origin=True)
        self.end_headers()

        self.wfile.write(b": connected to agent-egress-sentinel sse\n\n")
        self.wfile.flush()

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

                self.wfile.write(b": heartbeat\n\n")
                self.wfile.flush()
                time.sleep(1.0)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class EgressServer(ThreadingHTTPServer):
    """Custom ThreadingHTTPServer holding collector, rules, proxy, and API token."""

    def __init__(
        self,
        server_address: Tuple[str, int],
        collector: Optional[EgressCollector] = None,
        rules: Optional[RulesEngine] = None,
        proxy: Optional[EgressProxy] = None,
        api_token: Optional[str] = None,
    ):
        self.collector = collector or get_default_collector()
        self.rules = rules or RulesEngine()
        self.proxy = proxy
        self.api_token = api_token or get_or_create_api_token()
        super().__init__(server_address, EgressRequestHandler)
        self.rules.register_protected_ports(self.server_address[1])
        if self.proxy is not None:
            self.rules.register_protected_ports(self.proxy.port)


def run_server(
    web_host: str = "127.0.0.1",
    web_port: int = 8095,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8195,
    collector: Optional[EgressCollector] = None,
    rules: Optional[RulesEngine] = None,
) -> Tuple[EgressServer, EgressProxy]:
    """Start both the EgressProxy and the Web/API EgressServer."""
    collector = collector or get_default_collector()
    rules = rules or RulesEngine()
    rules.register_protected_ports(web_port, proxy_port)

    proxy = EgressProxy(
        host=proxy_host,
        port=proxy_port,
        collector=collector,
        rules_engine=rules,
        web_port=web_port,
    )
    proxy.start()

    server = EgressServer((web_host, web_port), collector=collector, rules=rules, proxy=proxy)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="EgressServerThread")
    server_thread.start()

    logger.info("Agent Egress Sentinel v%s UI running at http://%s:%d", __version__, web_host, web_port)
    logger.info("Agent Egress Proxy running at %s:%d", proxy_host, proxy_port)

    return server, proxy
