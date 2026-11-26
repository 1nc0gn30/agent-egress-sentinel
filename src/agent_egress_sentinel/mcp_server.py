"""Zero-Dependency JSON-RPC 2.0 Stdio MCP Server for Agent Egress Sentinel.

Exposes real MCP tools:
  - egress_audit_status: Audit live network egress telemetry, domains, and quarantine mode.
  - egress_set_quarantine: Switch live daemon quarantine policy mode.
  - egress_manage_rules: Inspect, add, or remove allowlist/blocklist domain rules.
100% Python Standard Library.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from . import __version__
from .collector import get_default_collector
from .rules_engine import RulesEngine

MCP_PROTOCOL_VERSION = "2024-11-05"

TOOLS_SPEC: List[Dict[str, Any]] = [
    {
        "name": "egress_audit_status",
        "description": "Audit live network egress telemetry, domain classifications, and quarantine enforcement.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "quarantine": {
                    "type": "string",
                    "enum": ["allow_all", "block_telemetry", "zero_egress", "allowlist_only"],
                    "description": "Optional quarantine policy to apply before auditing",
                },
                "filterDomain": {
                    "type": "string",
                    "description": "Optional substring filter on contacted domain names",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "egress_set_quarantine",
        "description": "Switch the active quarantine policy mode on the Agent Egress Sentinel daemon.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["allow_all", "block_telemetry", "zero_egress", "allowlist_only"],
                    "description": "Target quarantine policy mode",
                },
            },
            "required": ["mode"],
            "additionalProperties": False,
        },
    },
    {
        "name": "egress_manage_rules",
        "description": "List, add, or remove domains in the Sentinel allowlist or blocklist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "add_block", "remove_block", "add_allow", "remove_allow"],
                    "description": "Rule operation to perform",
                },
                "domain": {
                    "type": "string",
                    "description": "Target domain or wildcard (e.g. '*.telemetry.example.com')",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
]


class EgressMCPServer:
    """JSON-RPC 2.0 stdio MCP server backed by live :8095 daemon with SQLite fallback."""

    def __init__(self, base_url: str = "http://127.0.0.1:8095"):
        self.base_url = base_url.rstrip("/")
        self._fallback_rules = RulesEngine()

    def _http_json(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                return json.loads(exc.read().decode("utf-8"))
            except Exception:
                return {"error": f"HTTP {exc.code}"}
        except Exception:
            return None

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = arguments or {}

        if name == "egress_audit_status":
            if args.get("quarantine"):
                self.call_tool("egress_set_quarantine", {"mode": args["quarantine"]})

            health = self._http_json("GET", "/api/health")
            domains_resp = self._http_json("GET", "/api/domains")
            rules_resp = self._http_json("GET", "/api/rules")

            if health and isinstance(health, dict) and health.get("status") == "ok":
                online = True
                raw_domains = (domains_resp or {}).get("domains", [])
                active_reqs = health.get("total_requests", 0)
                quarantined_count = health.get("total_quarantined", 0)
                quarantine_mode = health.get("quarantine_mode", "allow_all")
                proxy_port = health.get("proxy_port", 8195)
            else:
                online = False
                collector = get_default_collector()
                stats = collector.get_stats()
                raw_domains = collector.get_domains()
                active_reqs = stats.get("total_requests", 0)
                quarantined_count = stats.get("total_quarantined", 0)
                quarantine_mode = self._fallback_rules.quarantine_mode
                proxy_port = 8195
                rules_resp = self._fallback_rules.get_summary()

            filter_domain = str(args.get("filterDomain") or "").strip().lower()
            formatted_domains = []
            for d in raw_domains:
                d_name = str(d.get("domain", ""))
                if filter_domain and filter_domain not in d_name.lower():
                    continue
                formatted_domains.append({
                    "name": d_name,
                    "category": d.get("category", "unknown"),
                    "bytesSent": int(d.get("total_bytes_sent") or 0),
                    "bytesRecv": int(d.get("total_bytes_recv") or 0),
                    "requestCount": int(d.get("request_count") or 0),
                    "quarantinedCount": int(d.get("quarantined_count") or 0),
                })

            return {
                "service": "agent-egress-sentinel",
                "version": __version__,
                "daemonOnline": online,
                "proxyPort": proxy_port,
                "quarantineMode": quarantine_mode,
                "activeEgressRequests": int(active_reqs),
                "quarantinedCount": int(quarantined_count),
                "domains": formatted_domains,
                "rules": rules_resp,
            }

        if name == "egress_set_quarantine":
            mode = str(args.get("mode") or "")
            valid = {"allow_all", "block_telemetry", "zero_egress", "allowlist_only"}
            if mode not in valid:
                raise ValueError(f"Invalid mode '{mode}'. Choose from {sorted(valid)}")

            live = self._http_json("POST", "/api/quarantine", {"mode": mode})
            if live and live.get("status") == "ok":
                return {"status": "ok", "daemonOnline": True, "quarantineMode": live.get("quarantine_mode", mode)}

            self._fallback_rules.set_quarantine_mode(mode)
            return {
                "status": "ok",
                "daemonOnline": False,
                "quarantineMode": self._fallback_rules.quarantine_mode,
                "note": "Local daemon offline; updated in-session fallback policy.",
            }

        if name == "egress_manage_rules":
            action = str(args.get("action") or "list")
            domain = str(args.get("domain") or "").strip()

            if action == "list":
                live = self._http_json("GET", "/api/rules")
                if live and "quarantine_mode" in live:
                    return {"status": "ok", "daemonOnline": True, "rules": live}
                return {"status": "ok", "daemonOnline": False, "rules": self._fallback_rules.get_summary()}

            if not domain:
                raise ValueError(f"Action '{action}' requires a non-empty 'domain' argument.")

            if action == "add_block":
                live = self._http_json("POST", "/api/rules/block", {"domain": domain})
                if live and live.get("status") == "ok":
                    return {"status": "ok", "daemonOnline": True, **live}
                norm = self._fallback_rules.add_blocked_domain(domain)
                return {"status": "ok", "daemonOnline": False, "blocked": norm, "rules": self._fallback_rules.get_summary()}

            if action == "remove_block":
                q = urllib.parse.urlencode({"domain": domain})
                live = self._http_json("DELETE", f"/api/rules/block?{q}")
                if live and live.get("status") == "ok":
                    return {"status": "ok", "daemonOnline": True, **live}
                removed = self._fallback_rules.remove_blocked_domain(domain)
                return {"status": "ok", "daemonOnline": False, "removed": removed, "rules": self._fallback_rules.get_summary()}

            if action == "add_allow":
                live = self._http_json("POST", "/api/rules/allow", {"domain": domain})
                if live and live.get("status") == "ok":
                    return {"status": "ok", "daemonOnline": True, **live}
                norm = self._fallback_rules.add_allowed_domain(domain)
                return {"status": "ok", "daemonOnline": False, "allowed": norm, "rules": self._fallback_rules.get_summary()}

            if action == "remove_allow":
                q = urllib.parse.urlencode({"domain": domain})
                live = self._http_json("DELETE", f"/api/rules/allow?{q}")
                if live and live.get("status") == "ok":
                    return {"status": "ok", "daemonOnline": True, **live}
                removed = self._fallback_rules.remove_allowed_domain(domain)
                return {"status": "ok", "daemonOnline": False, "removed": removed, "rules": self._fallback_rules.get_summary()}

            raise ValueError(f"Unsupported action '{action}'")

        raise KeyError(f"Unknown MCP tool: {name}")

    def handle_message(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        # Notifications have no id and expect no response
        if req_id is None and method.startswith("notifications/"):
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "agent-egress-sentinel",
                        "version": __version__,
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS_SPEC},
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments") or {}
            try:
                result = self.call_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                        "structuredContent": result,
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_stdio(self) -> int:
        """Read newline-delimited JSON-RPC 2.0 requests from stdin and write responses to stdout."""
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if not isinstance(msg, dict):
                    raise ValueError("JSON-RPC payload must be an object")
            except Exception as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            resp = self.handle_message(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        return 0
