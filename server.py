#!/usr/bin/env python3
"""
Agent Egress Sentinel — Sovereign Radar & Network Interceptor Server.
Zero-dependency Python 3 HTTP Server & HTTP/HTTPS Proxy.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agent_egress_sentinel.collector import get_default_collector
from agent_egress_sentinel.rules_engine import RulesEngine
from agent_egress_sentinel.server import run_server

def main():
    parser = argparse.ArgumentParser(description="Agent Egress Sentinel Server")
    parser.add_argument("--web-host", default="127.0.0.1", help="Web UI host (default: 127.0.0.1)")
    parser.add_argument("--web-port", "-p", "--port", dest="web_port", type=int, default=8095, help="Web UI port (default: 8095)")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Proxy listen host (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", type=int, default=8195, help="Proxy listen port (default: 8195)")
    parser.add_argument("--quarantine", default="allow_all", choices=["allow_all", "block_telemetry", "zero_egress", "allowlist_only"])
    args = parser.parse_args()

    collector = get_default_collector()
    rules = RulesEngine(quarantine_mode=args.quarantine)

    print("\n" + "=" * 60)
    print("  🛡️  AGENT EGRESS SENTINEL — ACTIVE DEFENSE & RADAR")
    print("  Engineered by 1nc0gn30 (@1nc0gn30) • NullAI Platform")
    print("=" * 60)
    print(f"  • Web Radar Dashboard: http://{args.web_host}:{args.web_port}")
    print(f"  • Egress Proxy Tunnel: http://{args.proxy_host}:{args.proxy_port}")
    print(f"  • Quarantine Policy:   {args.quarantine.upper()}")
    print("=" * 60 + "\n")

    server, proxy = run_server(
        web_host=args.web_host,
        web_port=args.web_port,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        collector=collector,
        rules=rules,
    )

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping Agent Egress Sentinel...")
        proxy.stop()
        server.shutdown()

if __name__ == "__main__":
    main()
