"""Command-Line Interface for Agent Egress Sentinel.

Autonomous Zero-Dependency Network Interceptor, Domain Classifier,
and Telemetry Radar for AI Agents and LLM Runtimes.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import List, Optional

from .collector import get_default_collector
from .process_runner import AgentProcessRunner
from .proxy import EgressProxy
from .rules_engine import RulesEngine
from .server import run_server


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_serve(args: argparse.Namespace) -> int:
    """Run sentinel radar server and proxy daemon."""
    collector = get_default_collector()
    rules = RulesEngine(quarantine_mode=args.quarantine)

    print("\n" + "=" * 60)
    print("  🛡️  AGENT EGRESS SENTINEL — ACTIVE DEFENSE & RADAR")
    print("  Engineered by Neal Frazier Tech (@1nc0gn30)")
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
        print("\n[Sentinel] Shutting down...")
        proxy.stop()
        server.shutdown()
        print("[Sentinel] Clean shutdown complete.")
        return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run an arbitrary AI agent command under sentinel proxy supervision."""
    if not args.cmd:
        print("Error: No command specified to run. Usage: agent-egress run <command...>")
        return 1

    collector = get_default_collector()
    rules = RulesEngine(quarantine_mode=args.quarantine)

    # Start local proxy instance if not already running on port
    proxy = EgressProxy(host="127.0.0.1", port=args.proxy_port, collector=collector, rules_engine=rules, agent_name=args.agent_name)
    try:
        proxy.start()
    except OSError:
        # Port might already be used by existing sentinel serve daemon
        pass

    runner = AgentProcessRunner(
        proxy_host="127.0.0.1",
        proxy_port=args.proxy_port,
        collector=collector,
        rules=rules,
    )

    print(f"\n[Sentinel] Launching agent process: {' '.join(args.cmd)}")
    print(f"[Sentinel] Monitoring egress via proxy 127.0.0.1:{args.proxy_port} (Agent: {args.agent_name})...\n" + "-" * 60)

    def _stream_out(line: str):
        sys.stdout.write(line)
        sys.stdout.flush()

    def _stream_err(line: str):
        sys.stderr.write(line)
        sys.stderr.flush()

    res = runner.run(
        cmd=args.cmd,
        agent_name=args.agent_name,
        on_stdout=_stream_out,
        on_stderr=_stream_err,
    )

    print("-" * 60)
    print(f"[Sentinel] Process finished with exit code {res['exit_code']} in {res['elapsed_seconds']}s")

    # Domain summary
    domains = collector.get_domains()
    print(f"\n[Sentinel Audit] Captured {len(domains)} unique domain destinations:")
    for d in domains:
        q_tag = " [QUARANTINED]" if d["quarantined_count"] > 0 else ""
        print(f"  • {d['domain']} ({d['category']}) — {d['request_count']} reqs, {d['total_bytes_sent'] + d['total_bytes_recv']} bytes{q_tag}")

    if args.export_har:
        har = collector.export_har()
        with open(args.export_har, "w", encoding="utf-8") as f:
            json.dump(har, f, indent=2)
        print(f"[Sentinel] Exported HAR 1.2 trace to {args.export_har}")

    return res["exit_code"]


def cmd_stats(args: argparse.Namespace) -> int:
    collector = get_default_collector()
    stats = collector.get_stats()
    domains = collector.get_domains()

    print("\n--- Agent Egress Sentinel Stats ---")
    print(f"Total Requests:    {stats.get('total_requests', 0)}")
    print(f"Total Domains:     {stats.get('total_domains', 0)}")
    print(f"Total Agents:      {stats.get('total_agents', 0)}")
    print(f"Total Bytes Sent:  {stats.get('total_bytes_sent', 0):,} bytes")
    print(f"Total Bytes Recv:  {stats.get('total_bytes_recv', 0):,} bytes")
    print(f"Quarantined Reqs:  {stats.get('total_quarantined', 0)}")

    if domains:
        print("\nObserved Domains:")
        for d in domains:
            print(f"  - {d['domain']} [{d['category']}] ({d['request_count']} requests, avg latency {d['avg_latency_ms']:.1f}ms)")
    print("----------------------------------\n")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    collector = get_default_collector()
    har_data = collector.export_har()
    out_file = args.output or "agent-traffic.har"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(har_data, f, indent=2)
    print(f"[Sentinel] Successfully exported {len(har_data['log']['entries'])} network events to {out_file}")
    return 0


def cmd_clear(args: argparse.Namespace) -> int:
    collector = get_default_collector()
    collector.clear()
    print("[Sentinel] All egress logs and historical records cleared.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-egress",
        description="Agent Egress Sentinel — Network Traffic Sniffer & Endpoint Monitor for AI Agents",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # serve command
    p_serve = subparsers.add_parser("serve", help="Start radar web dashboard and egress proxy daemon")
    p_serve.add_argument("--web-host", default="0.0.0.0", help="Web UI host (default: 0.0.0.0)")
    p_serve.add_argument("--web-port", type=int, default=8095, help="Web UI port (default: 8095)")
    p_serve.add_argument("--proxy-host", default="127.0.0.1", help="Proxy listen host (default: 127.0.0.1)")
    p_serve.add_argument("--proxy-port", type=int, default=8096, help="Proxy listen port (default: 8096)")
    p_serve.add_argument(
        "--quarantine",
        default="allow_all",
        choices=["allow_all", "block_telemetry", "zero_egress", "allowlist_only"],
        help="Quarantine policy mode",
    )

    # run command
    p_run = subparsers.add_parser("run", help="Run an AI agent process under proxy supervision")
    p_run.add_argument("--agent-name", default="target_agent", help="Agent identifier tag")
    p_run.add_argument("--proxy-port", type=int, default=8096, help="Proxy port to use (default: 8096)")
    p_run.add_argument(
        "--quarantine",
        default="allow_all",
        choices=["allow_all", "block_telemetry", "zero_egress", "allowlist_only"],
        help="Quarantine policy mode",
    )
    p_run.add_argument("--export-har", help="Path to export HAR log after command finishes")
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="Command and arguments to execute")

    # stats command
    subparsers.add_parser("stats", help="Display summary stats of captured traffic")

    # export command
    p_export = subparsers.add_parser("export", help="Export traffic log to HAR 1.2 file")
    p_export.add_argument("-o", "--output", default="agent-traffic.har", help="Output HAR file path")

    # clear command
    subparsers.add_parser("clear", help="Clear captured traffic database")

    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    if args.command == "serve":
        return cmd_serve(args)
    elif args.command == "run":
        return cmd_run(args)
    elif args.command == "stats":
        return cmd_stats(args)
    elif args.command == "export":
        return cmd_export(args)
    elif args.command == "clear":
        return cmd_clear(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
