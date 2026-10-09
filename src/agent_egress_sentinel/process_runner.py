"""Agent Process Runner & Socket Monitor.

Executes arbitrary AI agent commands with injected proxy environment variables,
captures stdout/stderr, and inspects Linux /proc socket descriptors to detect
raw socket egress that bypasses standard HTTP proxies.
Zero external dependencies.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .collector import EgressCollector, NetworkEvent, get_default_collector
from .rules_engine import DomainCategory, RulesEngine

logger = logging.getLogger("agent_egress.runner")


def _hex_to_ip(hex_str: str) -> str:
    """Convert hex representation from /proc/net/tcp to IPv4 dotted decimal."""
    try:
        # Little-endian hex to IP
        parts = [str(int(hex_str[i : i + 2], 16)) for i in range(len(hex_str) - 2, -1, -2)]
        return ".".join(parts)
    except Exception:
        return "0.0.0.0"


def _hex_to_port(hex_str: str) -> int:
    """Convert hex port from /proc/net/tcp to integer."""
    try:
        return int(hex_str, 16)
    except Exception:
        return 0


class SocketMonitor(threading.Thread):
    """Background thread polling /proc/<pid>/fd and /proc/net/tcp to detect raw socket connections."""

    def __init__(
        self,
        pid: int,
        agent_name: str,
        collector: EgressCollector,
        rules: RulesEngine,
        poll_interval: float = 0.5,
    ):
        super().__init__(daemon=True, name=f"SocketMonitor-{pid}")
        self.pid = pid
        self.agent_name = agent_name
        self.collector = collector
        self.rules = rules
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._seen_connections: Set[Tuple[str, int]] = set()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._inspect_pid_sockets()
            except Exception as e:
                logger.debug("Socket poll error: %s", e)
            self._stop_event.wait(self.poll_interval)

    def _inspect_pid_sockets(self) -> None:
        fd_dir = Path(f"/proc/{self.pid}/fd")
        if not fd_dir.exists():
            return

        # Find socket inodes owned by process
        socket_inodes = set()
        for fd in fd_dir.glob("*"):
            try:
                target = os.readlink(fd)
                if target.startswith("socket:["):
                    inode = target[8:-1]
                    socket_inodes.add(inode)
            except (OSError, FileNotFoundError):
                continue

        if not socket_inodes:
            return

        # Scan /proc/net/tcp and /proc/net/tcp6 for matched inodes
        for net_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            p = Path(net_file)
            if not p.exists():
                continue
            try:
                with open(p, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except OSError:
                continue

            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue

                inode = parts[9]
                state = parts[3]
                # 01 = TCP_ESTABLISHED, 02 = TCP_SYN_SENT
                if inode in socket_inodes and state in ("01", "02"):
                    rem_address = parts[2]
                    if ":" in rem_address:
                        rem_hex_ip, rem_hex_port = rem_address.split(":", 1)
                        rem_ip = _hex_to_ip(rem_hex_ip)
                        rem_port = _hex_to_port(rem_hex_port)

                        # Skip loopback to our own proxy
                        if rem_ip in ("127.0.0.1", "0.0.0.0") and rem_port in (8096, 8095):
                            continue

                        conn_key = (rem_ip, rem_port)
                        if conn_key not in self._seen_connections:
                            self._seen_connections.add(conn_key)

                            # Reverse DNS lookup attempt (non-blocking / fast)
                            try:
                                domain = socket.gethostbyaddr(rem_ip)[0]
                            except Exception:
                                domain = rem_ip

                            category = self.rules.classify(domain, rem_port)
                            self.collector.record(NetworkEvent(
                                pid=self.pid,
                                agent_name=self.agent_name,
                                domain=domain,
                                remote_ip=rem_ip,
                                remote_port=rem_port,
                                protocol="RAW_TCP",
                                method="SOCKET",
                                url_path=f"tcp://{rem_ip}:{rem_port}",
                                status_code=200,
                                bytes_sent=0,
                                bytes_recv=0,
                                latency_ms=0.0,
                                category=category.value if isinstance(category, DomainCategory) else str(category),
                                quarantined=False,
                                notes="Discovered via Linux /proc socket descriptor audit",
                            ))


class AgentProcessRunner:
    """Runs target AI agent processes with proxy injection and live telemetry."""

    def __init__(
        self,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 8096,
        collector: Optional[EgressCollector] = None,
        rules: Optional[RulesEngine] = None,
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.collector = collector or get_default_collector()
        self.rules = rules or RulesEngine()

    def run(
        self,
        cmd: List[str],
        agent_name: str = "default_agent",
        cwd: Optional[str] = None,
        env_extra: Optional[Dict[str, str]] = None,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Execute agent command synchronously, streaming output and capturing traffic."""
        proxy_url = f"http://{self.proxy_host}:{self.proxy_port}"

        # Inject standard proxy environment variables
        run_env = os.environ.copy()
        run_env.update({
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "ALL_PROXY": proxy_url,
            "all_proxy": proxy_url,
            # Ensure Python urllib, requests, httpx, aiohttp adhere to proxy
            "PYTHONHTTPSVERIFY": "1",
            "AGENT_SENTINEL_NAME": agent_name,
        })
        if env_extra:
            run_env.update(env_extra)

        start_time = time.time()

        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=run_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        # Launch socket monitor thread for raw socket discovery
        monitor = SocketMonitor(
            pid=proc.pid,
            agent_name=agent_name,
            collector=self.collector,
            rules=self.rules,
        )
        monitor.start()

        stdout_lines = []
        stderr_lines = []

        def _reader(stream, line_list, callback):
            try:
                for line in iter(stream.readline, ""):
                    line_list.append(line)
                    if callback:
                        callback(line)
                stream.close()
            except Exception:
                pass

        t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, on_stdout), daemon=True)
        t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, on_stderr), daemon=True)
        t_out.start()
        t_err.start()

        returncode = proc.wait()
        monitor.stop()
        monitor.join(timeout=1.0)
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)

        elapsed = time.time() - start_time

        return {
            "pid": proc.pid,
            "agent_name": agent_name,
            "command": " ".join(cmd),
            "exit_code": returncode,
            "elapsed_seconds": round(elapsed, 3),
            "stdout": "".join(stdout_lines),
            "stderr": "".join(stderr_lines),
        }
