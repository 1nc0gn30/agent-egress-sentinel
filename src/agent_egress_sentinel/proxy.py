"""Zero-Dependency Forward & CONNECT Egress Proxy for AI Agent Traffic.

Captures all outbound HTTP and HTTPS connections from any AI runtime or model process.
Parses TLS ClientHello SNI hostnames without breaking SSL encryption or requiring root CAs.
Enforces quarantine policy in real-time and streams audit logs to EgressCollector.
100% Python Standard Library.
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import threading
import time
from typing import Optional, Tuple
from urllib.parse import urlparse

from .collector import EgressCollector, NetworkEvent, get_default_collector
from .rules_engine import DomainCategory, RulesEngine

logger = logging.getLogger("agent_egress.proxy")


def extract_sni_hostname(packet: bytes) -> Optional[str]:
    """Parse TLS ClientHello handshake packet to extract Server Name Indication (SNI).

    Works without decrypting payload or requiring CA certificates.
    Returns hostname string if found, otherwise None.
    """
    try:
        # TLS Record Header: 5 bytes
        # Byte 0: ContentType (0x16 = Handshake)
        # Bytes 1-2: Version
        # Bytes 3-4: Length
        if len(packet) < 9 or packet[0] != 0x16:
            return None

        # Byte 5: Handshake Type (0x01 = ClientHello)
        if packet[5] != 0x01:
            return None

        # Skip record header (5 bytes) + Handshake Type (1) + Handshake Length (3) = 9 bytes
        pos = 9

        # Client Version (2 bytes) + Random (32 bytes) = 34 bytes
        pos += 34
        if pos >= len(packet):
            return None

        # Session ID length (1 byte)
        session_id_len = packet[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(packet):
            return None

        # Cipher Suites length (2 bytes)
        cipher_suites_len = struct.unpack("!H", packet[pos : pos + 2])[0]
        pos += 2 + cipher_suites_len
        if pos + 1 > len(packet):
            return None

        # Compression Methods length (1 byte)
        compression_len = packet[pos]
        pos += 1 + compression_len
        if pos + 2 > len(packet):
            return None

        # Extensions length (2 bytes)
        extensions_len = struct.unpack("!H", packet[pos : pos + 2])[0]
        pos += 2
        extensions_end = pos + extensions_len

        while pos + 4 <= extensions_end and pos + 4 <= len(packet):
            ext_type, ext_len = struct.unpack("!HH", packet[pos : pos + 4])
            pos += 4

            if ext_type == 0x0000:  # server_name extension
                if pos + 2 <= len(packet):
                    # server_name_list length
                    list_len = struct.unpack("!H", packet[pos : pos + 2])[0]
                    sub_pos = pos + 2
                    if sub_pos + 3 <= pos + ext_len:
                        name_type = packet[sub_pos]
                        name_len = struct.unpack("!H", packet[sub_pos + 1 : sub_pos + 3])[0]
                        sub_pos += 3
                        if name_type == 0x00 and sub_pos + name_len <= len(packet):
                            return packet[sub_pos : sub_pos + name_len].decode("ascii", errors="ignore")

            pos += ext_len

    except Exception:
        pass
    return None


class EgressProxy:
    """Thread-safe forward and CONNECT proxy server."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8096,
        collector: Optional[EgressCollector] = None,
        rules_engine: Optional[RulesEngine] = None,
        agent_name: str = "ai_agent",
    ):
        self.host = host
        self.port = port
        self.collector = collector or get_default_collector()
        self.rules = rules_engine or RulesEngine()
        self.agent_name = agent_name

        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start proxy server in background daemon thread."""
        with self._lock:
            if self._running:
                return

            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen(128)
            self._server_socket.settimeout(1.0)
            self._running = True

            self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="EgressProxyThread")
            self._thread.start()
            logger.info("EgressProxy listening on %s:%d (Agent: %s)", self.host, self.port, self.agent_name)

    def stop(self) -> None:
        """Gracefully stop proxy server."""
        with self._lock:
            self._running = False
            if self._server_socket:
                try:
                    self._server_socket.close()
                except Exception:
                    pass
                self._server_socket = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    @property
    def is_running(self) -> bool:
        return self._running

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client_sock, client_addr = self._server_socket.accept()
            except (socket.timeout, OSError):
                continue
            except Exception as e:
                if self._running:
                    logger.debug("Accept error: %s", e)
                break

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock, client_addr),
                daemon=True,
            )
            client_thread.start()

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        start_time = time.time()
        client_sock.settimeout(15.0)
        client_ip, client_port = client_addr

        try:
            # Read initial request header
            initial_data = b""
            while b"\r\n\r\n" not in initial_data:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                initial_data += chunk
                if len(initial_data) > 65536:
                    break

            if not initial_data:
                client_sock.close()
                return

            header_part, _, remaining_data = initial_data.partition(b"\r\n\r\n")
            lines = header_part.decode("iso-8859-1", errors="replace").split("\r\n")
            if not lines:
                client_sock.close()
                return

            request_line = lines[0].strip()
            parts = request_line.split(" ")
            if len(parts) < 2:
                client_sock.close()
                return

            method = parts[0].upper()
            target_uri = parts[1]

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            active_agent = headers.get("x-agent-name", self.agent_name)

            if method == "CONNECT":
                self._handle_connect(
                    client_sock=client_sock,
                    client_ip=client_ip,
                    target_uri=target_uri,
                    headers=headers,
                    agent_name=active_agent,
                    start_time=start_time,
                )
            else:
                self._handle_http(
                    client_sock=client_sock,
                    client_ip=client_ip,
                    method=method,
                    target_uri=target_uri,
                    headers=headers,
                    initial_payload=initial_data,
                    agent_name=active_agent,
                    start_time=start_time,
                )

        except Exception as e:
            logger.debug("Client handler error: %s", e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_connect(
        self,
        client_sock: socket.socket,
        client_ip: str,
        target_uri: str,
        headers: dict,
        agent_name: str,
        start_time: float,
    ) -> None:
        """Handle HTTPS CONNECT tunneling."""
        if ":" in target_uri:
            target_host, port_str = target_uri.split(":", 1)
            try:
                target_port = int(port_str)
            except ValueError:
                target_port = 443
        else:
            target_host = target_uri
            target_port = 443

        # Policy Quarantine Check
        allowed, reason = self.rules.is_allowed(target_host, target_port)
        category = self.rules.classify(target_host, target_port)

        if not allowed:
            # Block and return 403 Forbidden
            err_body = f"Forbidden: Outbound connection to {target_host}:{target_port} blocked by Agent Egress Sentinel.\nReason: {reason}\n"
            resp = (
                f"HTTP/1.1 403 Forbidden\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(err_body.encode('utf-8'))}\r\n"
                f"X-Sentinel-Quarantine: 1\r\n"
                f"Connection: close\r\n\r\n"
                f"{err_body}"
            )
            try:
                client_sock.sendall(resp.encode("utf-8"))
            except Exception:
                pass

            # Record Quarantined Event
            self.collector.record(NetworkEvent(
                agent_name=agent_name,
                domain=target_host,
                remote_ip="0.0.0.0",
                remote_port=target_port,
                protocol="HTTPS",
                method="CONNECT",
                url_path=f"tunnel://{target_host}:{target_port}",
                status_code=403,
                bytes_sent=0,
                bytes_recv=0,
                latency_ms=(time.time() - start_time) * 1000.0,
                content_type="text/plain",
                headers=headers,
                category=category.value if isinstance(category, DomainCategory) else str(category),
                quarantined=True,
                notes=f"Quarantined by policy: {reason}",
            ))
            return

        # Attempt upstream connection
        try:
            remote_sock = socket.create_connection((target_host, target_port), timeout=10.0)
            remote_ip = remote_sock.getpeername()[0]
        except Exception as e:
            err_msg = f"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nSentinel Upstream Connect Failed: {e}\n"
            try:
                client_sock.sendall(err_msg.encode("utf-8"))
            except Exception:
                pass
            return

        # Tell client the tunnel is established
        try:
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except Exception:
            remote_sock.close()
            return

        bytes_sent = 0
        bytes_recv = 0
        sni_domain = None
        first_payload_preview = ""

        # Bidirectional Tunnel Relay using select
        sockets = [client_sock, remote_sock]
        tunnel_open = True

        while tunnel_open and self._running:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, 30.0)
            except (select.error, OSError):
                break

            if exceptional or not readable:
                break

            for s in readable:
                try:
                    data = s.recv(16384)
                except Exception:
                    tunnel_open = False
                    break

                if not data:
                    tunnel_open = False
                    break

                if s is client_sock:
                    bytes_sent += len(data)
                    # Check for TLS ClientHello SNI on first chunk if not yet detected
                    if sni_domain is None and len(data) > 5 and data[0] == 0x16:
                        parsed_sni = extract_sni_hostname(data)
                        if parsed_sni:
                            sni_domain = parsed_sni

                    if not first_payload_preview and len(data) > 0:
                        first_payload_preview = f"TLS Handshake ({len(data)} bytes)"
                    try:
                        remote_sock.sendall(data)
                    except Exception:
                        tunnel_open = False
                        break
                else:
                    bytes_recv += len(data)
                    try:
                        client_sock.sendall(data)
                    except Exception:
                        tunnel_open = False
                        break

        remote_sock.close()

        resolved_domain = sni_domain or target_host
        final_category = self.rules.classify(resolved_domain, target_port)
        latency_ms = (time.time() - start_time) * 1000.0

        self.collector.record(NetworkEvent(
            agent_name=agent_name,
            domain=resolved_domain,
            remote_ip=remote_ip,
            remote_port=target_port,
            protocol="HTTPS",
            method="CONNECT",
            url_path=f"tunnel://{resolved_domain}:{target_port}",
            status_code=200,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            latency_ms=latency_ms,
            content_type="application/octet-stream",
            headers={"host": f"{resolved_domain}:{target_port}"},
            request_sample=first_payload_preview or f"Forwarded {bytes_sent} bytes via TLS tunnel",
            response_sample=f"Received {bytes_recv} bytes from {resolved_domain}",
            category=final_category.value if isinstance(final_category, DomainCategory) else str(final_category),
            quarantined=False,
            notes=f"SNI: {sni_domain}" if sni_domain else "Standard CONNECT tunnel",
        ))

    def _handle_http(
        self,
        client_sock: socket.socket,
        client_ip: str,
        method: str,
        target_uri: str,
        headers: dict,
        initial_payload: bytes,
        agent_name: str,
        start_time: float,
    ) -> None:
        """Handle standard HTTP request forwarding."""
        parsed = urlparse(target_uri)
        target_host = parsed.hostname or headers.get("host", "127.0.0.1")
        if ":" in target_host:
            target_host, port_str = target_host.split(":", 1)
            target_port = int(port_str)
        else:
            target_port = parsed.port or 80

        url_path = parsed.path or "/"
        if parsed.query:
            url_path += f"?{parsed.query}"

        allowed, reason = self.rules.is_allowed(target_host, target_port)
        category = self.rules.classify(target_host, target_port)

        if not allowed:
            err_body = f"Forbidden: HTTP request to {target_host} blocked by Sentinel.\nReason: {reason}\n"
            resp = (
                f"HTTP/1.1 403 Forbidden\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(err_body.encode('utf-8'))}\r\n"
                f"Connection: close\r\n\r\n"
                f"{err_body}"
            )
            try:
                client_sock.sendall(resp.encode("utf-8"))
            except Exception:
                pass

            self.collector.record(NetworkEvent(
                agent_name=agent_name,
                domain=target_host,
                remote_ip="0.0.0.0",
                remote_port=target_port,
                protocol="HTTP",
                method=method,
                url_path=url_path,
                status_code=403,
                bytes_sent=len(initial_payload),
                bytes_recv=0,
                latency_ms=(time.time() - start_time) * 1000.0,
                content_type="text/plain",
                headers=headers,
                category=category.value if isinstance(category, DomainCategory) else str(category),
                quarantined=True,
                notes=reason,
            ))
            return

        try:
            remote_sock = socket.create_connection((target_host, target_port), timeout=10.0)
            remote_ip = remote_sock.getpeername()[0]
        except Exception as e:
            err_msg = f"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nGateway Error: {e}\n"
            try:
                client_sock.sendall(err_msg.encode("utf-8"))
            except Exception:
                pass
            return

        # Rewrite request to relative path for origin server
        origin_request = f"{method} {url_path} HTTP/1.1\r\n"
        for k, v in headers.items():
            if k.lower() not in ("proxy-connection", "keep-alive"):
                origin_request += f"{k.title()}: {v}\r\n"
        origin_request += "Connection: close\r\n\r\n"

        bytes_sent = len(origin_request.encode("utf-8"))
        bytes_recv = 0
        response_preview = ""
        status_code = 200

        try:
            remote_sock.sendall(origin_request.encode("utf-8"))

            resp_data = b""
            while self._running:
                chunk = remote_sock.recv(8192)
                if not chunk:
                    break
                resp_data += chunk
                bytes_recv += len(chunk)
                try:
                    client_sock.sendall(chunk)
                except Exception:
                    break

            if resp_data:
                status_line = resp_data.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
                parts = status_line.split(" ")
                if len(parts) >= 2 and parts[1].isdigit():
                    status_code = int(parts[1])
                response_preview = resp_data[:500].decode("utf-8", errors="replace")

        except Exception as e:
            logger.debug("HTTP proxy error: %s", e)
        finally:
            remote_sock.close()

        self.collector.record(NetworkEvent(
            agent_name=agent_name,
            domain=target_host,
            remote_ip=remote_ip,
            remote_port=target_port,
            protocol="HTTP",
            method=method,
            url_path=url_path,
            status_code=status_code,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            latency_ms=(time.time() - start_time) * 1000.0,
            content_type=headers.get("content-type", "application/json"),
            headers=headers,
            request_sample=f"{method} {url_path}",
            response_sample=response_preview,
            category=category.value if isinstance(category, DomainCategory) else str(category),
            quarantined=False,
            notes="Plain HTTP proxied",
        ))
