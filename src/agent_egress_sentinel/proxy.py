"""Zero-Dependency Forward & CONNECT Egress Proxy for AI Agent Traffic.

Captures outbound HTTP and HTTPS connections from any AI runtime or model process.
Parses TLS ClientHello SNI hostnames without breaking SSL encryption or requiring root CAs,
re-evaluates SNI against quarantine rules BEFORE relaying payload, enforces SSRF/private-net
and control-plane protection, and streams audit logs to EgressCollector.
100% Python Standard Library.
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple
from urllib.parse import urlparse

from .collector import EgressCollector, NetworkEvent, get_default_collector
from .rules_engine import DomainCategory, RulesEngine

logger = logging.getLogger("agent_egress.proxy")

MAX_HTTP_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB cap on forwarded HTTP bodies
MAX_RESPONSE_PREVIEW_BYTES = 8192               # Bounded in-memory preview buffer
MAX_CONCURRENT_CLIENTS = 64


def parse_host_port(authority: str, default_port: int) -> Optional[Tuple[str, int]]:
    """Safely parse host[:port] or [ipv6][:port] authority strings."""
    raw = (authority or "").strip()
    if not raw or any(ch in raw for ch in (" ", "\t", "\r", "\n", "/", "\\")):
        return None

    host = ""
    port = default_port

    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return None
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                return None
            port_str = rest[1:]
            if not port_str.isdigit():
                return None
            port = int(port_str)
    elif raw.count(":") == 1:
        host_part, port_str = raw.split(":", 1)
        if not host_part or not port_str.isdigit():
            return None
        host = host_part
        port = int(port_str)
    elif ":" in raw:
        # Unbracketed IPv6 literal without port
        host = raw
        port = default_port
    else:
        host = raw
        port = default_port

    if not host or not (1 <= port <= 65535):
        return None
    return host, port


def extract_sni_hostname(packet: bytes) -> Optional[str]:
    """Parse TLS ClientHello handshake packet to extract Server Name Indication (SNI).

    Works without decrypting payload or requiring CA certificates.
    Returns hostname string if found, otherwise None.
    """
    try:
        if len(packet) < 9 or packet[0] != 0x16:
            return None
        if packet[5] != 0x01:
            return None

        pos = 9 + 34  # record(5) + hs_type(1) + hs_len(3) + version(2) + random(32)
        if pos >= len(packet):
            return None

        session_id_len = packet[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(packet):
            return None

        cipher_suites_len = struct.unpack("!H", packet[pos : pos + 2])[0]
        pos += 2 + cipher_suites_len
        if pos + 1 > len(packet):
            return None

        compression_len = packet[pos]
        pos += 1 + compression_len
        if pos + 2 > len(packet):
            return None

        extensions_len = struct.unpack("!H", packet[pos : pos + 2])[0]
        pos += 2
        extensions_end = pos + extensions_len

        while pos + 4 <= extensions_end and pos + 4 <= len(packet):
            ext_type, ext_len = struct.unpack("!HH", packet[pos : pos + 4])
            pos += 4

            if ext_type == 0x0000:  # server_name extension
                if pos + 2 <= len(packet):
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
    """Thread-safe forward HTTP and HTTPS CONNECT proxy server with SNI & SSRF enforcement."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8195,
        collector: Optional[EgressCollector] = None,
        rules_engine: Optional[RulesEngine] = None,
        agent_name: str = "ai_agent",
        web_port: Optional[int] = None,
    ):
        self.host = host
        self.port = port
        self.collector = collector or get_default_collector()
        self.rules = rules_engine or RulesEngine()
        self.agent_name = agent_name

        # Always protect proxy port and optional web control port against self-escape
        self.rules.register_protected_ports(self.port)
        if web_port is not None:
            self.rules.register_protected_ports(web_port)

        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._executor: Optional[ThreadPoolExecutor] = None
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
            self.port = self._server_socket.getsockname()[1]
            self.rules.register_protected_ports(self.port)
            self._running = True
            self._executor = ThreadPoolExecutor(
                max_workers=MAX_CONCURRENT_CLIENTS,
                thread_name_prefix="EgressProxyClient",
            )

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
            executor = self._executor
            self._executor = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)

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

            executor = self._executor
            if executor is not None and self._running:
                try:
                    executor.submit(self._handle_client, client_sock, client_addr)
                except RuntimeError:
                    client_sock.close()
            else:
                client_sock.close()

    def _send_simple_response(self, client_sock: socket.socket, status_line: str, body: str, extra_headers: str = "") -> None:
        encoded = body.encode("utf-8")
        resp = (
            f"HTTP/1.1 {status_line}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(encoded)}\r\n"
            f"{extra_headers}"
            f"Connection: close\r\n\r\n"
        ).encode("ascii") + encoded
        try:
            client_sock.sendall(resp)
        except Exception:
            pass

    def _resolve_and_validate_target(self, target_host: str, target_port: int) -> Tuple[Optional[Tuple[int, str]], Optional[str], bool]:
        """Resolve DNS and verify EVERY returned IP against RulesEngine (DNS pinning / SSRF guard).

        Returns:
            ((family, pinned_ip) or None, error_message_or_none, is_policy_block)
        """
        try:
            infos = socket.getaddrinfo(target_host, target_port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            return None, f"DNS resolution failed for {target_host}: {exc}", False

        if not infos:
            return None, f"No addresses resolved for {target_host}", False

        first_candidate: Optional[Tuple[int, str]] = None
        for family, _socktype, _proto, _canon, sockaddr in infos:
            ip_str = sockaddr[0]
            allowed, reason = self.rules.is_allowed(target_host, target_port, resolved_ip=ip_str)
            if not allowed:
                return None, reason, True
            if first_candidate is None:
                first_candidate = (family, ip_str)

        return first_candidate, None, False

    def _connect_pinned(self, family: int, ip_str: str, port: int, timeout: float = 10.0) -> socket.socket:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip_str, port))
            return sock
        except Exception:
            sock.close()
            raise

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        start_time = time.time()
        client_sock.settimeout(15.0)
        client_ip, _client_port = client_addr

        try:
            initial_data = b""
            while b"\r\n\r\n" not in initial_data:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                initial_data += chunk
                if len(initial_data) > 65536:
                    self._send_simple_response(client_sock, "431 Request Header Fields Too Large", "Request headers too large.\n")
                    return

            if not initial_data:
                return

            header_part, _, _remaining = initial_data.partition(b"\r\n\r\n")
            lines = header_part.decode("iso-8859-1", errors="replace").split("\r\n")
            if not lines:
                return

            request_line = lines[0].strip()
            parts = request_line.split(" ")
            if len(parts) < 2:
                self._send_simple_response(client_sock, "400 Bad Request", "Malformed HTTP request line.\n")
                return

            method = parts[0].upper()
            target_uri = parts[1]

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

    def _record_quarantined(
        self,
        agent_name: str,
        domain: str,
        remote_ip: str,
        remote_port: int,
        protocol: str,
        method: str,
        url_path: str,
        bytes_sent: int,
        headers: dict,
        reason: str,
        start_time: float,
    ) -> None:
        category = self.rules.classify(domain, remote_port)
        self.collector.record(NetworkEvent(
            agent_name=agent_name,
            domain=domain,
            remote_ip=remote_ip,
            remote_port=remote_port,
            protocol=protocol,
            method=method,
            url_path=url_path,
            status_code=403,
            bytes_sent=bytes_sent,
            bytes_recv=0,
            latency_ms=(time.time() - start_time) * 1000.0,
            content_type="text/plain",
            headers=headers,
            category=category.value if isinstance(category, DomainCategory) else str(category),
            quarantined=True,
            notes=f"Quarantined by policy: {reason}",
        ))

    def _handle_connect(
        self,
        client_sock: socket.socket,
        client_ip: str,
        target_uri: str,
        headers: dict,
        agent_name: str,
        start_time: float,
    ) -> None:
        """Handle HTTPS CONNECT tunneling with DNS-pinned SSRF check and pre-relay SNI re-evaluation."""
        parsed_hp = parse_host_port(target_uri, 443)
        if parsed_hp is None:
            self._send_simple_response(client_sock, "400 Bad Request", "Invalid CONNECT target authority.\n")
            return
        target_host, target_port = parsed_hp

        # 1. Hostname / literal IP policy check
        allowed, reason = self.rules.is_allowed(target_host, target_port)
        if not allowed:
            self._send_simple_response(
                client_sock,
                "403 Forbidden",
                f"Forbidden: Outbound connection to {target_host}:{target_port} blocked by Agent Egress Sentinel.\nReason: {reason}\n",
                extra_headers="X-Sentinel-Quarantine: 1\r\n",
            )
            self._record_quarantined(
                agent_name=agent_name,
                domain=target_host,
                remote_ip="0.0.0.0",
                remote_port=target_port,
                protocol="HTTPS",
                method="CONNECT",
                url_path=f"tunnel://{target_host}:{target_port}",
                bytes_sent=0,
                headers=headers,
                reason=reason,
                start_time=start_time,
            )
            return

        # 2. DNS resolution & resolved IP SSRF validation (pinned connect)
        pinned, err_msg, is_policy_block = self._resolve_and_validate_target(target_host, target_port)
        if pinned is None:
            if is_policy_block:
                self._send_simple_response(
                    client_sock,
                    "403 Forbidden",
                    f"Forbidden: Resolved destination for {target_host}:{target_port} blocked.\nReason: {err_msg}\n",
                    extra_headers="X-Sentinel-Quarantine: 1\r\n",
                )
                self._record_quarantined(
                    agent_name=agent_name,
                    domain=target_host,
                    remote_ip="0.0.0.0",
                    remote_port=target_port,
                    protocol="HTTPS",
                    method="CONNECT",
                    url_path=f"tunnel://{target_host}:{target_port}",
                    bytes_sent=0,
                    headers=headers,
                    reason=err_msg or "Policy blocked",
                    start_time=start_time,
                )
            else:
                self._send_simple_response(client_sock, "502 Bad Gateway", f"Sentinel Upstream Connect Failed: {err_msg}\n")
            return

        family, remote_ip = pinned
        try:
            remote_sock = self._connect_pinned(family, remote_ip, target_port, timeout=10.0)
        except Exception as e:
            self._send_simple_response(client_sock, "502 Bad Gateway", f"Sentinel Upstream Connect Failed: {e}\n")
            return

        try:
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except Exception:
            remote_sock.close()
            return

        bytes_sent = 0
        bytes_recv = 0
        sni_domain: Optional[str] = None
        sni_checked = False
        first_payload_preview = ""

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
                    # Inspect TLS ClientHello SNI BEFORE relaying any bytes upstream!
                    if not sni_checked:
                        sni_checked = True
                        if len(data) > 5 and data[0] == 0x16:
                            parsed_sni = extract_sni_hostname(data)
                            if parsed_sni:
                                sni_domain = parsed_sni
                                sni_allowed, sni_reason = self.rules.is_allowed(
                                    sni_domain, target_port, resolved_ip=remote_ip
                                )
                                if not sni_allowed:
                                    # Close immediately without forwarding the ClientHello upstream
                                    remote_sock.close()
                                    self._record_quarantined(
                                        agent_name=agent_name,
                                        domain=sni_domain,
                                        remote_ip=remote_ip,
                                        remote_port=target_port,
                                        protocol="HTTPS",
                                        method="CONNECT",
                                        url_path=f"tunnel://{sni_domain}:{target_port}",
                                        bytes_sent=0,
                                        headers={"host": f"{sni_domain}:{target_port}", "connect_target": target_host},
                                        reason=f"SNI policy violation ({sni_domain}): {sni_reason}",
                                        start_time=start_time,
                                    )
                                    return

                    bytes_sent += len(data)
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
        """Handle standard HTTP request forwarding with strict scheme, host, SSRF & buffer bounds."""
        parsed = urlparse(target_uri)
        if parsed.scheme and parsed.scheme.lower() != "http":
            self._send_simple_response(
                client_sock,
                "400 Bad Request",
                f"Unsupported proxy scheme '{parsed.scheme}'. Only http:// or CONNECT is permitted.\n",
            )
            return

        target_host: Optional[str] = None
        target_port: int = 80

        if parsed.netloc:
            # Strip any userinfo
            netloc = parsed.netloc.rsplit("@", 1)[-1]
            parsed_hp = parse_host_port(netloc, 80)
            if parsed_hp is None:
                self._send_simple_response(client_sock, "400 Bad Request", "Invalid target host or port.\n")
                return
            target_host, target_port = parsed_hp
        elif headers.get("host"):
            parsed_hp = parse_host_port(headers["host"], 80)
            if parsed_hp is None:
                self._send_simple_response(client_sock, "400 Bad Request", "Invalid Host header.\n")
                return
            target_host, target_port = parsed_hp
        else:
            self._send_simple_response(client_sock, "400 Bad Request", "Missing Host header.\n")
            return

        url_path = parsed.path or "/"
        if parsed.query:
            url_path += f"?{parsed.query}"

        allowed, reason = self.rules.is_allowed(target_host, target_port)
        if not allowed:
            self._send_simple_response(
                client_sock,
                "403 Forbidden",
                f"Forbidden: HTTP request to {target_host}:{target_port} blocked by Sentinel.\nReason: {reason}\n",
                extra_headers="X-Sentinel-Quarantine: 1\r\n",
            )
            self._record_quarantined(
                agent_name=agent_name,
                domain=target_host,
                remote_ip="0.0.0.0",
                remote_port=target_port,
                protocol="HTTP",
                method=method,
                url_path=url_path,
                bytes_sent=len(initial_payload),
                headers=headers,
                reason=reason,
                start_time=start_time,
            )
            return

        # Validate Content-Length with strict bounds
        content_len = 0
        if "content-length" in headers:
            try:
                content_len = int(headers["content-length"])
            except (ValueError, TypeError):
                self._send_simple_response(client_sock, "400 Bad Request", "Invalid Content-Length header.\n")
                return
            if content_len < 0:
                self._send_simple_response(client_sock, "400 Bad Request", "Negative Content-Length header.\n")
                return
            if content_len > MAX_HTTP_REQUEST_BODY_BYTES:
                self._send_simple_response(client_sock, "413 Payload Too Large", "Request body exceeds sentinel proxy limit.\n")
                return

        pinned, err_msg, is_policy_block = self._resolve_and_validate_target(target_host, target_port)
        if pinned is None:
            if is_policy_block:
                self._send_simple_response(
                    client_sock,
                    "403 Forbidden",
                    f"Forbidden: Resolved destination for {target_host}:{target_port} blocked.\nReason: {err_msg}\n",
                    extra_headers="X-Sentinel-Quarantine: 1\r\n",
                )
                self._record_quarantined(
                    agent_name=agent_name,
                    domain=target_host,
                    remote_ip="0.0.0.0",
                    remote_port=target_port,
                    protocol="HTTP",
                    method=method,
                    url_path=url_path,
                    bytes_sent=len(initial_payload),
                    headers=headers,
                    reason=err_msg or "Policy blocked",
                    start_time=start_time,
                )
            else:
                self._send_simple_response(client_sock, "502 Bad Gateway", f"Gateway Error: {err_msg}\n")
            return

        req_body = initial_payload if isinstance(initial_payload, bytes) else b""
        if b"\r\n\r\n" in req_body:
            _, _, req_body = req_body.partition(b"\r\n\r\n")

        while len(req_body) < content_len:
            to_read = min(8192, content_len - len(req_body))
            try:
                chunk = client_sock.recv(to_read)
                if not chunk:
                    break
                req_body += chunk
            except Exception:
                break

        family, remote_ip = pinned
        try:
            remote_sock = self._connect_pinned(family, remote_ip, target_port, timeout=10.0)
        except Exception as e:
            self._send_simple_response(client_sock, "502 Bad Gateway", f"Gateway Error: {e}\n")
            return

        # Rewrite request to relative path for origin server
        origin_request = f"{method} {url_path} HTTP/1.1\r\n"
        for k, v in headers.items():
            if k.lower() not in ("proxy-connection", "keep-alive", "proxy-authorization"):
                origin_request += f"{k.title()}: {v}\r\n"
        origin_request += "Connection: close\r\n\r\n"

        bytes_sent = len(origin_request.encode("utf-8")) + len(req_body)
        bytes_recv = 0
        preview_buf = bytearray()
        status_code = 200

        try:
            remote_sock.sendall(origin_request.encode("utf-8"))
            if req_body:
                remote_sock.sendall(req_body)

            while self._running:
                chunk = remote_sock.recv(8192)
                if not chunk:
                    break
                bytes_recv += len(chunk)
                if len(preview_buf) < MAX_RESPONSE_PREVIEW_BYTES:
                    need = MAX_RESPONSE_PREVIEW_BYTES - len(preview_buf)
                    preview_buf.extend(chunk[:need])
                try:
                    client_sock.sendall(chunk)
                except Exception:
                    break

            if preview_buf:
                status_line = bytes(preview_buf).split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
                parts = status_line.split(" ")
                if len(parts) >= 2 and parts[1].isdigit():
                    status_code = int(parts[1])

        except Exception as e:
            logger.debug("HTTP proxy error: %s", e)
        finally:
            remote_sock.close()

        category = self.rules.classify(target_host, target_port)
        response_preview = bytes(preview_buf[:500]).decode("utf-8", errors="replace")

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
