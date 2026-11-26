"""Domain Taxonomy, Classification, SSRF Guard, and Quarantine Rules Engine.

Identifies AI Agent egress destinations (LLM APIs, Model Hubs, Telemetry, Search,
Local, Private/Metadata Networks) and enforces quarantine & SSRF policy rules
with zero external dependencies.
"""

from __future__ import annotations

import ipaddress
import os
import re
import threading
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class DomainCategory(str, Enum):
    LLM_API = "llm_api"
    MODEL_HUB = "model_hub"
    TELEMETRY_TRACKER = "telemetry_tracker"
    SEARCH_SCRAPER = "search_scraper"
    LOCAL_SERVICE = "local_service"
    PRIVATE_NETWORK = "private_network"
    EXTERNAL_WEB = "external_web"
    UNKNOWN = "unknown"


_METADATA_HOSTNAMES = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "169.254.169.254",
    "fd00:ec2::254",
})

# Pre-compiled classification patterns
_TAXONOMY_PATTERNS: List[Tuple[re.Pattern, DomainCategory]] = [
    # Local Services (loopback & mDNS)
    (
        re.compile(
            r"^(localhost|127\.\d+\.\d+\.\d+|::1|.*\.local|.*\.internal|.*\.lan)$",
            re.IGNORECASE,
        ),
        DomainCategory.LOCAL_SERVICE,
    ),
    # LLM APIs & Frontier Model Providers
    (
        re.compile(
            r"(^|\.)(openai\.com|anthropic\.com|x\.ai|groq\.com|deepseek\.com|mistral\.ai|cohere\.ai|cohere\.com|together\.xyz|together\.ai|fireworks\.ai|anyscale\.com|perplexity\.ai|openrouter\.ai|ai\.google\.dev|generativelanguage\.googleapis\.com|vertexai\.googleapis\.com|bedrock-runtime\..*\.amazonaws\.com)$",
            re.IGNORECASE,
        ),
        DomainCategory.LLM_API,
    ),
    # Model Hubs & Weights Distribution
    (
        re.compile(
            r"(^|\.)(huggingface\.co|hf\.co|civitai\.com|replicate\.com|replicate\.delivery|wandb\.ai|modal\.com|runpod\.io|ollama\.com|ollama\.ai)$",
            re.IGNORECASE,
        ),
        DomainCategory.MODEL_HUB,
    ),
    # Telemetry, Analytics & Error Tracking
    (
        re.compile(
            r"(^|\.)(segment\.io|segment\.com|posthog\.com|sentry\.io|datadoghq\.com|mixpanel\.com|amplitude\.com|telemetrydeck\.com|google-analytics\.com|analytics\.google\.com|statsigapi\.net|launchdarkly\.com|bugsnag\.com|raygun\.io|newrelic\.com|app-measurement\.com)$",
            re.IGNORECASE,
        ),
        DomainCategory.TELEMETRY_TRACKER,
    ),
    # Search, Scraping & Web Retrieval
    (
        re.compile(
            r"(^|\.)(serpapi\.com|serper\.dev|tavily\.com|exa\.ai|brave\.com|duckduckgo\.com|bing\.com|google\.com|searxng\..*)$",
            re.IGNORECASE,
        ),
        DomainCategory.SEARCH_SCRAPER,
    ),
    # Package & Code Registries
    (
        re.compile(
            r"(^|\.)(github\.com|githubusercontent\.com|gitlab\.com|npmjs\.org|npmjs\.com|pypi\.org|pythonhosted\.org)$",
            re.IGNORECASE,
        ),
        DomainCategory.EXTERNAL_WEB,
    ),
]


def _normalize_host(domain: str) -> str:
    """Normalize a host or host:port or [ipv6]:port string to lowercase hostname/IP."""
    cleaned = (domain or "").strip().lower()
    if not cleaned:
        return ""
    if cleaned.startswith("["):
        end = cleaned.find("]")
        if end != -1:
            return cleaned[1:end]
        return cleaned.strip("[]")
    # Single colon implies host:port (not raw IPv6 which has >= 2 colons)
    if cleaned.count(":") == 1:
        host_part, port_part = cleaned.split(":", 1)
        if port_part.isdigit() or port_part == "":
            return host_part
    return cleaned.rstrip(".")


def _parse_ip(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse an IPv4 or IPv6 literal, handling IPv4-mapped IPv6 addresses."""
    if not host:
        return None
    # Strip IPv6 zone identifier (e.g. fe80::1%eth0)
    bare = host.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(bare)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        return ip
    except ValueError:
        return None


def _ip_network_class(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Classify an IP address into loopback, link_local, private, reserved, or global."""
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_link_local:
        return "link_local"
    if ip_obj.is_unspecified or ip_obj.is_multicast:
        return "reserved"
    # RFC1918 (10/8, 172.16/12, 192.168/16), IPv6 ULA (fc00::/7), CGNAT (100.64/10)
    if ip_obj.is_private:
        return "private"
    if ip_obj.is_reserved:
        return "reserved"
    return "global"


class RulesEngine:
    """Evaluates agent outbound traffic against domain categories, SSRF guards, and quarantine rules."""

    def __init__(
        self,
        quarantine_mode: str = "allow_all",
        allowed_domains: Optional[Set[str]] = None,
        blocked_domains: Optional[Set[str]] = None,
        protected_ports: Optional[Set[int]] = None,
        allow_private_net: Optional[bool] = None,
    ):
        """Initialize Rules Engine.

        quarantine_mode options:
          - 'allow_all': Monitor only, never block public destinations (private/metadata/self-ports still guarded by default).
          - 'block_telemetry': Block known telemetry/tracker domains automatically.
          - 'zero_egress': Block ALL non-local egress (strictly local sandbox; self-control ports still protected).
          - 'allowlist_only': Only permit explicitly allowed domains.
        """
        self._lock = threading.RLock()
        self.quarantine_mode = quarantine_mode
        self.allowed_domains: Set[str] = {_normalize_host(d) for d in (allowed_domains or []) if _normalize_host(d)}
        self.blocked_domains: Set[str] = {_normalize_host(d) for d in (blocked_domains or []) if _normalize_host(d)}
        self.custom_categories: Dict[str, DomainCategory] = {}
        self.protected_ports: Set[int] = set(protected_ports) if protected_ports is not None else {8095, 8195}
        if allow_private_net is None:
            self.allow_private_net = os.environ.get("EGRESS_ALLOW_PRIVATE_NET", "").strip() == "1"
        else:
            self.allow_private_net = bool(allow_private_net)

    def register_protected_ports(self, *ports: int) -> None:
        with self._lock:
            for p in ports:
                if isinstance(p, int) and 1 <= p <= 65535:
                    self.protected_ports.add(p)

    def _matches_set(self, host: str, domain_set: Set[str]) -> Optional[str]:
        if host in domain_set:
            return host
        for entry in domain_set:
            if entry.startswith("*.") and host.endswith(entry[1:]):
                return entry
        return None

    def classify(self, domain: str, port: int = 443) -> DomainCategory:
        """Classify a target domain or IP into a DomainCategory."""
        cleaned = _normalize_host(domain)
        if not cleaned:
            return DomainCategory.UNKNOWN

        with self._lock:
            if cleaned in self.custom_categories:
                return self.custom_categories[cleaned]

        if cleaned in _METADATA_HOSTNAMES:
            return DomainCategory.PRIVATE_NETWORK

        ip_obj = _parse_ip(cleaned)
        if ip_obj is not None:
            net_cls = _ip_network_class(ip_obj)
            if net_cls == "loopback":
                return DomainCategory.LOCAL_SERVICE
            if net_cls in ("private", "link_local", "reserved"):
                return DomainCategory.PRIVATE_NETWORK
            return DomainCategory.EXTERNAL_WEB

        if cleaned in ("localhost",):
            return DomainCategory.LOCAL_SERVICE

        for pattern, category in _TAXONOMY_PATTERNS:
            if pattern.search(cleaned):
                return category

        return DomainCategory.EXTERNAL_WEB

    def is_allowed(
        self,
        domain: str,
        port: int = 443,
        resolved_ip: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Check if egress to the domain (and optional resolved IP) is permitted.

        Returns:
            (allowed: bool, reason: str)
        """
        cleaned = _normalize_host(domain)
        if not cleaned:
            return False, "Blocked: Empty destination host."

        with self._lock:
            mode = self.quarantine_mode
            allowed_domains = set(self.allowed_domains)
            blocked_domains = set(self.blocked_domains)
            protected_ports = set(self.protected_ports)
            allow_private = self.allow_private_net

        category = self.classify(cleaned, port)

        # 1. Explicit blocklist always takes top priority
        matched_block = self._matches_set(cleaned, blocked_domains)
        if matched_block:
            return False, f"Domain '{cleaned}' matches explicit blocklist rule '{matched_block}'."
        if resolved_ip:
            res_norm = _normalize_host(resolved_ip)
            matched_ip_block = self._matches_set(res_norm, blocked_domains)
            if matched_ip_block:
                return False, f"Resolved IP '{res_norm}' matches explicit blocklist rule '{matched_ip_block}'."

        # 2. Protect Sentinel's own loopback control plane & proxy ports from self-escape
        ip_literal = _parse_ip(cleaned)
        res_ip_obj = _parse_ip(_normalize_host(resolved_ip)) if resolved_ip else None
        is_loopback = (
            cleaned == "localhost"
            or (ip_literal is not None and (ip_literal.is_loopback or ip_literal.is_unspecified))
            or (res_ip_obj is not None and (res_ip_obj.is_loopback or res_ip_obj.is_unspecified))
        )
        if is_loopback and port in protected_ports:
            return (
                False,
                f"Blocked: Loopback control/proxy port {port} is protected against sentinel self-escape.",
            )

        # Check explicit allowlist match for host or resolved IP
        matched_allow = self._matches_set(cleaned, allowed_domains)
        if not matched_allow and resolved_ip:
            matched_allow = self._matches_set(_normalize_host(resolved_ip), allowed_domains)

        # 3. SSRF / Private RFC1918 / Link-local / Cloud Metadata / IPv6 ULA guard
        if cleaned in _METADATA_HOSTNAMES and not matched_allow and not allow_private:
            return False, f"Blocked: Cloud metadata endpoint '{cleaned}' denied by SSRF guard."

        for label, ip_candidate in (("destination", ip_literal), ("resolved IP", res_ip_obj)):
            if ip_candidate is None:
                continue
            net_cls = _ip_network_class(ip_candidate)
            if net_cls == "link_local" and not matched_allow and not allow_private:
                return (
                    False,
                    f"Blocked: Link-local / cloud metadata {label} '{ip_candidate}' denied by SSRF guard.",
                )
            if net_cls in ("private", "reserved") and not matched_allow and not allow_private:
                return (
                    False,
                    f"Blocked: Private/reserved network {label} '{ip_candidate}' denied by SSRF guard.",
                )

        # 4. Explicit allowlist overrides quarantine modes
        if matched_allow:
            return True, f"Domain '{cleaned}' matches explicit allowlist rule '{matched_allow}'."

        # 5. Policy quarantine evaluation
        if mode == "zero_egress":
            if category != DomainCategory.LOCAL_SERVICE or not is_loopback:
                return False, "Zero-egress quarantine policy active (all non-loopback egress blocked)."
            return True, "Permitted local loopback egress under zero-egress policy."

        if mode == "allowlist_only":
            return False, "Egress blocked under allowlist_only quarantine policy."

        if mode == "block_telemetry":
            if category == DomainCategory.TELEMETRY_TRACKER:
                return False, "Blocked: Target identified as telemetry/analytics tracker."
            return True, "Permitted: Target is not a telemetry tracker."

        # Default 'allow_all'
        return True, "Permitted under monitor-only policy."

    def add_allowed_domain(self, domain: str) -> str:
        norm = _normalize_host(domain)
        if not norm:
            raise ValueError("Invalid domain")
        with self._lock:
            self.allowed_domains.add(norm)
            self.blocked_domains.discard(norm)
        return norm

    def remove_allowed_domain(self, domain: str) -> bool:
        norm = _normalize_host(domain)
        with self._lock:
            existed = norm in self.allowed_domains
            self.allowed_domains.discard(norm)
            return existed

    def add_blocked_domain(self, domain: str) -> str:
        norm = _normalize_host(domain)
        if not norm:
            raise ValueError("Invalid domain")
        with self._lock:
            self.blocked_domains.add(norm)
            self.allowed_domains.discard(norm)
        return norm

    def remove_blocked_domain(self, domain: str) -> bool:
        norm = _normalize_host(domain)
        with self._lock:
            existed = norm in self.blocked_domains
            self.blocked_domains.discard(norm)
            return existed

    def set_quarantine_mode(self, mode: str) -> None:
        valid_modes = {"allow_all", "block_telemetry", "zero_egress", "allowlist_only"}
        if mode not in valid_modes:
            raise ValueError(f"Invalid mode '{mode}'. Choose from: {sorted(valid_modes)}")
        with self._lock:
            self.quarantine_mode = mode

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "quarantine_mode": self.quarantine_mode,
                "allowed_domains": sorted(self.allowed_domains),
                "blocked_domains": sorted(self.blocked_domains),
                "protected_ports": sorted(self.protected_ports),
                "allow_private_net": self.allow_private_net,
                "custom_categories": {k: v.value for k, v in self.custom_categories.items()},
            }
