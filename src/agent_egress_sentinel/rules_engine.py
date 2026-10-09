"""Domain Taxonomy, Classification, and Quarantine Rules Engine.

Identifies AI Agent egress destinations (LLM APIs, Model Hubs, Telemetry, Search, Local)
and enforces quarantine policy rules with zero external dependencies.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class DomainCategory(str, Enum):
    LLM_API = "llm_api"
    MODEL_HUB = "model_hub"
    TELEMETRY_TRACKER = "telemetry_tracker"
    SEARCH_SCRAPER = "search_scraper"
    LOCAL_SERVICE = "local_service"
    EXTERNAL_WEB = "external_web"
    UNKNOWN = "unknown"


# Pre-compiled classification patterns
_TAXONOMY_PATTERNS: List[Tuple[re.Pattern, DomainCategory]] = [
    # Local & Private Services
    (
        re.compile(
            r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|.*\.local|.*\.internal|.*\.lan)$",
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


class RulesEngine:
    """Evaluates agent outbound traffic against domain categories and quarantine rules."""

    def __init__(
        self,
        quarantine_mode: str = "allow_all",
        allowed_domains: Optional[Set[str]] = None,
        blocked_domains: Optional[Set[str]] = None,
    ):
        """Initialize Rules Engine.

        quarantine_mode options:
          - 'allow_all': Monitor only, never block.
          - 'block_telemetry': Block known telemetry/tracker domains automatically.
          - 'zero_egress': Block ALL non-local egress (strictly local sandbox).
          - 'allowlist_only': Only permit explicitly allowed domains.
        """
        self.quarantine_mode = quarantine_mode
        self.allowed_domains: Set[str] = set(allowed_domains or [])
        self.blocked_domains: Set[str] = set(blocked_domains or [])
        self.custom_categories: Dict[str, DomainCategory] = {}

    def classify(self, domain: str, port: int = 443) -> DomainCategory:
        """Classify a target domain into a DomainCategory."""
        cleaned_domain = domain.strip().lower()
        if ":" in cleaned_domain:
            cleaned_domain = cleaned_domain.split(":", 1)[0]

        # Check custom overrides first
        if cleaned_domain in self.custom_categories:
            return self.custom_categories[cleaned_domain]

        # Check local ports / addresses
        if cleaned_domain in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or port in (11434, 1234, 8000, 8080, 8094, 8095, 9393, 9394):
            if cleaned_domain in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
                return DomainCategory.LOCAL_SERVICE

        for pattern, category in _TAXONOMY_PATTERNS:
            if pattern.search(cleaned_domain):
                return category

        return DomainCategory.EXTERNAL_WEB

    def is_allowed(self, domain: str, port: int = 443) -> Tuple[bool, str]:
        """Check if egress to the domain is permitted under current policy.

        Returns:
            (allowed: bool, reason: str)
        """
        cleaned_domain = domain.strip().lower()
        if ":" in cleaned_domain:
            cleaned_domain = cleaned_domain.split(":", 1)[0]

        category = self.classify(cleaned_domain, port)

        # 1. Explicit blocklist always takes top priority
        if cleaned_domain in self.blocked_domains:
            return False, f"Domain '{cleaned_domain}' is in explicit blocklist."

        for blocked in self.blocked_domains:
            if blocked.startswith("*.") and cleaned_domain.endswith(blocked[1:]):
                return False, f"Domain matches wildcard block '{blocked}'."

        # 2. Explicit allowlist overrides quarantine modes
        if cleaned_domain in self.allowed_domains:
            return True, f"Domain '{cleaned_domain}' is in explicit allowlist."

        for allowed in self.allowed_domains:
            if allowed.startswith("*.") and cleaned_domain.endswith(allowed[1:]):
                return True, f"Domain matches wildcard allow '{allowed}'."

        # 3. Policy quarantine evaluation
        if self.quarantine_mode == "zero_egress":
            if category != DomainCategory.LOCAL_SERVICE:
                return False, "Zero-egress quarantine policy active (all non-local egress blocked)."
            return True, "Permitted local egress under zero-egress policy."

        if self.quarantine_mode == "allowlist_only":
            return False, "Egress blocked under allowlist_only quarantine policy."

        if self.quarantine_mode == "block_telemetry":
            if category == DomainCategory.TELEMETRY_TRACKER:
                return False, "Blocked: Target identified as telemetry/analytics tracker."
            return True, "Permitted: Target is not a telemetry tracker."

        # Default 'allow_all'
        return True, "Permitted under monitor-only policy."

    def add_allowed_domain(self, domain: str) -> None:
        self.allowed_domains.add(domain.strip().lower())

    def remove_allowed_domain(self, domain: str) -> None:
        self.allowed_domains.discard(domain.strip().lower())

    def add_blocked_domain(self, domain: str) -> None:
        self.blocked_domains.add(domain.strip().lower())

    def remove_blocked_domain(self, domain: str) -> None:
        self.blocked_domains.discard(domain.strip().lower())

    def set_quarantine_mode(self, mode: str) -> None:
        valid_modes = {"allow_all", "block_telemetry", "zero_egress", "allowlist_only"}
        if mode not in valid_modes:
            raise ValueError(f"Invalid mode '{mode}'. Choose from: {valid_modes}")
        self.quarantine_mode = mode

    def get_summary(self) -> Dict[str, Any]:
        return {
            "quarantine_mode": self.quarantine_mode,
            "allowed_domains": sorted(list(self.allowed_domains)),
            "blocked_domains": sorted(list(self.blocked_domains)),
            "custom_categories": {k: v.value for k, v in self.custom_categories.items()},
        }
