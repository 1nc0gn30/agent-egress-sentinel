"""Agent Egress Sentinel — Network Traffic Sniffer & Endpoint Monitor for AI Agents.

Autonomous Zero-Dependency Network Interceptor, Domain Classifier,
and Telemetry Radar for AI Agents and LLM Runtimes.
100% Python Standard Library.
"""

__version__ = "0.1.0"
__author__ = "1nc0gn30 (@1nc0gn30)"
__entity__ = "1nc0gn30 • NullAI • NullAI Platform"

from .collector import EgressCollector, get_default_collector, NetworkEvent
from .proxy import EgressProxy
from .rules_engine import RulesEngine, DomainCategory
from .process_runner import AgentProcessRunner
from .server import EgressServer, run_server

__all__ = [
    "__version__",
    "EgressCollector",
    "get_default_collector",
    "NetworkEvent",
    "EgressProxy",
    "RulesEngine",
    "DomainCategory",
    "AgentProcessRunner",
    "EgressServer",
    "run_server",
]
