"""Egress Collector and Storage Engine for AI Agent Traffic.

Thread-safe memory ring-buffer and SQLite WAL backing store.
Zero external dependencies (pure Python standard library).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class NetworkEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    pid: Optional[int] = None
    agent_name: str = "default_agent"
    domain: str = "unknown"
    remote_ip: str = "0.0.0.0"
    remote_port: int = 443
    protocol: str = "HTTPS"
    method: str = "GET"
    url_path: str = "/"
    status_code: int = 200
    bytes_sent: int = 0
    bytes_recv: int = 0
    latency_ms: float = 0.0
    content_type: str = "application/json"
    headers: Dict[str, str] = field(default_factory=dict)
    request_sample: str = ""
    response_sample: str = ""
    category: str = "unknown"
    quarantined: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EgressCollector:
    """Thread-safe collector and database for agent network observations."""

    def __init__(self, db_path: Optional[str] = None, max_ring_size: int = 2000):
        self.max_ring_size = max_ring_size
        self._events: List[NetworkEvent] = []
        self._lock = threading.RLock()

        if db_path is None:
            data_dir = Path.home() / ".agent_egress"
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(data_dir / "egress.db")
        else:
            self.db_path = db_path
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS egress_events (
                        id TEXT PRIMARY KEY,
                        timestamp REAL,
                        pid INTEGER,
                        agent_name TEXT,
                        domain TEXT,
                        remote_ip TEXT,
                        remote_port INTEGER,
                        protocol TEXT,
                        method TEXT,
                        url_path TEXT,
                        status_code INTEGER,
                        bytes_sent INTEGER,
                        bytes_recv INTEGER,
                        latency_ms REAL,
                        content_type TEXT,
                        headers_json TEXT,
                        request_sample TEXT,
                        response_sample TEXT,
                        category TEXT,
                        quarantined INTEGER,
                        notes TEXT
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_egress_domain ON egress_events(domain);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_egress_agent ON egress_events(agent_name);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_egress_timestamp ON egress_events(timestamp);")
                conn.commit()

    def record(self, event: NetworkEvent) -> NetworkEvent:
        """Record a captured network event to the ring buffer and SQLite database."""
        with self._lock:
            self._events.append(event)
            if len(self._events) > self.max_ring_size:
                self._events.pop(0)

            try:
                with self._get_connection() as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO egress_events (
                            id, timestamp, pid, agent_name, domain, remote_ip, remote_port,
                            protocol, method, url_path, status_code, bytes_sent, bytes_recv,
                            latency_ms, content_type, headers_json, request_sample, response_sample,
                            category, quarantined, notes
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        event.id,
                        event.timestamp,
                        event.pid,
                        event.agent_name,
                        event.domain,
                        event.remote_ip,
                        event.remote_port,
                        event.protocol,
                        event.method,
                        event.url_path,
                        event.status_code,
                        event.bytes_sent,
                        event.bytes_recv,
                        event.latency_ms,
                        event.content_type,
                        json.dumps(event.headers, ensure_ascii=False),
                        event.request_sample,
                        event.response_sample,
                        event.category,
                        1 if event.quarantined else 0,
                        event.notes,
                    ))
                    conn.commit()
            except Exception:
                pass

        return event

    def get_events(
        self,
        domain: Optional[str] = None,
        agent_name: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical events with filtering."""
        with self._lock:
            with self._get_connection() as conn:
                clauses = []
                params: List[Any] = []
                if domain:
                    clauses.append("domain LIKE ?")
                    params.append(f"%{domain}%")
                if agent_name:
                    clauses.append("agent_name = ?")
                    params.append(agent_name)
                if category:
                    clauses.append("category = ?")
                    params.append(category)

                where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
                query = f"""
                    SELECT * FROM egress_events
                    {where_sql}
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?;
                """
                params.extend([limit, offset])
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                result = []
                for row in rows:
                    item = dict(row)
                    item["quarantined"] = bool(item["quarantined"])
                    try:
                        item["headers"] = json.loads(item["headers_json"])
                    except Exception:
                        item["headers"] = {}
                    item.pop("headers_json", None)
                    result.append(item)
                return result

    def get_domains(self) -> List[Dict[str, Any]]:
        """Aggregate domain statistics for visualization and audit."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT
                        domain,
                        category,
                        COUNT(*) as request_count,
                        SUM(bytes_sent) as total_bytes_sent,
                        SUM(bytes_recv) as total_bytes_recv,
                        AVG(latency_ms) as avg_latency_ms,
                        MAX(timestamp) as last_seen,
                        SUM(CASE WHEN quarantined = 1 THEN 1 ELSE 0 END) as quarantined_count,
                        COUNT(DISTINCT url_path) as unique_endpoints
                    FROM egress_events
                    GROUP BY domain
                    ORDER BY request_count DESC;
                """)
                return [dict(r) for r in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """Substrate metrics summary."""
        with self._lock:
            with self._get_connection() as conn:
                row = conn.execute("""
                    SELECT
                        COUNT(*) as total_requests,
                        COUNT(DISTINCT domain) as total_domains,
                        COUNT(DISTINCT agent_name) as total_agents,
                        COALESCE(SUM(bytes_sent), 0) as total_bytes_sent,
                        COALESCE(SUM(bytes_recv), 0) as total_bytes_recv,
                        COALESCE(AVG(latency_ms), 0) as avg_latency_ms,
                        SUM(CASE WHEN quarantined = 1 THEN 1 ELSE 0 END) as total_quarantined
                    FROM egress_events;
                """).fetchone()
                return dict(row) if row else {}

    def export_har(self) -> Dict[str, Any]:
        """Export captured traffic in standard HTTP Archive (HAR 1.2) format."""
        events = self.get_events(limit=500)
        entries = []
        for e in events:
            raw_path = e["url_path"]
            if raw_path.startswith("tunnel://"):
                full_url = f"https://{e['domain']}:{e['remote_port']}"
            elif raw_path.startswith("/"):
                full_url = f"{e['protocol'].lower()}://{e['domain']}{raw_path}"
            else:
                full_url = f"{e['protocol'].lower()}://{e['domain']}/{raw_path}"

            entries.append({
                "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e["timestamp"])),
                "time": round(e["latency_ms"], 2),
                "request": {
                    "method": e["method"],
                    "url": full_url,
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": str(v)} for k, v in e.get("headers", {}).items()],
                    "queryString": [],
                    "bodySize": e["bytes_sent"],
                    "postData": {"mimeType": e["content_type"], "text": e["request_sample"]} if e["request_sample"] else None,
                },
                "response": {
                    "status": e["status_code"],
                    "statusText": "OK" if e["status_code"] == 200 else "Captured",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": "Content-Type", "value": e["content_type"]}],
                    "content": {"size": e["bytes_recv"], "mimeType": e["content_type"], "text": e["response_sample"]},
                    "bodySize": e["bytes_recv"],
                },
                "serverIPAddress": e["remote_ip"],
                "connection": str(e["remote_port"]),
                "_agent": e["agent_name"],
                "_category": e["category"],
            })

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "Agent Egress Sentinel", "version": "0.1.0"},
                "entries": entries,
            }
        }

    def clear(self) -> None:
        """Clear all logged events."""
        with self._lock:
            self._events.clear()
            with self._get_connection() as conn:
                conn.execute("DELETE FROM egress_events;")
                conn.commit()


_DEFAULT_COLLECTOR: Optional[EgressCollector] = None


def get_default_collector() -> EgressCollector:
    global _DEFAULT_COLLECTOR
    if _DEFAULT_COLLECTOR is None:
        _DEFAULT_COLLECTOR = EgressCollector()
    return _DEFAULT_COLLECTOR
