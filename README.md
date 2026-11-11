# Agent Egress Sentinel

![Agent Egress Sentinel Hero Banner](assets/hero-banner.svg)

**Agent Egress Sentinel** (`agent-egress-sentinel`) is a zero-dependency Python 3.9+ network interceptor, HTTP/HTTPS `CONNECT` egress proxy (`127.0.0.1:8195`), domain classifier, and real-time telemetry radar (`127.0.0.1:8095`) for AI agents and LLM runtimes. It tracks outbound requests, enforces domain quarantine policies, and exports captured traffic to HAR 1.2 or synthesized OpenAPI 3.0 specifications.

- **Zoth Studio v2 Dossier**: [https://zoth.nullai.tech/tools/agent-egress-sentinel](https://zoth.nullai.tech/tools/agent-egress-sentinel)
- **Repository**: [https://github.com/1nc0gn30/agent-egress-sentinel](https://github.com/1nc0gn30/agent-egress-sentinel)
- **Default Loopback Endpoints**: Web Radar `http://127.0.0.1:8095` • Egress Proxy `http://127.0.0.1:8195`

---

## Overview

- **HTTP & HTTPS `CONNECT` Proxy (`EgressProxy`)**: Listens on `127.0.0.1:8195`, recording destination hostnames, byte counts, status codes, and latency across agent tool and SDK calls.
- **Process Supervision (`AgentProcessRunner`)**: Wraps child agent processes with `HTTP_PROXY` / `HTTPS_PROXY` pointed at `127.0.0.1:8195` while sampling `/proc/net/tcp` socket states to detect direct-socket bypasses.
- **4 Quarantine Policy Modes (`RulesEngine`)**:
  - `allow_all`: Log and classify all outbound destinations without blocking.
  - `block_telemetry`: Block analytics, crash-reporting, and telemetry beacons while allowing LLM and API traffic.
  - `allowlist_only`: Permit only domains explicitly added to the allowlist.
  - `zero_egress`: Quarantine 100% of external network traffic for air-gapped agent runs.
- **HAR 1.2 & OpenAPI 3.0 Export**: Exports captured traces to standard HAR 1.2 archives or synthesizes OpenAPI 3.0 schemas directly from observed API paths (ready for offline replay in `agent-mock-twin`).

---

## Architecture

```text
Agent Process (HTTP_PROXY / HTTPS_PROXY -> 127.0.0.1:8195)
        │
        ▼
EgressProxy (:8195) ──► RulesEngine (allow_all | block_telemetry | allowlist_only | zero_egress)
        │
        ▼
TrafficCollector (SQLite) ──► Radar Web UI (:8095) + SSE (/api/stream) + HAR / OpenAPI Export
```

---

## Quickstart

```bash
git clone https://github.com/1nc0gn30/agent-egress-sentinel.git
cd agent-egress-sentinel
python3 -m pip install -e .

# Start Web Radar (:8095) and Egress Proxy (:8195)
agent-egress serve --web-host 127.0.0.1 --web-port 8095 --proxy-host 127.0.0.1 --proxy-port 8195 --quarantine block_telemetry
```

Or run directly from the repository checkout:

```bash
python3 server.py --web-port 8095 --proxy-port 8195
```

Open `http://127.0.0.1:8095` in your browser.

---

## CLI & ZothOS v3.4.0 Integration

`agent-egress` (`./bin/agent-egress` and `./bin/agent-egress-sentinel-tui`) supervises child processes, inspects daemon metrics, and exports traces:

```bash
# Inspect live daemon health and observed domain stats
agent-egress --status
agent-egress --json
agent-egress stats --port 8095 --json

# Run an AI agent command under proxy supervision on :8195 and export HAR 1.2
agent-egress run --agent-name researcher_01 --proxy-port 8195 --quarantine block_telemetry --export-har session.har -- python3 my_agent.py

# Export captured traffic to HAR 1.2 or OpenAPI 3.0
agent-egress export -o agent-traffic.har
agent-egress openapi -o openapi-spec.json

# Clear historical egress logs
agent-egress clear
```

---

## REST API Reference

Mutating `POST` routes enforce local-origin CSRF validation (`127.0.0.1`, `localhost`, `[::1]`, or local CLI callers).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Web radar dashboard (`public/index.html`) |
| `GET` | `/health`, `/api/health`, `/status` | Service health, `web_port` (`8095`), `proxy_port` (`8195`), and `quarantine_mode` |
| `GET` | `/api/stats` | Total requests, domains, agents, bytes sent/received, and quarantined count |
| `GET` | `/api/domains` | Aggregated per-domain request counts, categories, and latency |
| `GET` | `/api/traffic?limit=100` | Captured network events filterable by `domain`, `category`, and `agent` |
| `GET` | `/api/rules` | Active quarantine mode plus custom allowlist and blocklist domains |
| `GET` | `/api/export` | Download captured traffic as HAR 1.2 (`agent-egress.har`) |
| `GET` | `/api/openapi`, `/api/export/openapi` | Download synthesized OpenAPI 3.0 JSON specification |
| `GET` | `/api/stream` | Live Server-Sent Events (SSE) network event stream |
| `POST` | `/api/quarantine` | Set quarantine policy (`{"mode": "block_telemetry"}`) |
| `POST` | `/api/rules/block`, `/api/rules/allow` | Block or allowlist a specific domain (`{"domain": "telemetry.example.com"}`) |
| `POST` | `/api/clear` | Clear captured egress logs |

---

## Testing & Verification

```bash
PYTHONPATH=src python3 -m pytest -q
./bin/agent-egress --help
./bin/agent-egress --json
```

---

## Support & License

100% free and open-source software under the MIT License.

- Optional support: [Buy Us a Coffee via Stripe](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)
- Engineered by **1nc0gn30** (`@1nc0gn30`, [https://1nc0gn30.si](https://1nc0gn30.si)) • **NullAI** ([https://nullai.tech](https://nullai.tech))
