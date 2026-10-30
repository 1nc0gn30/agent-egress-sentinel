<div align="center">
  <img src="assets/hero-banner.svg" alt="Agent Egress Sentinel — Sovereign Architecture Banner" width="100%" />
</div>

<br />

<div align="center">
  <a href="https://zoth.nullai.tech/tools/agent-egress-sentinel"><img src="https://img.shields.io/badge/Zoth_Studio_v2-Workspace-D4AF37?style=for-the-badge&logo=sparkles&logoColor=black" alt="Zoth Studio Workspace" /></a>
  <a href="http://127.0.0.1:8095"><img src="https://img.shields.io/badge/Radar-Port_:8095-38BDF8?style=for-the-badge&logo=fastapi&logoColor=black" alt="Port :8095" /></a>
  <a href="http://127.0.0.1:8195"><img src="https://img.shields.io/badge/Proxy-Port_:8195-10B981?style=for-the-badge&logo=shield&logoColor=black" alt="Proxy :8195" /></a>
  <a href="https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X"><img src="https://img.shields.io/badge/☕_Buy_Us_a_Coffee-Stripe-D4AF37?style=for-the-badge" alt="Buy Us a Coffee" /></a>
</div>

# 🛡️ Agent Egress Sentinel

> **Autonomous Zero-Dependency Network Interceptor, Domain Classifier, and Kinetic Egress Radar for AI Agents and LLM Runtimes.**  
> *Engineered by Neal Frazier Tech ([@1nc0gn30](https://github.com/1nc0gn30)) • NullAI Platform*

---

## 🏛️ Architectural Overview

**Agent Egress Sentinel** is an official sovereign tool in the **[Zoth Studio v2](https://zoth.nullai.tech)** (71-Tool Matrix) and **[ZothOS Linux 3.3](https://zothos.nullai.tech)** ecosystem.

| Property | Specification |
| :--- | :--- |
| **Tool ID** | `agent-egress-sentinel` |
| **Category** | `Security & Network` |
| **Web Radar Port** | `http://127.0.0.1:8095` |
| **Proxy Tunnel Port** | `http://127.0.0.1:8195` |
| **Execution Mode** | Python Standard Library Server + Proxy Daemon |
| **Zoth Studio Route** | [`http://127.0.0.1:3000/tools/agent-egress-sentinel`](http://127.0.0.1:3000/tools/agent-egress-sentinel) |
| **License** | **100% Free & Open Access (Zero Paywalls)** |

---

## 💎 What It Does & How It Works

- **Zero-Dependency Python Standard Library**: Operates completely out-of-the-box using standard `socket`, `select`, `sqlite3`, `http.server`, and `threading`. Zero external `pip` dependencies.
- **In-Memory TLS ClientHello SNI Extractor**: Sniffs destination hostnames directly from the initial TLS handshake without breaking SSL certificate chains or requiring self-signed root cert installations.
- **Kinetic Orbital Radar Dashboard**: Real-time concentric visual radar mapping destinations across LLM APIs, Model Hubs, Telemetry Sinks, Search Engines, and Local loopback services.
- **Autonomous Rules & Kernel Quarantine**:
  - `ALLOW_ALL`: Monitor and trace all agent outbound requests in real time.
  - `BLOCK_TELEMETRY`: Blackhole tracking pings (Segment, PostHog, Sentry, Datadog) while allowing model inference.
  - `ZERO_EGRESS`: Strict air-gap mode isolating all egress except localhost/127.0.0.1.
  - `ALLOWLIST_ONLY`: Restrict outbound connections strictly to verified domains.
- **Compliance HAR 1.2 & OpenAPI Exporter**: Generates standard HTTP Archive (HAR 1.2) traces and synthesized OpenAPI 3.0 specs of agent-discovered endpoints.

---

## 🛠️ ZothOS CLI & Daemon Commands

The CLI is pre-installed in `/usr/local/bin/agent-egress-sentinel` (aliased as `agent-egress`):

```bash
# Check daemon health & ZothOS integration status
agent-egress --status

# Print current session statistics & observed domains
agent-egress stats

# Run an arbitrary agent script under sentinel proxy supervision
agent-egress run python3 my_agent.py

# Export network traffic trace to HAR 1.2 format
agent-egress export agent-traffic.har

# Synthesize discovered endpoints into OpenAPI 3.0 specification
agent-egress openapi openapi-spec.json

# Clear historical database and traffic events
agent-egress clear

# Start radar web UI (:8095) and proxy tunnel (:8195)
agent-egress serve --web-port 8095 --proxy-port 8195
```

---

## ☕ Support Neal Frazier Tech (Zero Paywalls)

All tools across the Zoth Studio ecosystem are 100% free, unlocked, and open-source by default. If this utility provides value to your workflow, support development via:

- **Stripe "Buy Us a Coffee"**: [https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)
- **Solana Tip Address**: `GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK`

---

<div align="center">
  <sub>Engineered by <b>Neal Frazier Tech</b> (<a href="https://github.com/1nc0gn30">@1nc0gn30</a>) &bull; <a href="https://nullai.tech">NullAI Platform</a> &bull; <a href="https://zoth.nullai.tech">Zoth Studio v2</a></sub>
</div>
