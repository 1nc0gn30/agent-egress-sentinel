/**
 * Agent Egress Sentinel v2.6.0 — Kinetic Domain Radar & Telemetry Engine
 * Pure Vanilla Canvas & Safe DOM Builder Architecture. Zero external JS dependencies.
 * Zero inline onclick HTML sinks (XSS-safe). Dual Light/Dark theme aware.
 * Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
 */

(function () {
  'use strict';

  const SOLANA_TIP_ADDRESS = 'GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK';
  const VERSION = '2.6.0';

  const CATEGORY_THEME_DARK = {
    llm_api: { label: 'LLM API', color: '#38BDF8', glow: 'rgba(56, 189, 248, 0.35)', orbit: 110 },
    model_hub: { label: 'Model Hub', color: '#A855F7', glow: 'rgba(168, 85, 247, 0.35)', orbit: 165 },
    telemetry_tracker: { label: 'Telemetry', color: '#EF4444', glow: 'rgba(239, 68, 68, 0.35)', orbit: 220 },
    private_network: { label: 'Private / SSRF', color: '#F43F5E', glow: 'rgba(244, 63, 94, 0.38)', orbit: 245 },
    search_scraper: { label: 'Search/Scraper', color: '#10B981', glow: 'rgba(16, 185, 129, 0.35)', orbit: 270 },
    local_service: { label: 'Local Loopback', color: '#F59E0B', glow: 'rgba(245, 158, 11, 0.35)', orbit: 65 },
    external_web: { label: 'External Web', color: '#94A3B8', glow: 'rgba(148, 163, 184, 0.28)', orbit: 305 },
    unknown: { label: 'Unknown', color: '#64748B', glow: 'rgba(100, 116, 139, 0.28)', orbit: 325 },
  };

  const CATEGORY_THEME_LIGHT = {
    llm_api: { label: 'LLM API', color: '#0369A1', glow: 'rgba(3, 105, 161, 0.22)', orbit: 110 },
    model_hub: { label: 'Model Hub', color: '#6D28D9', glow: 'rgba(109, 40, 217, 0.22)', orbit: 165 },
    telemetry_tracker: { label: 'Telemetry', color: '#BE123C', glow: 'rgba(190, 18, 60, 0.22)', orbit: 220 },
    private_network: { label: 'Private / SSRF', color: '#9F1239', glow: 'rgba(159, 18, 57, 0.24)', orbit: 245 },
    search_scraper: { label: 'Search/Scraper', color: '#047857', glow: 'rgba(4, 120, 87, 0.22)', orbit: 270 },
    local_service: { label: 'Local Loopback', color: '#B45309', glow: 'rgba(180, 83, 9, 0.22)', orbit: 65 },
    external_web: { label: 'External Web', color: '#475569', glow: 'rgba(71, 85, 105, 0.18)', orbit: 305 },
    unknown: { label: 'Unknown', color: '#64748B', glow: 'rgba(100, 116, 139, 0.18)', orbit: 325 },
  };

  function isLightMode() {
    return document.documentElement.getAttribute('data-theme') === 'light';
  }

  function getCategoryTheme(cat) {
    const map = isLightMode() ? CATEGORY_THEME_LIGHT : CATEGORY_THEME_DARK;
    return map[cat] || map.unknown;
  }

  const state = {
    daemonOnline: false,
    proxyPort: 8195,
    domains: new Map(),
    events: [],
    rules: {
      quarantine_mode: 'allow_all',
      allowed_domains: [],
      blocked_domains: [],
      protected_ports: [8095, 8195],
    },
    selectedDomain: null,
    filterCategory: 'all',
    searchQuery: '',
    sweepAngle: 0,
    particles: [],
    hoveredNode: null,
    sseConnected: false,
    canvasSize: 540,
    stats: {
      total_requests: 0,
      total_domains: 0,
      total_bytes_sent: 0,
      total_bytes_recv: 0,
      avg_latency_ms: 0,
      total_quarantined: 0,
      quarantine_mode: 'allow_all',
    },
  };

  let canvas, ctx;
  let statsReqs, statsDomains, statsData, statsLatency, statsQuarantine;
  let trafficTableBody, domainListEl;

  async function init() {
    canvas = document.getElementById('radarCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');

    statsReqs = document.getElementById('statTotalReqs');
    statsDomains = document.getElementById('statTotalDomains');
    statsData = document.getElementById('statTotalData');
    statsLatency = document.getElementById('statAvgLatency');
    statsQuarantine = document.getElementById('statQuarantined');
    trafficTableBody = document.getElementById('trafficTableBody');
    domainListEl = document.getElementById('domainList');

    updateThemeToggleLabel();
    bindCanvasEventsOnce();
    resizeCanvas();
    setupEventListeners();

    const online = await probeDaemonHealth();
    if (online) {
      await Promise.all([fetchStats(), fetchDomains(), fetchTraffic(), fetchRules()]);
      connectSSE();
      setInterval(fetchStats, 4000);
      setInterval(fetchDomains, 5000);
    } else {
      setOfflinePreviewState();
    }

    requestAnimationFrame(renderLoop);
  }

  async function probeDaemonHealth() {
    try {
      const res = await fetch('/api/health', { cache: 'no-store' });
      if (!res.ok) return false;
      const data = await res.json();
      if (!data || data.status !== 'ok') return false;

      state.daemonOnline = true;
      state.proxyPort = data.proxy_port || 8195;
      updateProxyLabels(state.proxyPort);
      updateDaemonBadge(true, state.proxyPort);
      return true;
    } catch (_err) {
      state.daemonOnline = false;
      updateDaemonBadge(false, state.proxyPort);
      return false;
    }
  }

  function updateProxyLabels(port) {
    const endpoint = `127.0.0.1:${port}`;
    const badge = document.getElementById('proxyEndpointBadge');
    const inline = document.getElementById('proxyPortInline');
    const hint = document.getElementById('proxyEmptyHint');
    if (badge) badge.textContent = endpoint;
    if (inline) inline.textContent = endpoint;
    if (hint) hint.textContent = endpoint;
  }

  function updateDaemonBadge(online, proxyPort) {
    const txt = document.getElementById('daemonModeText');
    const dot = document.getElementById('sseIndicator');
    if (txt) {
      txt.textContent = online ? `LIVE PROXY :${proxyPort}` : 'OFFLINE PREVIEW';
    }
    if (dot) {
      dot.style.background = online ? 'var(--accent-emerald)' : 'var(--accent-amber)';
      dot.style.boxShadow = online ? '0 0 8px var(--accent-emerald)' : '0 0 8px var(--accent-amber)';
    }
  }

  function setOfflinePreviewState() {
    state.stats = {
      total_requests: 0,
      total_domains: 0,
      total_bytes_sent: 0,
      total_bytes_recv: 0,
      avg_latency_ms: 0,
      total_quarantined: 0,
      quarantine_mode: 'block_telemetry',
    };
    renderStats();
    renderDomainList();
    renderTrafficTable();
    renderRulesLists();
  }

  // --- Theme Management ---
  function updateThemeToggleLabel() {
    const btn = document.getElementById('themeToggleBtn');
    if (!btn) return;
    btn.textContent = isLightMode() ? '☾ Dark' : '☀ Light';
  }

  function toggleTheme() {
    const next = isLightMode() ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    try {
      localStorage.setItem('egress-sentinel-theme', next);
    } catch (_e) {}
    updateThemeToggleLabel();
  }

  // --- Canvas Sizing & Single-Bind Listeners (Zero Listener Leak) ---
  function bindCanvasEventsOnce() {
    canvas.addEventListener('mousemove', onCanvasMouseMove);
    canvas.addEventListener('mouseleave', () => { state.hoveredNode = null; });
    canvas.addEventListener('click', onCanvasClick);
    window.addEventListener('resize', debounce(resizeCanvas, 150));
  }

  function resizeCanvas() {
    const container = canvas.parentElement;
    if (!container) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const rect = container.getBoundingClientRect();
    const size = Math.max(240, Math.min(Math.floor(rect.width), 560));

    state.canvasSize = size;
    canvas.width = Math.floor(size * dpr);
    canvas.height = Math.floor(size * dpr);
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  // --- Kinetic Radar Render Loop ---
  function renderLoop() {
    drawRadar();
    updateParticles();
    state.sweepAngle = (state.sweepAngle + 0.02) % (Math.PI * 2);
    requestAnimationFrame(renderLoop);
  }

  function drawRadar() {
    const light = isLightMode();
    const width = state.canvasSize || 540;
    const height = width;
    const cx = width / 2;
    const cy = height / 2;
    const maxRadius = width * 0.45;

    ctx.clearRect(0, 0, width, height);

    // 1. Concentric Range Rings
    const rings = [0.2, 0.4, 0.6, 0.8, 1.0];
    rings.forEach((ratio, idx) => {
      const r = maxRadius * ratio;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      if (idx === rings.length - 1) {
        ctx.strokeStyle = light ? 'rgba(154, 114, 9, 0.45)' : 'rgba(212, 175, 55, 0.38)';
        ctx.lineWidth = 1.5;
      } else {
        ctx.strokeStyle = light ? 'rgba(28, 25, 23, 0.11)' : 'rgba(255, 255, 255, 0.08)';
        ctx.lineWidth = 1;
      }
      ctx.stroke();

      ctx.fillStyle = light ? 'rgba(87, 83, 78, 0.65)' : 'rgba(255, 255, 255, 0.3)';
      ctx.font = '9px ui-monospace, SFMono-Regular, monospace';
      ctx.textAlign = 'left';
      ctx.fillText(`${Math.round(ratio * 100)}%`, cx + 4, cy - r + 11);
    });

    // 2. Crosshair Grid Lines
    ctx.beginPath();
    ctx.moveTo(cx - maxRadius, cy);
    ctx.lineTo(cx + maxRadius, cy);
    ctx.moveTo(cx, cy - maxRadius);
    ctx.lineTo(cx, cy + maxRadius);
    ctx.strokeStyle = light ? 'rgba(28, 25, 23, 0.1)' : 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 5]);
    ctx.stroke();
    ctx.setLineDash([]);

    // 3. Sweeping Radar Beam
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, maxRadius, state.sweepAngle - 0.35, state.sweepAngle);
    ctx.closePath();
    const beamGrad = ctx.createRadialGradient(cx, cy, 10, cx, cy, maxRadius);
    beamGrad.addColorStop(0, light ? 'rgba(154, 114, 9, 0.24)' : 'rgba(212, 175, 55, 0.3)');
    beamGrad.addColorStop(1, light ? 'rgba(154, 114, 9, 0.0)' : 'rgba(212, 175, 55, 0.0)');
    ctx.fillStyle = beamGrad;
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(state.sweepAngle) * maxRadius, cy + Math.sin(state.sweepAngle) * maxRadius);
    ctx.strokeStyle = light ? 'rgba(154, 114, 9, 0.65)' : 'rgba(212, 175, 55, 0.65)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.restore();

    // 4. Center AI Agent Core
    drawAgentCore(cx, cy, light);

    // 5. Orbital Domain Nodes
    const domainList = Array.from(state.domains.values());
    const total = domainList.length;

    domainList.forEach((d, idx) => {
      const catCfg = getCategoryTheme(d.category);
      const angle = (idx / Math.max(total, 1)) * Math.PI * 2 - Math.PI / 2;
      const orbitR = Math.min((catCfg.orbit / 340) * maxRadius, maxRadius - 18);
      const nx = cx + Math.cos(angle) * orbitR;
      const ny = cy + Math.sin(angle) * orbitR;

      d.x = nx;
      d.y = ny;
      d.radius = 7 + Math.min(Math.log2((d.request_count || 1) + 1) * 2, 10);

      ctx.beginPath();
      ctx.arc(nx, ny, d.radius * 1.75, 0, Math.PI * 2);
      ctx.fillStyle = catCfg.glow;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(nx, ny, d.radius, 0, Math.PI * 2);
      ctx.fillStyle = d.quarantined_count > 0 ? (light ? '#BE123C' : '#EF4444') : catCfg.color;
      ctx.fill();
      ctx.strokeStyle = light ? '#FAF7F0' : '#FFFFFF';
      ctx.lineWidth = d === state.hoveredNode ? 2.5 : 1.2;
      ctx.stroke();

      ctx.fillStyle = d === state.hoveredNode
        ? (light ? '#1C1917' : '#FFFFFF')
        : (light ? 'rgba(28, 25, 23, 0.82)' : 'rgba(241, 245, 249, 0.78)');
      ctx.font = `${d === state.hoveredNode ? 'bold 11px' : '10px'} system-ui, sans-serif`;
      ctx.textAlign = 'center';
      const shortName = d.domain.length > 18 ? d.domain.substring(0, 16) + '..' : d.domain;
      ctx.fillText(shortName, nx, ny + d.radius + 13);
    });

    // 6. Kinetic Particles
    state.particles.forEach((p) => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.fill();
    });

    // 7. Hover Tooltip
    if (state.hoveredNode) {
      drawNodeTooltip(state.hoveredNode, light);
    }
  }

  function drawAgentCore(cx, cy, light) {
    const pulse = Math.sin(Date.now() / 320) * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, 26 + pulse, 0, Math.PI * 2);
    ctx.fillStyle = light ? 'rgba(154, 114, 9, 0.14)' : 'rgba(212, 175, 55, 0.16)';
    ctx.fill();

    ctx.beginPath();
    ctx.arc(cx, cy, 20, 0, Math.PI * 2);
    const grad = ctx.createRadialGradient(cx, cy, 2, cx, cy, 20);
    if (light) {
      grad.addColorStop(0, '#D4AF37');
      grad.addColorStop(1, '#9A7209');
    } else {
      grad.addColorStop(0, '#FFF2B2');
      grad.addColorStop(1, '#D4AF37');
    }
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.strokeStyle = light ? '#FAF7F0' : '#FFFFFF';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    ctx.fillStyle = light ? '#FFFFFF' : '#08080B';
    ctx.font = 'bold 9px ui-monospace, SFMono-Regular, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('AGENT', cx, cy - 3);
    ctx.font = '7px ui-monospace, SFMono-Regular, monospace';
    ctx.fillText('CORE', cx, cy + 6);
    ctx.textBaseline = 'alphabetic';
  }

  function drawNodeTooltip(node, light) {
    const padding = 8;
    const catCfg = getCategoryTheme(node.category);
    const lines = [
      node.domain,
      `Category: ${catCfg.label}`,
      `Requests: ${node.request_count || 0} | Endpoints: ${node.unique_endpoints || 1}`,
      `Throughput: ${formatBytes((node.total_bytes_sent || 0) + (node.total_bytes_recv || 0))}`,
      node.quarantined_count > 0 ? `Quarantined: ${node.quarantined_count}` : null,
    ].filter(Boolean);

    ctx.font = '11px system-ui, sans-serif';
    const maxWidth = Math.max(...lines.map((l) => ctx.measureText(l).width)) + padding * 2;
    const boxHeight = lines.length * 16 + padding * 2;

    let bx = node.x + 12;
    let by = node.y - boxHeight / 2;
    const width = state.canvasSize || 540;
    if (bx + maxWidth > width) bx = node.x - maxWidth - 12;
    if (by < 10) by = 10;

    ctx.save();
    ctx.fillStyle = light ? 'rgba(255, 255, 255, 0.96)' : 'rgba(12, 12, 18, 0.94)';
    ctx.strokeStyle = light ? 'rgba(154, 114, 9, 0.5)' : 'rgba(212, 175, 55, 0.55)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(bx, by, maxWidth, boxHeight, 6);
    } else {
      ctx.rect(bx, by, maxWidth, boxHeight);
    }
    ctx.fill();
    ctx.stroke();

    lines.forEach((line, i) => {
      if (i === 0) {
        ctx.fillStyle = light ? '#9A7209' : '#D4AF37';
      } else if (line.includes('Quarantined')) {
        ctx.fillStyle = light ? '#BE123C' : '#EF4444';
      } else {
        ctx.fillStyle = light ? '#1C1917' : '#E2E8F0';
      }
      ctx.font = i === 0 ? 'bold 11px system-ui, sans-serif' : '10px system-ui, sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(line, bx + padding, by + padding + (i + 1) * 14 - 2);
    });
    ctx.restore();
  }

  function spawnPacketParticle(targetDomain) {
    const cx = (state.canvasSize || 540) / 2;
    const cy = cx;
    const node = state.domains.get(targetDomain);
    if (!node || !node.x) return;

    const catCfg = getCategoryTheme(node.category);
    state.particles.push({
      x: cx,
      y: cy,
      tx: node.x,
      ty: node.y,
      progress: 0,
      speed: 0.025 + Math.random() * 0.015,
      size: 2.5 + Math.random() * 1.5,
      color: catCfg.color,
    });
  }

  function updateParticles() {
    for (let i = state.particles.length - 1; i >= 0; i--) {
      const p = state.particles[i];
      p.progress += p.speed;
      p.x += (p.tx - p.x) * p.speed * 2.5;
      p.y += (p.ty - p.y) * p.speed * 2.5;
      if (p.progress >= 1.0 || Math.hypot(p.tx - p.x, p.ty - p.y) < 6) {
        state.particles.splice(i, 1);
      }
    }
  }

  function onCanvasMouseMove(e) {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    let found = null;
    for (const d of state.domains.values()) {
      if (d.x && d.y && Math.hypot(mx - d.x, my - d.y) <= d.radius + 5) {
        found = d;
        break;
      }
    }
    state.hoveredNode = found;
    canvas.style.cursor = found ? 'pointer' : 'default';
  }

  function onCanvasClick() {
    if (state.hoveredNode) {
      filterByDomain(state.hoveredNode.domain);
    }
  }

  function filterByDomain(domain) {
    state.selectedDomain = state.selectedDomain === domain ? null : domain;
    const searchInput = document.getElementById('tableSearchInput');
    if (searchInput) searchInput.value = state.selectedDomain || '';
    state.searchQuery = state.selectedDomain || '';
    renderDomainList();
    renderTrafficTable();
    showToast(
      state.selectedDomain ? `Filtering events by domain: ${state.selectedDomain}` : 'Cleared domain filter',
      'info'
    );
  }

  // --- API Sync & SSE Feed ---
  function renderStats() {
    const data = state.stats;
    if (statsReqs) statsReqs.textContent = (data.total_requests || 0).toLocaleString();
    if (statsDomains) statsDomains.textContent = (data.total_domains || 0).toLocaleString();
    if (statsData) statsData.textContent = formatBytes((data.total_bytes_sent || 0) + (data.total_bytes_recv || 0));
    if (statsLatency) statsLatency.textContent = `${Math.round(data.avg_latency_ms || 0)}ms`;
    if (statsQuarantine) statsQuarantine.textContent = (data.total_quarantined || 0).toLocaleString();

    const policySelect = document.getElementById('policyModeSelect');
    if (policySelect && data.quarantine_mode) {
      policySelect.value = data.quarantine_mode;
    }
  }

  async function fetchStats() {
    try {
      const res = await fetch('/api/stats', { cache: 'no-store' });
      if (!res.ok) return;
      const data = await res.json();
      state.stats = data;
      if (data.proxy_port) {
        state.proxyPort = data.proxy_port;
        updateProxyLabels(data.proxy_port);
      }
      renderStats();
    } catch (_err) {}
  }

  async function fetchDomains() {
    try {
      const res = await fetch('/api/domains', { cache: 'no-store' });
      if (!res.ok) return;
      const data = await res.json();
      const seen = new Set();
      (data.domains || []).forEach((d) => {
        seen.add(d.domain);
        const existing = state.domains.get(d.domain);
        state.domains.set(d.domain, { ...existing, ...d });
      });
      // Remove stale server domains if logs were cleared
      for (const key of Array.from(state.domains.keys())) {
        if (!seen.has(key) && !String(key).startsWith('demo:')) {
          state.domains.delete(key);
        }
      }
      renderDomainList();
    } catch (_err) {}
  }

  async function fetchTraffic() {
    try {
      const res = await fetch('/api/traffic?limit=100', { cache: 'no-store' });
      if (!res.ok) return;
      const data = await res.json();
      state.events = data.events || [];
      renderTrafficTable();
    } catch (_err) {}
  }

  async function fetchRules() {
    try {
      const res = await fetch('/api/rules', { cache: 'no-store' });
      if (!res.ok) return;
      state.rules = await res.json();
      renderRulesLists();
    } catch (_err) {}
  }

  function connectSSE() {
    try {
      const sse = new EventSource('/api/stream');
      sse.onopen = () => {
        state.sseConnected = true;
        updateDaemonBadge(true, state.proxyPort);
      };
      sse.onmessage = (event) => {
        try {
          const item = JSON.parse(event.data);
          if (!state.events.some((e) => e.id === item.id)) {
            state.events.unshift(item);
            if (state.events.length > 200) state.events.pop();
          }
          if (!state.domains.has(item.domain)) {
            state.domains.set(item.domain, {
              domain: item.domain,
              category: item.category,
              request_count: 1,
              total_bytes_sent: item.bytes_sent || 0,
              total_bytes_recv: item.bytes_recv || 0,
              quarantined_count: item.quarantined ? 1 : 0,
            });
          } else {
            const d = state.domains.get(item.domain);
            d.request_count = (d.request_count || 0) + 1;
            d.total_bytes_sent = (d.total_bytes_sent || 0) + (item.bytes_sent || 0);
            d.total_bytes_recv = (d.total_bytes_recv || 0) + (item.bytes_recv || 0);
            if (item.quarantined) d.quarantined_count = (d.quarantined_count || 0) + 1;
          }
          spawnPacketParticle(item.domain);
          renderDomainList();
          renderTrafficTable();
          fetchStats();
        } catch (_e) {}
      };
      sse.onerror = () => {
        state.sseConnected = false;
      };
    } catch (_e) {}
  }

  // --- Safe DOM Builders (Zero innerHTML XSS Sinks) ---
  function renderDomainList() {
    if (!domainListEl) return;
    domainListEl.replaceChildren();

    const domains = Array.from(state.domains.values());
    if (domains.length === 0) {
      const empty = document.createElement('div');
      empty.style.padding = '16px';
      empty.style.textAlign = 'center';
      empty.style.fontSize = '12px';
      empty.style.color = 'var(--text-muted)';
      empty.textContent = 'No agent egress detected yet. Route an agent through the proxy or click Demo Event Probe.';
      domainListEl.appendChild(empty);
      return;
    }

    domains.forEach((d) => {
      const catCfg = getCategoryTheme(d.category);
      const isSelected = state.selectedDomain === d.domain;

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = isSelected ? 'domain-item selected' : 'domain-item';
      btn.dataset.domain = d.domain;

      const left = document.createElement('div');
      left.style.display = 'flex';
      left.style.alignItems = 'center';
      left.style.gap = '10px';
      left.style.minWidth = '0';

      const dot = document.createElement('span');
      dot.style.width = '10px';
      dot.style.height = '10px';
      dot.style.borderRadius = '50%';
      dot.style.flexShrink = '0';
      dot.style.backgroundColor = catCfg.color;

      const meta = document.createElement('div');
      meta.style.minWidth = '0';

      const nameEl = document.createElement('div');
      nameEl.style.fontSize = '12px';
      nameEl.style.fontWeight = '700';
      nameEl.style.fontFamily = 'var(--font-mono)';
      nameEl.style.whiteSpace = 'nowrap';
      nameEl.style.overflow = 'hidden';
      nameEl.style.textOverflow = 'ellipsis';
      nameEl.textContent = d.domain;

      const subEl = document.createElement('div');
      subEl.style.fontSize = '10px';
      subEl.style.color = 'var(--text-muted)';
      subEl.textContent = `${catCfg.label} • ${d.request_count || 0} reqs`;

      meta.appendChild(nameEl);
      meta.appendChild(subEl);
      left.appendChild(dot);
      left.appendChild(meta);

      const right = document.createElement('div');
      right.style.textAlign = 'right';
      right.style.flexShrink = '0';
      right.style.fontFamily = 'var(--font-mono)';
      right.style.fontSize = '11px';

      const bytesEl = document.createElement('div');
      bytesEl.style.color = 'var(--text-muted)';
      bytesEl.textContent = formatBytes((d.total_bytes_sent || 0) + (d.total_bytes_recv || 0));

      const statusEl = document.createElement('span');
      statusEl.style.fontSize = '10px';
      statusEl.style.fontWeight = '800';
      statusEl.style.color = d.quarantined_count > 0 ? 'var(--accent-crimson)' : 'var(--accent-emerald)';
      statusEl.textContent = d.quarantined_count > 0 ? 'BLOCKED' : 'PERMITTED';

      right.appendChild(bytesEl);
      right.appendChild(statusEl);

      btn.appendChild(left);
      btn.appendChild(right);
      domainListEl.appendChild(btn);
    });
  }

  function renderTrafficTable() {
    if (!trafficTableBody) return;
    trafficTableBody.replaceChildren();

    let filtered = state.events;
    if (state.filterCategory !== 'all') {
      filtered = filtered.filter((e) => e.category === state.filterCategory);
    }
    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      filtered = filtered.filter(
        (e) =>
          String(e.domain || '').toLowerCase().includes(q) ||
          String(e.url_path || '').toLowerCase().includes(q) ||
          String(e.agent_name || '').toLowerCase().includes(q)
      );
    }

    if (filtered.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.style.padding = '28px';
      td.style.textAlign = 'center';
      td.style.color = 'var(--text-muted)';
      td.style.fontFamily = 'var(--font-mono)';
      td.style.fontSize = '12px';
      td.textContent = `No matching egress events. Proxy listening on 127.0.0.1:${state.proxyPort}.`;
      tr.appendChild(td);
      trafficTableBody.appendChild(tr);
      return;
    }

    filtered.slice(0, 60).forEach((e) => {
      const catCfg = getCategoryTheme(e.category);
      const tr = document.createElement('tr');

      const tdTime = document.createElement('td');
      tdTime.style.fontFamily = 'var(--font-mono)';
      tdTime.style.fontSize = '11px';
      tdTime.style.color = 'var(--text-muted)';
      tdTime.textContent = new Date((e.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString();

      const tdAgent = document.createElement('td');
      const agentTag = document.createElement('span');
      agentTag.style.padding = '2px 7px';
      agentTag.style.borderRadius = '5px';
      agentTag.style.fontSize = '11px';
      agentTag.style.fontFamily = 'var(--font-mono)';
      agentTag.style.background = 'var(--bg-surface-elevated)';
      agentTag.style.border = '1px solid var(--border-subtle)';
      agentTag.textContent = String(e.agent_name || 'agent');
      tdAgent.appendChild(agentTag);

      const tdDomain = document.createElement('td');
      const domWrap = document.createElement('div');
      domWrap.style.display = 'flex';
      domWrap.style.alignItems = 'center';
      domWrap.style.gap = '8px';
      const dot = document.createElement('span');
      dot.style.width = '8px';
      dot.style.height = '8px';
      dot.style.borderRadius = '50%';
      dot.style.flexShrink = '0';
      dot.style.backgroundColor = catCfg.color;
      const domText = document.createElement('span');
      domText.style.fontFamily = 'var(--font-mono)';
      domText.style.fontWeight = '700';
      domText.textContent = String(e.domain || 'unknown');
      domWrap.appendChild(dot);
      domWrap.appendChild(domText);
      tdDomain.appendChild(domWrap);

      const tdProto = document.createElement('td');
      const pill = document.createElement('span');
      pill.className = e.quarantined ? 'status-pill blocked' : (Number(e.status_code) === 200 ? 'status-pill ok' : 'status-pill warn');
      const labelPrefix = e.quarantined ? 'QUARANTINE' : String(e.method || 'GET');
      pill.textContent = `${labelPrefix} ${e.status_code || ''}`.trim();
      tdProto.appendChild(pill);

      const tdBytes = document.createElement('td');
      tdBytes.style.fontFamily = 'var(--font-mono)';
      tdBytes.style.color = 'var(--text-muted)';
      tdBytes.textContent = formatBytes((e.bytes_sent || 0) + (e.bytes_recv || 0));

      const tdLatency = document.createElement('td');
      tdLatency.style.fontFamily = 'var(--font-mono)';
      tdLatency.style.color = 'var(--text-muted)';
      tdLatency.textContent = `${Math.round(Number(e.latency_ms || 0))}ms`;

      const tdAction = document.createElement('td');
      tdAction.style.textAlign = 'right';
      const btnInspect = document.createElement('button');
      btnInspect.type = 'button';
      btnInspect.className = 'btn-secondary btn-inspect-row';
      btnInspect.dataset.eventId = String(e.id || '');
      btnInspect.style.padding = '5px 10px';
      btnInspect.style.fontSize = '11px';
      btnInspect.textContent = 'Inspect';
      tdAction.appendChild(btnInspect);

      tr.appendChild(tdTime);
      tr.appendChild(tdAgent);
      tr.appendChild(tdDomain);
      tr.appendChild(tdProto);
      tr.appendChild(tdBytes);
      tr.appendChild(tdLatency);
      tr.appendChild(tdAction);
      trafficTableBody.appendChild(tr);
    });
  }

  function renderRulesLists() {
    const allowEl = document.getElementById('allowedDomainsList');
    const blockEl = document.getElementById('blockedDomainsList');
    const allowCount = document.getElementById('allowCount');
    const blockCount = document.getElementById('blockCount');
    const protectedBadge = document.getElementById('protectedPortsBadge');

    const allowed = state.rules.allowed_domains || [];
    const blocked = state.rules.blocked_domains || [];
    const protectedPorts = state.rules.protected_ports || [8095, 8195];

    if (allowCount) allowCount.textContent = String(allowed.length);
    if (blockCount) blockCount.textContent = String(blocked.length);
    if (protectedBadge) {
      protectedBadge.replaceChildren();
      protectedBadge.appendChild(document.createTextNode('Protected Control Ports: '));
      const strong = document.createElement('strong');
      strong.style.color = 'var(--accent-crimson)';
      strong.textContent = protectedPorts.join(', ');
      protectedBadge.appendChild(strong);
    }

    function fillList(container, items, listKind, emptyText) {
      if (!container) return;
      container.replaceChildren();
      if (items.length === 0) {
        const span = document.createElement('span');
        span.style.fontSize = '12px';
        span.style.color = 'var(--text-dim)';
        span.textContent = emptyText;
        container.appendChild(span);
        return;
      }
      items.forEach((dom) => {
        const chip = document.createElement('span');
        chip.className = 'rule-chip';
        const txt = document.createElement('span');
        txt.textContent = dom;
        const rmBtn = document.createElement('button');
        rmBtn.type = 'button';
        rmBtn.className = 'btn-remove-rule';
        rmBtn.dataset.domain = dom;
        rmBtn.dataset.list = listKind;
        rmBtn.setAttribute('aria-label', `Remove ${dom} from ${listKind} list`);
        rmBtn.textContent = '✕';
        chip.appendChild(txt);
        chip.appendChild(rmBtn);
        container.appendChild(chip);
      });
    }

    fillList(allowEl, allowed, 'allow', 'No custom allowlist rules configured.');
    fillList(blockEl, blocked, 'block', 'No custom blocklist rules configured.');
  }

  // --- Inspect Modal (Safe DOM construction) ---
  function inspectEvent(eventId) {
    const ev = state.events.find((e) => String(e.id) === String(eventId));
    if (!ev) return;

    const modal = document.getElementById('inspectModal');
    const content = document.getElementById('inspectModalContent');
    if (!modal || !content) return;

    const catCfg = getCategoryTheme(ev.category);
    content.replaceChildren();

    const wrap = document.createElement('div');
    wrap.style.display = 'flex';
    wrap.style.flexDirection = 'column';
    wrap.style.gap = '14px';
    wrap.style.fontSize = '12px';

    const grid = document.createElement('div');
    grid.style.display = 'grid';
    grid.style.gridTemplateColumns = 'repeat(2, 1fr)';
    grid.style.gap = '10px';
    grid.style.padding = '12px';
    grid.style.borderRadius = '10px';
    grid.style.background = 'var(--bg-code)';
    grid.style.border = '1px solid var(--border-subtle)';
    grid.style.fontFamily = 'var(--font-mono)';
    grid.style.fontSize = '11px';

    const fields = [
      ['Domain', String(ev.domain || ''), 'var(--gold-primary)'],
      ['Category', catCfg.label, catCfg.color],
      ['Protocol', String(ev.protocol || 'HTTPS'), null],
      ['Method', String(ev.method || 'GET'), null],
      ['Remote IP', `${ev.remote_ip || '0.0.0.0'}:${ev.remote_port || 443}`, null],
      ['Status', ev.quarantined ? 'QUARANTINED' : String(ev.status_code || 200), ev.quarantined ? 'var(--accent-crimson)' : 'var(--accent-emerald)'],
      ['Bytes Sent', formatBytes(ev.bytes_sent || 0), null],
      ['Bytes Recv', formatBytes(ev.bytes_recv || 0), null],
      ['Endpoint', String(ev.url_path || '/'), null, true],
    ];

    fields.forEach(([label, val, color, span2]) => {
      const cell = document.createElement('div');
      if (span2) cell.style.gridColumn = 'span 2';
      const lbl = document.createElement('span');
      lbl.style.color = 'var(--text-muted)';
      lbl.textContent = `${label}: `;
      const v = document.createElement('strong');
      if (color) v.style.color = color;
      v.textContent = val;
      cell.appendChild(lbl);
      cell.appendChild(v);
      grid.appendChild(cell);
    });
    wrap.appendChild(grid);

    function addPreBlock(title, text) {
      const box = document.createElement('div');
      const h = document.createElement('div');
      h.style.fontWeight = '700';
      h.style.color = 'var(--text-muted)';
      h.style.marginBottom = '4px';
      h.textContent = title;
      const pre = document.createElement('pre');
      pre.style.padding = '10px';
      pre.style.borderRadius = '8px';
      pre.style.background = 'var(--bg-code)';
      pre.style.border = '1px solid var(--border-subtle)';
      pre.style.fontFamily = 'var(--font-mono)';
      pre.style.fontSize = '11px';
      pre.style.whiteSpace = 'pre-wrap';
      pre.style.overflowX = 'auto';
      pre.textContent = text;
      box.appendChild(h);
      box.appendChild(pre);
      wrap.appendChild(box);
    }

    addPreBlock('Request Payload Sample / Handshake:', String(ev.request_sample || '(TLS Handshake tunnel - payload encrypted)'));
    addPreBlock('Response Sample / Server Ack:', String(ev.response_sample || '(Binary response stream)'));

    if (ev.notes) {
      const note = document.createElement('div');
      note.style.padding = '10px';
      note.style.borderRadius = '8px';
      note.style.background = 'var(--gold-glow)';
      note.style.border = '1px solid var(--border-gold)';
      note.style.fontSize = '11px';
      note.textContent = `Sentinel Notes: ${ev.notes}`;
      wrap.appendChild(note);
    }

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.flexWrap = 'wrap';
    actions.style.justifyContent = 'space-between';
    actions.style.gap = '8px';
    actions.style.paddingTop = '10px';
    actions.style.borderTop = '1px solid var(--border-subtle)';

    const btnBlock = document.createElement('button');
    btnBlock.type = 'button';
    btnBlock.className = 'btn-danger';
    btnBlock.textContent = `🚫 Add ${ev.domain} to Blocklist`;
    btnBlock.addEventListener('click', () => addPolicyRule('block', ev.domain, true));

    const btnClose = document.createElement('button');
    btnClose.type = 'button';
    btnClose.className = 'btn-secondary';
    btnClose.textContent = 'Close';
    btnClose.addEventListener('click', () => modal.classList.add('hidden'));

    actions.appendChild(btnBlock);
    actions.appendChild(btnClose);
    wrap.appendChild(actions);

    content.appendChild(wrap);
    modal.classList.remove('hidden');
  }

  // --- Policy & Rule Mutations ---
  async function changeQuarantinePolicy(mode) {
    if (!state.daemonOnline) {
      state.stats.quarantine_mode = mode;
      state.rules.quarantine_mode = mode;
      showToast(`Preview policy set to ${mode.toUpperCase()} (start local daemon for live enforcement)`, 'info');
      return;
    }
    try {
      const res = await fetch('/api/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      if (res.ok) {
        showToast(`Quarantine policy switched to: ${mode.toUpperCase()}`, 'success');
        fetchStats();
        fetchRules();
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(err.error || 'Failed to switch policy', 'error');
      }
    } catch (err) {
      showToast('Failed to update policy: ' + err.message, 'error');
    }
  }

  async function addPolicyRule(listKind, domain, closeModalAfter) {
    const clean = String(domain || '').trim();
    if (!clean) {
      showToast('Enter a domain or wildcard pattern first.', 'error');
      return;
    }
    if (!state.daemonOnline) {
      const target = listKind === 'allow' ? state.rules.allowed_domains : state.rules.blocked_domains;
      if (!target.includes(clean.toLowerCase())) target.push(clean.toLowerCase());
      renderRulesLists();
      showToast(`Added '${clean}' to ${listKind}list (offline preview)`, 'info');
      return;
    }
    try {
      const endpoint = listKind === 'allow' ? '/api/rules/allow' : '/api/rules/block';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: clean }),
      });
      const payload = await res.json().catch(() => ({}));
      if (res.ok) {
        if (payload.rules) state.rules = payload.rules;
        else await fetchRules();
        renderRulesLists();
        showToast(`Domain '${clean}' added to Sentinel ${listKind}list`, 'success');
        if (closeModalAfter) {
          const modal = document.getElementById('inspectModal');
          if (modal) modal.classList.add('hidden');
        }
      } else {
        showToast(payload.error || 'Could not save rule', 'error');
      }
    } catch (err) {
      showToast('Failed to update rule: ' + err.message, 'error');
    }
  }

  async function removePolicyRule(listKind, domain) {
    const clean = String(domain || '').trim();
    if (!clean) return;
    if (!state.daemonOnline) {
      if (listKind === 'allow') {
        state.rules.allowed_domains = state.rules.allowed_domains.filter((d) => d !== clean);
      } else {
        state.rules.blocked_domains = state.rules.blocked_domains.filter((d) => d !== clean);
      }
      renderRulesLists();
      return;
    }
    try {
      const endpoint = listKind === 'allow' ? '/api/rules/allow' : '/api/rules/block';
      const res = await fetch(`${endpoint}?domain=${encodeURIComponent(clean)}`, { method: 'DELETE' });
      const payload = await res.json().catch(() => ({}));
      if (res.ok) {
        if (payload.rules) state.rules = payload.rules;
        else await fetchRules();
        renderRulesLists();
        showToast(`Removed '${clean}' from ${listKind}list`, 'info');
      } else {
        showToast(payload.error || 'Could not remove rule', 'error');
      }
    } catch (err) {
      showToast('Failed to remove rule: ' + err.message, 'error');
    }
  }

  async function clearLogs() {
    if (state.daemonOnline) {
      try {
        await fetch('/api/clear', { method: 'POST' });
      } catch (_err) {
        showToast('Error clearing daemon logs', 'error');
        return;
      }
    }
    state.events = [];
    state.domains.clear();
    renderTrafficTable();
    renderDomainList();
    if (state.daemonOnline) fetchStats();
    else setOfflinePreviewState();
    showToast('Egress traffic logs cleared.', 'info');
  }

  function handleExportHAR() {
    if (state.daemonOnline) {
      window.location.href = '/api/export';
      return;
    }
    const har = {
      log: {
        version: '1.2',
        creator: { name: 'Agent Egress Sentinel', version: VERSION },
        pages: [{ startedDateTime: new Date().toISOString(), id: 'page_1', title: 'AI Agent Egress Session', pageTimings: {} }],
        entries: state.events.map((ev) => ({
          startedDateTime: new Date((ev.timestamp || Date.now() / 1000) * 1000).toISOString(),
          time: Math.round(ev.latency_ms || 45),
          request: {
            method: ev.method || 'POST',
            url: `https://${ev.domain}${ev.url_path || '/v1'}`,
            httpVersion: 'HTTP/1.1',
            headers: [{ name: 'Host', value: ev.domain }],
            queryString: [],
            headersSize: -1,
            bodySize: ev.bytes_sent || 0,
          },
          response: {
            status: ev.status_code || 200,
            statusText: ev.quarantined ? 'Quarantined' : 'OK',
            httpVersion: 'HTTP/1.1',
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            content: { size: ev.bytes_recv || 0, mimeType: 'application/json', text: ev.response_sample || '{}' },
            headersSize: -1,
            bodySize: ev.bytes_recv || 0,
          },
          cache: {},
          timings: { send: 5, wait: Math.max(1, Math.round(ev.latency_ms || 45) - 10), receive: 5 },
        })),
      },
    };
    downloadJsonBlob(har, `agent-egress-audit-${Date.now()}.har`);
    showToast('HAR 1.2 audit archive downloaded.', 'success');
  }

  function handleExportOpenAPI() {
    if (state.daemonOnline) {
      window.location.href = '/api/export/openapi';
      return;
    }
    const paths = {};
    state.events.forEach((ev) => {
      const p = ev.url_path || '/api/v1/endpoint';
      if (!paths[p]) paths[p] = {};
      paths[p][(ev.method || 'post').toLowerCase()] = {
        summary: `Egress to ${ev.domain}`,
        tags: [ev.category || 'general'],
        responses: {
          [String(ev.status_code || 200)]: {
            description: ev.quarantined ? 'Blocked by Egress Sentinel' : 'Success',
            content: { 'application/json': { schema: { type: 'object' } } },
          },
        },
      };
    });
    const openapi = {
      openapi: '3.0.3',
      info: {
        title: 'Agent Egress Sentinel — Synthesized API Blueprint',
        version: VERSION,
        contact: { name: 'Neal Frazier Tech (@1nc0gn30) • NullAI Platform', url: 'https://nullai.tech' },
      },
      servers: Array.from(state.domains.keys()).map((d) => ({ url: `https://${d}` })),
      paths,
    };
    downloadJsonBlob(openapi, `agent-egress-openapi-${Date.now()}.json`);
    showToast('OpenAPI 3.0 specification downloaded.', 'success');
  }

  function downloadJsonBlob(obj, filename) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Client-only Demo Event Probe (never pollutes production SQLite history!)
  function runDemoEventProbe() {
    const sampleTargets = [
      { domain: 'api.openai.com', category: 'llm_api', path: '/v1/chat/completions', method: 'POST', sent: 3400, recv: 12400 },
      { domain: 'api.anthropic.com', category: 'llm_api', path: '/v1/messages', method: 'POST', sent: 4100, recv: 16800 },
      { domain: 'huggingface.co', category: 'model_hub', path: '/api/models/meta-llama', method: 'GET', sent: 820, recv: 45000 },
      { domain: 'api.segment.io', category: 'telemetry_tracker', path: '/v1/track', method: 'POST', sent: 1200, recv: 0 },
      { domain: '169.254.169.254', category: 'private_network', path: '/latest/meta-data/', method: 'GET', sent: 280, recv: 0 },
      { domain: 'localhost', category: 'local_service', path: '/v1/models', method: 'GET', sent: 400, recv: 1800 },
    ];

    let delay = 0;
    sampleTargets.forEach((target, idx) => {
      setTimeout(() => {
        const mode = state.stats.quarantine_mode || 'allow_all';
        const isPrivate = target.category === 'private_network';
        const isQuarantined =
          isPrivate ||
          (mode === 'zero_egress' && target.category !== 'local_service') ||
          (mode === 'block_telemetry' && target.category === 'telemetry_tracker') ||
          (mode === 'allowlist_only' && !(state.rules.allowed_domains || []).includes(target.domain));

        const demoEv = {
          id: `demo-${Date.now()}-${idx}`,
          timestamp: Date.now() / 1000,
          agent_name: 'demo_probe',
          domain: target.domain,
          remote_ip: isPrivate ? '169.254.169.254' : '198.51.100.' + (10 + idx),
          remote_port: isPrivate ? 80 : 443,
          protocol: isPrivate ? 'HTTP' : 'HTTPS',
          method: target.method,
          url_path: target.path,
          status_code: isQuarantined ? 403 : 200,
          bytes_sent: target.sent,
          bytes_recv: isQuarantined ? 0 : target.recv,
          latency_ms: Math.round(32 + Math.random() * 65),
          category: target.category,
          quarantined: isQuarantined,
          request_sample: JSON.stringify({ demo_probe: true, target: target.domain, path: target.path }),
          response_sample: isQuarantined
            ? '{"error":"Blocked by Sentinel policy / SSRF guard (client-only demo probe)"}'
            : '{"status":"ok","demo_probe":true}',
          notes: 'Client-only Demo Event Probe (not written to SQLite audit store)',
        };

        state.events.unshift(demoEv);
        if (!state.domains.has(target.domain)) {
          state.domains.set(target.domain, {
            domain: target.domain,
            category: target.category,
            request_count: 1,
            total_bytes_sent: target.sent,
            total_bytes_recv: isQuarantined ? 0 : target.recv,
            quarantined_count: isQuarantined ? 1 : 0,
          });
        } else {
          const d = state.domains.get(target.domain);
          d.request_count = (d.request_count || 0) + 1;
          d.total_bytes_sent = (d.total_bytes_sent || 0) + target.sent;
          d.total_bytes_recv = (d.total_bytes_recv || 0) + (isQuarantined ? 0 : target.recv);
          if (isQuarantined) d.quarantined_count = (d.quarantined_count || 0) + 1;
        }

        if (!state.daemonOnline) {
          state.stats.total_requests += 1;
          state.stats.total_domains = state.domains.size;
          state.stats.total_bytes_sent += target.sent;
          state.stats.total_bytes_recv += isQuarantined ? 0 : target.recv;
          state.stats.avg_latency_ms = demoEv.latency_ms;
          if (isQuarantined) state.stats.total_quarantined += 1;
          renderStats();
        }

        spawnPacketParticle(target.domain);
        renderTrafficTable();
        renderDomainList();
      }, delay);
      delay += 260;
    });

    showToast('Running client-only Demo Event Probe (SQLite history untouched).', 'info');
  }

  function copySolanaAddress(e) {
    if (e) e.preventDefault();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(SOLANA_TIP_ADDRESS).catch(() => {});
    }
    showToast(`Solana tip address copied: ${SOLANA_TIP_ADDRESS}`, 'success');
  }

  // --- Event Listeners (Delegated, Zero Inline JS) ---
  function setupEventListeners() {
    const themeBtn = document.getElementById('themeToggleBtn');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

    const solBar = document.getElementById('btnSolanaTipBar');
    if (solBar) solBar.addEventListener('click', copySolanaAddress);

    const solFoot = document.getElementById('footerSolanaLink');
    if (solFoot) solFoot.addEventListener('click', copySolanaAddress);

    const simBtn = document.getElementById('btnSimulateLive');
    if (simBtn) simBtn.addEventListener('click', runDemoEventProbe);

    const clearBtn = document.getElementById('btnClearLogs');
    if (clearBtn) clearBtn.addEventListener('click', clearLogs);

    const exportHarBtn = document.getElementById('btnExportHarLive');
    if (exportHarBtn) exportHarBtn.addEventListener('click', handleExportHAR);

    const exportOpenApiBtn = document.getElementById('btnExportOpenApiLive');
    if (exportOpenApiBtn) exportOpenApiBtn.addEventListener('click', handleExportOpenAPI);

    const policySelect = document.getElementById('policyModeSelect');
    if (policySelect) {
      policySelect.addEventListener('change', (e) => changeQuarantinePolicy(e.target.value));
    }

    const closeModalBtn = document.getElementById('btnCloseInspectModal');
    const inspectModal = document.getElementById('inspectModal');
    if (closeModalBtn && inspectModal) {
      closeModalBtn.addEventListener('click', () => inspectModal.classList.add('hidden'));
      inspectModal.addEventListener('click', (e) => {
        if (e.target === inspectModal) inspectModal.classList.add('hidden');
      });
    }

    // Delegated domain list clicks
    if (domainListEl) {
      domainListEl.addEventListener('click', (e) => {
        const item = e.target.closest('.domain-item');
        if (item && item.dataset.domain) {
          filterByDomain(item.dataset.domain);
        }
      });
    }

    // Delegated traffic table inspect clicks
    if (trafficTableBody) {
      trafficTableBody.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-inspect-row');
        if (btn && btn.dataset.eventId) {
          inspectEvent(btn.dataset.eventId);
        }
      });
    }

    // Category tabs
    const filterTabs = document.querySelectorAll('.category-tab');
    filterTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        filterTabs.forEach((t) => t.classList.remove('active'));
        tab.classList.add('active');
        state.filterCategory = tab.dataset.category || 'all';
        renderTrafficTable();
      });
    });

    // Search filter
    const searchInput = document.getElementById('tableSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        state.searchQuery = e.target.value.trim();
        renderTrafficTable();
      });
    }

    // Rule editor actions
    const ruleInput = document.getElementById('ruleDomainInput');
    const btnAllow = document.getElementById('btnAddAllowRule');
    const btnBlock = document.getElementById('btnAddBlockRule');
    const ruleForm = document.getElementById('ruleEditorForm');
    if (ruleForm) {
      ruleForm.addEventListener('submit', (e) => {
        e.preventDefault();
        if (ruleInput && ruleInput.value.trim()) {
          addPolicyRule('block', ruleInput.value.trim(), false);
          ruleInput.value = '';
        }
      });
    }
    if (btnAllow) {
      btnAllow.addEventListener('click', () => {
        if (ruleInput && ruleInput.value.trim()) {
          addPolicyRule('allow', ruleInput.value.trim(), false);
          ruleInput.value = '';
        }
      });
    }
    if (btnBlock) {
      btnBlock.addEventListener('click', () => {
        if (ruleInput && ruleInput.value.trim()) {
          addPolicyRule('block', ruleInput.value.trim(), false);
          ruleInput.value = '';
        }
      });
    }

    // Delegated rule removal clicks
    const policySection = document.getElementById('policyRulesSection');
    if (policySection) {
      policySection.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-remove-rule');
        if (btn && btn.dataset.domain && btn.dataset.list) {
          removePolicyRule(btn.dataset.list, btn.dataset.domain);
        }
      });
    }

    // Token-gated /api/run launcher
    const runForm = document.getElementById('runAgentForm');
    if (runForm) {
      runForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const cmdInput = document.getElementById('runCommandInput');
        const agentInput = document.getElementById('runAgentName');
        const tokenInput = document.getElementById('runTokenInput');
        const cmd = cmdInput ? cmdInput.value.trim() : '';
        const agent_name = agentInput ? agentInput.value.trim() : 'autonomous_agent';
        const token = tokenInput ? tokenInput.value.trim() : '';

        if (!cmd) {
          showToast('Enter a command to supervise.', 'error');
          return;
        }
        if (!state.daemonOnline) {
          showToast('Start local daemon first: agent-egress-sentinel serve', 'error');
          return;
        }

        try {
          const headers = { 'Content-Type': 'application/json' };
          if (token) headers['X-Sentinel-Token'] = token;
          const res = await fetch('/api/run', {
            method: 'POST',
            headers,
            body: JSON.stringify({ command: cmd, agent_name }),
          });
          const data = await res.json().catch(() => ({}));
          if (res.ok) {
            showToast(`Supervised process launched (${agent_name})`, 'success');
          } else {
            showToast(data.error || `Launch rejected (HTTP ${res.status})`, 'error');
          }
        } catch (err) {
          showToast('Failed to launch: ' + err.message, 'error');
        }
      });
    }
  }

  // --- Helpers ---
  function formatBytes(bytes) {
    const n = Number(bytes || 0);
    if (!n || n <= 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(n) / Math.log(k)));
    return `${parseFloat((n / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  }

  function debounce(fn, ms) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  function showToast(message, type) {
    const toast = document.createElement('div');
    toast.className = 'sentinel-toast';
    if (type === 'success') toast.style.borderColor = 'var(--accent-emerald)';
    if (type === 'error') toast.style.borderColor = 'var(--accent-crimson)';
    toast.textContent = String(message || '');
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    document.body.appendChild(toast);

    requestAnimationFrame(() => {
      toast.style.opacity = '1';
      toast.style.transform = 'translateY(0)';
    });
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(8px)';
      setTimeout(() => toast.remove(), 250);
    }, 3200);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
