/**
 * Agent Egress Sentinel — Kinetic Domain Radar & Telemetry Engine
 * Pure Vanilla Canvas & Reactive DOM Architecture. Zero external JS dependencies.
 * Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
 */

(function () {
  'use strict';

  // --- Category Color Palette ---
  const CATEGORY_THEME = {
    llm_api: { label: 'LLM API', color: '#38BDF8', glow: 'rgba(56, 189, 248, 0.4)', orbit: 110 },
    model_hub: { label: 'Model Hub', color: '#A855F7', glow: 'rgba(168, 85, 247, 0.4)', orbit: 165 },
    telemetry_tracker: { label: 'Telemetry', color: '#EF4444', glow: 'rgba(239, 68, 68, 0.4)', orbit: 220 },
    search_scraper: { label: 'Search/Scraper', color: '#10B981', glow: 'rgba(16, 185, 129, 0.4)', orbit: 270 },
    local_service: { label: 'Local Service', color: '#F59E0B', glow: 'rgba(245, 158, 11, 0.4)', orbit: 65 },
    external_web: { label: 'External Web', color: '#94A3B8', glow: 'rgba(148, 163, 184, 0.3)', orbit: 310 },
    unknown: { label: 'Unknown', color: '#64748B', glow: 'rgba(100, 116, 139, 0.3)', orbit: 330 },
  };

  // --- State ---
  const state = {
    domains: new Map(), // domain -> domain object
    events: [],
    selectedDomain: null,
    filterCategory: 'all',
    searchQuery: '',
    sweepAngle: 0,
    particles: [],
    hoveredNode: null,
    isPro: false,
    sseConnected: false,
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

  // --- DOM References ---
  let canvas, ctx;
  let statsReqs, statsDomains, statsData, statsLatency, statsQuarantine;
  let trafficTableBody, domainListEl, endpointModal, payloadModal;

  // --- Initialize Application ---
  function init() {
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

    checkLicense();
    setupCanvas();
    setupEventListeners();
    fetchStats();
    fetchDomains();
    fetchTraffic();
    connectSSE();

    // Start Kinetic Render Loop
    requestAnimationFrame(renderLoop);

    // Periodic Refresh fallback
    setInterval(fetchStats, 3000);
    setInterval(fetchDomains, 4000);
  }

  // --- License & Monetization ---
  function checkLicense() {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('licensed') === 'true' || urlParams.get('pro') === 'true') {
      localStorage.setItem('sentinel_pro_licensed', 'true');
    }

    state.isPro = localStorage.getItem('sentinel_pro_licensed') === 'true';
    updateProUI();
  }

  function updateProUI() {
    const proBadge = document.getElementById('proStatusBadge');
    const paywallBlur = document.querySelectorAll('.pro-paywall-blur');
    const paywallOverlay = document.querySelectorAll('.pro-paywall-overlay');

    if (state.isPro) {
      if (proBadge) {
        proBadge.textContent = '⭐ PRO ACTIVE';
        proBadge.className = 'px-3 py-1 text-xs font-bold rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-lg shadow-amber-500/10';
      }
      paywallBlur.forEach(el => el.classList.remove('filter', 'blur-sm', 'pointer-events-none', 'select-none'));
      paywallOverlay.forEach(el => el.classList.add('hidden'));
    } else {
      if (proBadge) {
        proBadge.textContent = 'COMMUNITY EDITION';
        proBadge.className = 'px-3 py-1 text-xs font-semibold rounded-full bg-zinc-800 text-zinc-400 border border-zinc-700';
      }
      paywallBlur.forEach(el => el.classList.add('filter', 'blur-sm', 'pointer-events-none', 'select-none'));
      paywallOverlay.forEach(el => el.classList.remove('hidden'));
    }
  }

  window.activateLicenseKey = function (promptUser = true) {
    if (promptUser) {
      const key = prompt('Enter your Sentinel Pro License Key or Stripe Receipt Email:');
      if (!key || !key.trim()) return;
    }
    localStorage.setItem('sentinel_pro_licensed', 'true');
    state.isPro = true;
    updateProUI();
    closePaywallModal();
    showToast('⭐ Sentinel Pro successfully activated! Full export and deep telemetry unlocked.', 'success');
  };

  window.openPaywallModal = function () {
    const modal = document.getElementById('paywallModal');
    if (modal) modal.classList.remove('hidden');
  };

  window.closePaywallModal = function () {
    const modal = document.getElementById('paywallModal');
    if (modal) modal.classList.add('hidden');
  };

  // --- Canvas Setup & DPI Scaling ---
  function setupCanvas() {
    const container = canvas.parentElement;
    const dpr = window.devicePixelRatio || 1;
    const rect = container.getBoundingClientRect();
    const size = Math.min(rect.width, 680);

    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    ctx.scale(dpr, dpr);

    canvas.addEventListener('mousemove', onCanvasMouseMove);
    canvas.addEventListener('mouseleave', () => { state.hoveredNode = null; });
    canvas.addEventListener('click', onCanvasClick);
    window.addEventListener('resize', debounce(setupCanvas, 150));
  }

  // --- Kinetic Radar Render Loop ---
  function renderLoop() {
    drawRadar();
    updateParticles();
    state.sweepAngle = (state.sweepAngle + 0.02) % (Math.PI * 2);
    requestAnimationFrame(renderLoop);
  }

  function drawRadar() {
    const width = parseFloat(canvas.style.width);
    const height = parseFloat(canvas.style.height);
    const cx = width / 2;
    const cy = height / 2;
    const maxRadius = width * 0.46;

    ctx.clearRect(0, 0, width, height);

    // 1. Concentric Range Rings
    const rings = [0.2, 0.4, 0.6, 0.8, 1.0];
    rings.forEach((ratio, idx) => {
      const r = maxRadius * ratio;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = idx === rings.length - 1 ? 'rgba(212, 175, 55, 0.35)' : 'rgba(255, 255, 255, 0.06)';
      ctx.lineWidth = idx === rings.length - 1 ? 1.5 : 1;
      ctx.stroke();

      // Ring Distance Ticks
      ctx.fillStyle = 'rgba(255, 255, 255, 0.25)';
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.fillText(`${Math.round(ratio * 100)}%`, cx + 4, cy - r + 11);
    });

    // 2. Crosshair Grid Lines
    ctx.beginPath();
    ctx.moveTo(cx - maxRadius, cy);
    ctx.lineTo(cx + maxRadius, cy);
    ctx.moveTo(cx, cy - maxRadius);
    ctx.lineTo(cx, cy + maxRadius);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 5]);
    ctx.stroke();
    ctx.setLineDash([]);

    // 3. Sweeping Radar Beam (Conic Gradient)
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, maxRadius, state.sweepAngle - 0.35, state.sweepAngle);
    ctx.closePath();
    const beamGrad = ctx.createRadialGradient(cx, cy, 10, cx, cy, maxRadius);
    beamGrad.addColorStop(0, 'rgba(212, 175, 55, 0.3)');
    beamGrad.addColorStop(1, 'rgba(212, 175, 55, 0.0)');
    ctx.fillStyle = beamGrad;
    ctx.fill();

    // Beam Leading Edge Line
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(state.sweepAngle) * maxRadius, cy + Math.sin(state.sweepAngle) * maxRadius);
    ctx.strokeStyle = 'rgba(212, 175, 55, 0.6)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.restore();

    // 4. Center AI Agent Core
    drawAgentCore(cx, cy);

    // 5. Orbital Domain Nodes
    const domainList = Array.from(state.domains.values());
    const total = domainList.length;

    domainList.forEach((d, idx) => {
      const catCfg = CATEGORY_THEME[d.category] || CATEGORY_THEME.unknown;
      const angle = (idx / Math.max(total, 1)) * Math.PI * 2 - Math.PI / 2;
      const orbitR = Math.min((catCfg.orbit / 340) * maxRadius, maxRadius - 15);
      const nx = cx + Math.cos(angle) * orbitR;
      const ny = cy + Math.sin(angle) * orbitR;

      d.x = nx;
      d.y = ny;
      d.radius = 7 + Math.min(Math.log2(d.request_count + 1) * 2, 10);

      // Node Halo / Glow
      ctx.beginPath();
      ctx.arc(nx, ny, d.radius * 1.8, 0, Math.PI * 2);
      ctx.fillStyle = catCfg.glow;
      ctx.fill();

      // Node Body
      ctx.beginPath();
      ctx.arc(nx, ny, d.radius, 0, Math.PI * 2);
      ctx.fillStyle = d.quarantined_count > 0 ? '#EF4444' : catCfg.color;
      ctx.fill();
      ctx.strokeStyle = '#FFFFFF';
      ctx.lineWidth = d === state.hoveredNode ? 2.5 : 1;
      ctx.stroke();

      // Domain Label
      ctx.fillStyle = d === state.hoveredNode ? '#FFFFFF' : 'rgba(255, 255, 255, 0.7)';
      ctx.font = `${d === state.hoveredNode ? 'bold 11px' : '10px'} "Space Grotesk", sans-serif`;
      ctx.textAlign = 'center';
      const shortName = d.domain.length > 18 ? d.domain.substring(0, 16) + '..' : d.domain;
      ctx.fillText(shortName, nx, ny + d.radius + 12);
    });

    // 6. Draw Kinetic Particles
    state.particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    // 7. Hover Tooltip
    if (state.hoveredNode) {
      drawNodeTooltip(state.hoveredNode);
    }
  }

  function drawAgentCore(cx, cy) {
    const pulse = Math.sin(Date.now() / 300) * 2;
    // Core Outer Aura
    ctx.beginPath();
    ctx.arc(cx, cy, 26 + pulse, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(212, 175, 55, 0.15)';
    ctx.fill();

    // Core Solid Circle
    ctx.beginPath();
    ctx.arc(cx, cy, 20, 0, Math.PI * 2);
    const grad = ctx.createRadialGradient(cx, cy, 2, cx, cy, 20);
    grad.addColorStop(0, '#FFF2B2');
    grad.addColorStop(1, '#D4AF37');
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.strokeStyle = '#FFFFFF';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Core Glyph
    ctx.fillStyle = '#08080B';
    ctx.font = 'bold 9px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('AGENT', cx, cy - 2);
    ctx.font = '7px "JetBrains Mono", monospace';
    ctx.fillText('CORE', cx, cy + 6);
    ctx.textBaseline = 'alphabetic';
  }

  function drawNodeTooltip(node) {
    const padding = 8;
    const lines = [
      node.domain,
      `Category: ${CATEGORY_THEME[node.category]?.label || node.category}`,
      `Requests: ${node.request_count} | Endpoints: ${node.unique_endpoints || 1}`,
      `Throughput: ${formatBytes(node.total_bytes_sent + node.total_bytes_recv)}`,
      node.quarantined_count > 0 ? `⚠️ Quarantined: ${node.quarantined_count}` : null,
    ].filter(Boolean);

    ctx.font = '11px "Space Grotesk", sans-serif';
    const maxWidth = Math.max(...lines.map(l => ctx.measureText(l).width)) + padding * 2;
    const boxHeight = lines.length * 16 + padding * 2;

    let bx = node.x + 12;
    let by = node.y - boxHeight / 2;

    const width = parseFloat(canvas.style.width);
    if (bx + maxWidth > width) bx = node.x - maxWidth - 12;
    if (by < 10) by = 10;

    ctx.save();
    ctx.fillStyle = 'rgba(12, 12, 18, 0.92)';
    ctx.strokeStyle = 'rgba(212, 175, 55, 0.5)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(bx, by, maxWidth, boxHeight, 6);
    ctx.fill();
    ctx.stroke();

    lines.forEach((line, i) => {
      ctx.fillStyle = i === 0 ? '#D4AF37' : (line.includes('Quarantined') ? '#EF4444' : '#E2E8F0');
      ctx.font = i === 0 ? 'bold 11px "Space Grotesk", sans-serif' : '10px "Space Grotesk", sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(line, bx + padding, by + padding + (i + 1) * 14 - 2);
    });
    ctx.restore();
  }

  function spawnPacketParticle(targetDomain) {
    const width = parseFloat(canvas.style.width);
    const height = parseFloat(canvas.style.height);
    const cx = width / 2;
    const cy = height / 2;
    const node = state.domains.get(targetDomain);
    if (!node || !node.x) return;

    const catCfg = CATEGORY_THEME[node.category] || CATEGORY_THEME.unknown;
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
      p.x = p.x + (p.tx - p.x) * p.speed * 2.5;
      p.y = p.y + (p.ty - p.y) * p.speed * 2.5;

      if (p.progress >= 1.0 || Math.hypot(p.tx - p.x, p.ty - p.y) < 6) {
        state.particles.splice(i, 1);
      }
    }
  }

  // --- Interaction Event Handlers ---
  function onCanvasMouseMove(e) {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    let found = null;
    for (const d of state.domains.values()) {
      if (d.x && d.y) {
        const dist = Math.hypot(mx - d.x, my - d.y);
        if (dist <= d.radius + 4) {
          found = d;
          break;
        }
      }
    }
    state.hoveredNode = found;
    canvas.style.cursor = found ? 'pointer' : 'default';
  }

  function onCanvasClick(e) {
    if (state.hoveredNode) {
      filterByDomain(state.hoveredNode.domain);
    }
  }

  function filterByDomain(domain) {
    state.selectedDomain = state.selectedDomain === domain ? null : domain;
    const searchInput = document.getElementById('tableSearchInput');
    if (searchInput) {
      searchInput.value = state.selectedDomain || '';
    }
    state.searchQuery = state.selectedDomain || '';
    renderTrafficTable();
    showToast(state.selectedDomain ? `Filtering events by domain: ${state.selectedDomain}` : 'Cleared domain filter', 'info');
  }

  // --- API Sync & SSE Feed ---
  async function fetchStats() {
    try {
      const res = await fetch('/api/stats');
      if (!res.ok) return;
      const data = await res.json();
      state.stats = data;

      if (statsReqs) statsReqs.textContent = (data.total_requests || 0).toLocaleString();
      if (statsDomains) statsDomains.textContent = (data.total_domains || 0).toLocaleString();
      if (statsData) statsData.textContent = formatBytes((data.total_bytes_sent || 0) + (data.total_bytes_recv || 0));
      if (statsLatency) statsLatency.textContent = `${Math.round(data.avg_latency_ms || 0)}ms`;
      if (statsQuarantine) statsQuarantine.textContent = (data.total_quarantined || 0).toLocaleString();

      const policySelect = document.getElementById('policyModeSelect');
      if (policySelect && data.quarantine_mode) {
        policySelect.value = data.quarantine_mode;
      }
    } catch (err) {
      // Quiet background polling error
    }
  }

  async function fetchDomains() {
    try {
      const res = await fetch('/api/domains');
      if (!res.ok) return;
      const data = await res.json();

      (data.domains || []).forEach(d => {
        const existing = state.domains.get(d.domain);
        state.domains.set(d.domain, { ...existing, ...d });
      });

      renderDomainList();
    } catch (err) {
      // Quiet background polling error
    }
  }

  async function fetchTraffic() {
    try {
      const res = await fetch('/api/traffic?limit=100');
      if (!res.ok) return;
      const data = await res.json();
      state.events = data.events || [];
      renderTrafficTable();
    } catch (err) {
      // Quiet background polling error
    }
  }

  function connectSSE() {
    try {
      const sse = new EventSource('/api/stream');
      sse.onopen = () => {
        state.sseConnected = true;
        const ind = document.getElementById('sseIndicator');
        if (ind) {
          ind.classList.remove('bg-zinc-500');
          ind.classList.add('bg-emerald-400');
        }
      };

      sse.onmessage = (event) => {
        try {
          const item = JSON.parse(event.data);
          state.events.unshift(item);
          if (state.events.length > 200) state.events.pop();

          // Update domain entry
          if (!state.domains.has(item.domain)) {
            state.domains.set(item.domain, {
              domain: item.domain,
              category: item.category,
              request_count: 1,
              total_bytes_sent: item.bytes_sent,
              total_bytes_recv: item.bytes_recv,
              quarantined_count: item.quarantined ? 1 : 0,
            });
          } else {
            const d = state.domains.get(item.domain);
            d.request_count += 1;
            d.total_bytes_sent += item.bytes_sent;
            d.total_bytes_recv += item.bytes_recv;
            if (item.quarantined) d.quarantined_count += 1;
          }

          spawnPacketParticle(item.domain);
          renderTrafficTable();
          fetchStats();
        } catch (e) {
          // heartbeat or ignore
        }
      };

      sse.onerror = () => {
        state.sseConnected = false;
        const ind = document.getElementById('sseIndicator');
        if (ind) {
          ind.classList.remove('bg-emerald-400');
          ind.classList.add('bg-zinc-500');
        }
      };
    } catch (e) {
      // SSE not available
    }
  }

  // --- UI Renders ---
  function renderDomainList() {
    if (!domainListEl) return;
    const domains = Array.from(state.domains.values());
    if (domains.length === 0) {
      domainListEl.innerHTML = `<div class="p-4 text-center text-xs text-zinc-500">No agent egress detected yet. Run an agent or simulate traffic below.</div>`;
      return;
    }

    domainListEl.innerHTML = domains.map(d => {
      const catCfg = CATEGORY_THEME[d.category] || CATEGORY_THEME.unknown;
      const isSelected = state.selectedDomain === d.domain;
      return `
        <div onclick="window.filterByDomain('${escapeHtml(d.domain)}')" class="flex items-center justify-between p-3 rounded-lg border ${isSelected ? 'border-amber-500/60 bg-amber-500/10' : 'border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-800/50'} cursor-pointer transition-all duration-200">
          <div class="flex items-center space-x-3 overflow-hidden">
            <span class="w-2.5 h-2.5 rounded-full flex-shrink-0" style="background-color: ${catCfg.color}; box-shadow: 0 0 8px ${catCfg.color}66;"></span>
            <div class="truncate">
              <div class="text-xs font-semibold text-zinc-200 truncate">${escapeHtml(d.domain)}</div>
              <div class="text-[10px] text-zinc-400">${catCfg.label} • ${d.request_count} reqs</div>
            </div>
          </div>
          <div class="text-right flex-shrink-0 text-[11px] font-mono text-zinc-400">
            <div>${formatBytes(d.total_bytes_sent + d.total_bytes_recv)}</div>
            ${d.quarantined_count > 0 ? '<span class="text-[9px] text-red-400 font-bold">BLOCKED</span>' : '<span class="text-[9px] text-emerald-400 font-bold">PERMITTED</span>'}
          </div>
        </div>
      `;
    }).join('');
  }

  function renderTrafficTable() {
    if (!trafficTableBody) return;

    let filtered = state.events;

    if (state.filterCategory !== 'all') {
      filtered = filtered.filter(e => e.category === state.filterCategory);
    }

    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      filtered = filtered.filter(e =>
        e.domain.toLowerCase().includes(q) ||
        (e.url_path && e.url_path.toLowerCase().includes(q)) ||
        (e.agent_name && e.agent_name.toLowerCase().includes(q))
      );
    }

    if (filtered.length === 0) {
      trafficTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="p-8 text-center text-xs text-zinc-500">
            No matching egress events found.
          </td>
        </tr>
      `;
      return;
    }

    trafficTableBody.innerHTML = filtered.slice(0, 50).map(e => {
      const catCfg = CATEGORY_THEME[e.category] || CATEGORY_THEME.unknown;
      const timeStr = new Date(e.timestamp * 1000).toLocaleTimeString();
      const statusColor = e.quarantined ? 'text-red-400 bg-red-950/40 border-red-800/50' : (e.status_code === 200 ? 'text-emerald-400 bg-emerald-950/40 border-emerald-800/50' : 'text-amber-400 bg-amber-950/40 border-amber-800/50');

      return `
        <tr class="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
          <td class="p-3 text-[11px] font-mono text-zinc-400">${timeStr}</td>
          <td class="p-3 text-xs font-medium text-zinc-300">
            <span class="px-2 py-0.5 rounded text-[10px] bg-zinc-800 text-zinc-300 font-mono">${escapeHtml(e.agent_name || 'agent')}</span>
          </td>
          <td class="p-3 text-xs font-semibold text-zinc-100 flex items-center space-x-2">
            <span class="w-2 h-2 rounded-full flex-shrink-0" style="background-color: ${catCfg.color};"></span>
            <span class="font-mono text-xs">${escapeHtml(e.domain)}</span>
          </td>
          <td class="p-3 text-xs">
            <span class="px-2 py-0.5 text-[10px] font-mono uppercase rounded border ${statusColor}">
              ${e.quarantined ? 'QUARANTINE' : e.method} ${e.status_code || ''}
            </span>
          </td>
          <td class="p-3 text-xs font-mono text-zinc-400">${formatBytes(e.bytes_sent + e.bytes_recv)}</td>
          <td class="p-3 text-xs font-mono text-zinc-400">${Math.round(e.latency_ms)}ms</td>
          <td class="p-3 text-right">
            <button onclick="window.inspectEvent('${e.id}')" class="px-2.5 py-1 text-[11px] font-medium rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition">
              Inspect
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  // --- Inspect Event Modal ---
  window.inspectEvent = function (eventId) {
    const ev = state.events.find(e => e.id === eventId);
    if (!ev) return;

    const modal = document.getElementById('inspectModal');
    const content = document.getElementById('inspectModalContent');
    if (!modal || !content) return;

    const catCfg = CATEGORY_THEME[ev.category] || CATEGORY_THEME.unknown;

    content.innerHTML = `
      <div class="space-y-4 text-xs text-zinc-300">
        <div class="grid grid-cols-2 gap-3 p-3 bg-zinc-900/80 rounded-lg border border-zinc-800 font-mono text-[11px]">
          <div><span class="text-zinc-500">Domain:</span> <span class="text-amber-400 font-bold">${escapeHtml(ev.domain)}</span></div>
          <div><span class="text-zinc-500">Category:</span> <span style="color: ${catCfg.color}; font-weight: bold;">${catCfg.label}</span></div>
          <div><span class="text-zinc-500">Protocol:</span> ${escapeHtml(ev.protocol)}</div>
          <div><span class="text-zinc-500">Method:</span> ${escapeHtml(ev.method)}</div>
          <div><span class="text-zinc-500">Remote IP:</span> ${escapeHtml(ev.remote_ip)}:${ev.remote_port}</div>
          <div><span class="text-zinc-500">Status:</span> ${ev.quarantined ? '<span class="text-red-400 font-bold">QUARANTINED</span>' : ev.status_code}</div>
          <div><span class="text-zinc-500">Bytes Sent:</span> ${formatBytes(ev.bytes_sent)}</div>
          <div><span class="text-zinc-500">Bytes Recv:</span> ${formatBytes(ev.bytes_recv)}</div>
          <div class="col-span-2"><span class="text-zinc-500">Endpoint:</span> <span class="text-zinc-200">${escapeHtml(ev.url_path)}</span></div>
        </div>

        <div>
          <div class="font-bold text-zinc-400 mb-1">Request Payload Sample / Handshake:</div>
          <pre class="p-3 bg-black/60 rounded border border-zinc-800 text-[11px] font-mono text-zinc-300 overflow-x-auto whitespace-pre-wrap">${escapeHtml(ev.request_sample || '(TLS Handshake tunnel - raw payload encrypted)')}</pre>
        </div>

        <div>
          <div class="font-bold text-zinc-400 mb-1">Response Sample / Server Ack:</div>
          <pre class="p-3 bg-black/60 rounded border border-zinc-800 text-[11px] font-mono text-zinc-300 overflow-x-auto whitespace-pre-wrap">${escapeHtml(ev.response_sample || '(Binary response stream)')}</pre>
        </div>

        ${ev.notes ? `
          <div class="p-2.5 rounded bg-amber-950/20 border border-amber-800/40 text-amber-300 text-[11px]">
            <strong>Sentinel Notes:</strong> ${escapeHtml(ev.notes)}
          </div>
        ` : ''}

        <div class="flex items-center justify-between pt-2 border-t border-zinc-800">
          <button onclick="window.toggleBlockDomain('${escapeHtml(ev.domain)}')" class="px-3 py-1.5 rounded bg-red-900/40 text-red-300 hover:bg-red-800/60 border border-red-700/50 text-xs font-semibold">
            🚫 Add ${escapeHtml(ev.domain)} to Blocklist
          </button>
          <button onclick="document.getElementById('inspectModal').classList.add('hidden')" class="px-4 py-1.5 rounded bg-zinc-800 text-zinc-300 hover:bg-zinc-700 text-xs font-semibold">
            Close
          </button>
        </div>
      </div>
    `;

    modal.classList.remove('hidden');
  };

  // --- Policy & Action Interceptors ---
  window.changeQuarantinePolicy = async function (mode) {
    try {
      const res = await fetch('/api/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      if (res.ok) {
        showToast(`Quarantine policy switched to: ${mode.toUpperCase()}`, 'success');
        fetchStats();
      }
    } catch (err) {
      showToast('Failed to update policy: ' + err.message, 'error');
    }
  };

  window.toggleBlockDomain = async function (domain) {
    try {
      const res = await fetch('/api/rules/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });
      if (res.ok) {
        showToast(`Domain '${domain}' added to Sentinel blocklist`, 'success');
        document.getElementById('inspectModal').classList.add('hidden');
      }
    } catch (err) {
      showToast('Failed to block domain: ' + err.message, 'error');
    }
  };

  window.clearLogs = async function () {
    if (!confirm('Are you sure you want to clear all logged egress traffic events?')) return;
    try {
      await fetch('/api/clear', { method: 'POST' });
      state.events = [];
      state.domains.clear();
      renderTrafficTable();
      renderDomainList();
      fetchStats();
      showToast('Egress traffic logs cleared.', 'info');
    } catch (err) {
      showToast('Error clearing logs', 'error');
    }
  };

  window.handleExportHAR = function () {
    if (!state.isPro) {
      window.openPaywallModal();
      return;
    }
    window.location.href = '/api/export';
  };

  window.handleExportOpenAPI = function () {
    if (!state.isPro) {
      window.openPaywallModal();
      return;
    }
    window.location.href = '/api/export/openapi';
  };

  window.runAgentSimulation = function () {
    const sampleTargets = [
      { domain: 'api.openai.com', category: 'llm_api', path: '/v1/chat/completions', method: 'POST', sent: 3400, recv: 12400 },
      { domain: 'api.anthropic.com', category: 'llm_api', path: '/v1/messages', method: 'POST', sent: 4100, recv: 16800 },
      { domain: 'huggingface.co', category: 'model_hub', path: '/api/models/meta-llama', method: 'GET', sent: 820, recv: 45000 },
      { domain: 'api.segment.io', category: 'telemetry_tracker', path: '/v1/track', method: 'POST', sent: 1200, recv: 200 },
      { domain: 'telemetry.sentry.io', category: 'telemetry_tracker', path: '/api/123/envelope/', method: 'POST', sent: 2400, recv: 150 },
      { domain: 'api.tavily.com', category: 'search_scraper', path: '/search', method: 'POST', sent: 940, recv: 8900 },
      { domain: 'localhost', category: 'local_service', path: '/v1/models', method: 'GET', sent: 400, recv: 1800 },
    ];

    let delay = 0;
    sampleTargets.forEach((target, idx) => {
      setTimeout(() => {
        const isQuarantined = state.stats.quarantine_mode === 'zero_egress' && target.category !== 'local_service' ||
          state.stats.quarantine_mode === 'block_telemetry' && target.category === 'telemetry_tracker';

        const mockEvent = {
          id: 'sim-' + Date.now() + '-' + idx,
          timestamp: Date.now() / 1000,
          agent_name: 'autonomous_planner',
          domain: target.domain,
          remote_ip: '104.18.2' + idx + '.1',
          remote_port: 443,
          protocol: 'HTTPS',
          method: target.method,
          url_path: target.path,
          status_code: isQuarantined ? 403 : 200,
          bytes_sent: target.sent,
          bytes_recv: isQuarantined ? 0 : target.recv,
          latency_ms: 45 + Math.random() * 80,
          category: target.category,
          quarantined: isQuarantined,
          notes: isQuarantined ? 'Quarantined by policy' : 'Simulated agent traffic',
        };

        state.events.unshift(mockEvent);
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
          d.request_count += 1;
          d.total_bytes_sent += target.sent;
          d.total_bytes_recv += isQuarantined ? 0 : target.recv;
          if (isQuarantined) d.quarantined_count += 1;
        }

        spawnPacketParticle(target.domain);
        renderTrafficTable();
        renderDomainList();
        fetchStats();
      }, delay);
      delay += 350;
    });

    showToast('⚡ Simulating multi-agent network trajectories across radar orbits...', 'info');
  };

  // --- UI Event Listeners ---
  function setupEventListeners() {
    const filterTabs = document.querySelectorAll('.category-tab');
    filterTabs.forEach(tab => {
      tab.addEventListener('click', (e) => {
        filterTabs.forEach(t => t.classList.remove('active', 'border-amber-500', 'text-amber-400', 'bg-amber-500/10'));
        tab.classList.add('active', 'border-amber-500', 'text-amber-400', 'bg-amber-500/10');
        state.filterCategory = tab.dataset.category || 'all';
        renderTrafficTable();
      });
    });

    const searchInput = document.getElementById('tableSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        state.searchQuery = e.target.value.trim();
        renderTrafficTable();
      });
    }

    const runForm = document.getElementById('runAgentForm');
    if (runForm) {
      runForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const cmdInput = document.getElementById('runCommandInput');
        const agentInput = document.getElementById('runAgentName');
        const cmd = cmdInput ? cmdInput.value.trim() : '';
        const agent_name = agentInput ? agentInput.value.trim() : 'custom_agent';

        if (!cmd) return;

        try {
          showToast(`Launching agent: ${cmd}`, 'info');
          const res = await fetch('/api/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: cmd, agent_name }),
          });
          const data = await res.json();
          if (res.ok) {
            showToast(`Agent PID spawned under proxy supervision`, 'success');
          }
        } catch (err) {
          showToast('Failed to launch: ' + err.message, 'error');
        }
      });
    }
  }

  // --- Helper Functions ---
  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function debounce(fn, ms) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    const color = type === 'success' ? 'border-emerald-500 bg-emerald-950/90 text-emerald-200' :
      type === 'error' ? 'border-red-500 bg-red-950/90 text-red-200' :
      'border-amber-500 bg-zinc-900/90 text-amber-200';

    toast.className = `fixed bottom-5 right-5 z-50 px-4 py-3 rounded-lg border shadow-xl text-xs font-semibold backdrop-blur-md transition-all duration-300 transform translate-y-2 opacity-0 ${color}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
      toast.classList.remove('translate-y-2', 'opacity-0');
    }, 10);

    setTimeout(() => {
      toast.classList.add('translate-y-2', 'opacity-0');
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  window.filterByDomain = filterByDomain;

  // DOM Content Loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
