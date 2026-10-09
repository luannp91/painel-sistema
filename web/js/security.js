import "./utils/token-init.js";
import { apiFetch } from "./api/rest.js";
import { $, $$, esc } from "./utils/dom.js";

// ============================================================================
// Segurança — 4 páginas, um só script
// ============================================================================
//
// `data-page` no <html> define o que renderizar:
//   - "hub"       → cards de escolha com contadores ao vivo
//   - "processes" → KPIs, health, top, tabela completa
//   - "ports"     → KPIs, tabela de portas em escuta
//   - "network"   → KPIs, tabela de conexões ativas
//
// SSE entrega dois eventos:
//   - default    → SystemSnapshot   → health strip (só em "processes")
//   - "security" → SecuritySnapshot → tudo o mais
//
// Autenticação vai por cookie HttpOnly (o browser envia sozinho).

const PAGE = document.documentElement.dataset.page || "hub";

const state = {
  snapshot: null,
  es: null,
  filters: {
    search: "",
    severity: "",
    sort: "final_score",
    onlyFlagged: true,
    expanded: false,
  },
  ports: {
    search: "",
    protocol: "",
    sort: "port",
    onlyFlagged: false,
  },
  net: {
    search: "",
    state: "",
    sort: "pid",
    onlyFlagged: false,
    onlyPublic: false,
  },
  expandedPids: new Set(),
  lastUpdate: 0,
  learningRemainingSecs: 0,
};

/// Rastreia transição `true → false` do aprendizado para disparar toast.
let previousLearning = null;

// ---------------------------------------------------------------------------
// Helpers de domínio
// ---------------------------------------------------------------------------

function sevClass(sev) {
  switch (sev) {
    case "attention":
      return "kpi-attention";
    case "suspicious":
      return "kpi-suspicious";
    case "critical":
      return "kpi-critical";
    default:
      return "kpi-clean";
  }
}

function sevLabel(sev) {
  switch (sev) {
    case "clean":
      return "limpo";
    case "attention":
      return "atenção";
    case "suspicious":
      return "suspeito";
    case "critical":
      return "crítico";
    default:
      return sev;
  }
}

function toast(msg, kind = "info") {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.className = `toast show ${kind}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.className = "toast"), 3500);
}

function setStreamStatus(status, label) {
  const el = document.getElementById("streamStatus");
  const lbl = document.getElementById("streamLabel");
  if (!el || !lbl) return;
  el.className = `live-indicator${status ? ` ${status}` : ""}`;
  lbl.textContent = label;
}

function barClass(pct) {
  if (pct >= 90) return "err";
  if (pct >= 75) return "warn";
  return "";
}

function formatRemaining(secs) {
  if (secs <= 0) return "concluído";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}min`);
  parts.push(`${s}s`);
  return parts.join(" ");
}

// -- Endereços ---------------------------------------------------------------

function addrClass(addr) {
  if (!addr) return "unknown";
  if (addr === "::1" || addr.startsWith("127.")) return "loopback";
  if (addr.startsWith("169.254.") || addr.toLowerCase().startsWith("fe80:")) {
    return "linklocal";
  }
  if (
    addr.startsWith("10.") ||
    addr.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(addr) ||
    addr.toLowerCase().startsWith("fc") ||
    addr.toLowerCase().startsWith("fd")
  ) {
    return "private";
  }
  return "public";
}

function fmtAddrPort(addr, port) {
  if (!addr) return "—";
  return `${addr}:${port}`;
}

// -- Badges ------------------------------------------------------------------

function protoBadge(proto) {
  const cls = proto === "tcp" ? "proto-tcp" : "proto-udp";
  return `<span class="proto-badge ${cls}">${esc(proto.toUpperCase())}</span>`;
}

const STATE_LABEL = {
  listen: "Listen",
  established: "Estabelecida",
  time_wait: "Time Wait",
  close_wait: "Close Wait",
  syn_sent: "SYN Sent",
  syn_recv: "SYN Recv",
  other: "Outro",
};

function stateBadge(s) {
  const label = STATE_LABEL[s] ?? s;
  return `<span class="state-badge state-${esc(s)}">${esc(label)}</span>`;
}

// -- Correlação socket ↔ finding ---------------------------------------------

function findingsIndex(snap) {
  const byPid = new Map();
  for (const proc of snap.processes ?? []) {
    for (const f of proc.findings ?? []) {
      if (!byPid.has(proc.pid)) byPid.set(proc.pid, []);
      byPid.get(proc.pid).push(f);
    }
  }
  return byPid;
}

function isPortFlagged(socket, idx) {
  const findings = idx.get(socket.pid);
  if (!findings) return false;
  return findings.some(
    (f) =>
      f.kind === "unusual_listening_port" &&
      f.detail.includes(`:${socket.port}`),
  );
}

function isConnectionFlagged(conn, idx) {
  if (!conn.remote_addr || !conn.remote_port) return false;
  const findings = idx.get(conn.pid);
  if (!findings) return false;
  return findings.some(
    (f) =>
      f.kind === "external_connection" &&
      f.detail.includes(`${conn.remote_addr}:${conn.remote_port}`),
  );
}

// ---------------------------------------------------------------------------
// Health strip — SystemSnapshot (evento default do SSE)
// ---------------------------------------------------------------------------

function renderHealth(snap) {
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };
  const setBar = (id, pct) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.width = `${Math.min(100, pct).toFixed(1)}%`;
    el.className = `health-fill ${barClass(pct)}`;
  };

  const cpu = snap.cpu?.usage_percent ?? 0;
  set("healthCpu", `${cpu.toFixed(1)}%`);
  setBar("healthCpuBar", cpu);

  const mem = snap.memory?.percent ?? 0;
  set("healthMem", `${mem.toFixed(1)}%`);
  setBar("healthMemBar", mem);

  const disk = snap.disk?.percent ?? 0;
  set("healthDisk", `${disk.toFixed(1)}%`);
  setBar("healthDiskBar", disk);

  set("healthProcs", snap.processes?.count ?? "—");
}

// ---------------------------------------------------------------------------
// SSE
// ---------------------------------------------------------------------------

function connectStream() {
  let es;
  try {
    es = new EventSource("/api/stream");
  } catch {
    setStreamStatus("offline", "offline");
    return;
  }
  state.es = es;

  es.addEventListener("open", () => setStreamStatus("", "ao vivo"));

  es.onmessage = (e) => {
    if (PAGE !== "processes") return;
    try {
      renderHealth(JSON.parse(e.data));
    } catch (err) {
      console.warn("parse system SSE falhou:", err);
    }
  };

  es.addEventListener("security", (e) => {
    try {
      const snap = JSON.parse(e.data);
      state.snapshot = snap;
      state.lastUpdate = Date.now();
      renderAll();
    } catch (err) {
      console.warn("parse security SSE falhou:", err);
    }
  });

  es.addEventListener("error", () => {
    setStreamStatus("stale", "reconectando…");
    setTimeout(() => {
      if (state.es && state.es.readyState !== EventSource.OPEN) {
        setStreamStatus("offline", "offline");
      }
    }, 10000);
  });
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

function renderAll() {
  const snap = state.snapshot;
  if (!snap) return;

  const idx = findingsIndex(snap);

  if (PAGE !== "hub") {
    state.learningRemainingSecs = snap.learning_remaining_secs ?? 0;
    renderLearning(snap.learning);
  }

  switch (PAGE) {
    case "processes":
      renderProcessesPage(snap);
      break;
    case "ports":
      renderPortsPage(snap, idx);
      break;
    case "network":
      renderNetworkPage(snap, idx);
      break;
    case "hub":
    default:
      renderHub(snap, idx);
      break;
  }
}

// ---------------------------------------------------------------------------
// Página: Hub
// ---------------------------------------------------------------------------

function renderHub(snap, idx) {
  const processes = snap.processes ?? [];
  const ports = snap.sockets?.listening ?? [];
  const conns = snap.sockets?.connections ?? [];

  const alertProcesses =
    snap.counts.attention + snap.counts.suspicious + snap.counts.critical;
  const flaggedPorts = ports.filter((p) => isPortFlagged(p, idx)).length;
  const flaggedConns = conns.filter((c) => isConnectionFlagged(c, idx)).length;

  setHubStat("hubProcesses", processes.length, alertProcesses, "processos");
  setHubStat("hubPorts", ports.length, flaggedPorts, "portas");
  setHubStat("hubNetwork", conns.length, flaggedConns, "conexões");
}

function setHubStat(id, total, alerts, unit) {
  const el = document.getElementById(id);
  if (!el) return;
  if (alerts > 0) {
    el.textContent = `${total} ${unit} · ${alerts} ⚠`;
    el.classList.add("has-alert");
  } else {
    el.textContent = `${total} ${unit}`;
    el.classList.remove("has-alert");
  }
}

// ---------------------------------------------------------------------------
// Página: Processos
// ---------------------------------------------------------------------------

function renderProcessesPage(snap) {
  document.getElementById("kpiClean").textContent = snap.counts.clean;
  document.getElementById("kpiAttention").textContent = snap.counts.attention;
  document.getElementById("kpiSuspicious").textContent = snap.counts.suspicious;
  document.getElementById("kpiCritical").textContent = snap.counts.critical;

  const cycleEl = document.getElementById("healthCycle");
  if (cycleEl) cycleEl.textContent = `${snap.elapsed_ms} ms`;

  const total = snap.processes.length;
  const alertas =
    snap.counts.attention + snap.counts.suspicious + snap.counts.critical;
  document.getElementById("secCount").textContent = `${alertas} com alerta`;
  document.getElementById("secMeta").textContent =
    `${total} processos analisados`;
  document.getElementById("secUpdated").textContent =
    `Atualizado às ${new Date().toLocaleTimeString()}`;

  renderTop(snap.processes);
  renderTable();
}

// ---------------------------------------------------------------------------
// Aprendizado (compartilhado entre sub-páginas)
// ---------------------------------------------------------------------------

function renderLearning(isLearning) {
  const banner = document.getElementById("learningBanner");
  if (!banner) return;

  if (previousLearning === true && !isLearning) {
    toast("🎓 Aprendizado concluído — atenuação de baseline ativa", "ok");
  }
  previousLearning = isLearning;

  banner.hidden = !isLearning;
  if (!isLearning) return;
  updateLearningCountdown();
}

function updateLearningCountdown() {
  const el = document.getElementById("learningRemaining");
  if (!el) return;
  const secs = state.learningRemainingSecs;
  const prog = el.closest(".learning-progress");

  if (secs <= 0) {
    el.textContent = "concluído";
    prog?.classList.add("done");
    return;
  }
  prog?.classList.remove("done");
  el.textContent = formatRemaining(secs);
}

// ---------------------------------------------------------------------------
// Top processos (página processes)
// ---------------------------------------------------------------------------

function renderTop(processes) {
  const container = document.getElementById("topProcesses");
  const meta = document.getElementById("topMeta");
  if (!container) return;

  const top = processes.filter((p) => p.final_score > 0).slice(0, 5);

  if (meta) {
    meta.textContent =
      top.length === 0 ? "nenhum" : `${top.length} de ${processes.length}`;
  }

  if (top.length === 0) {
    container.innerHTML = `
      <div class="sec-empty">
        <span class="icon">🛡️</span>
        <p>Nenhum processo com score acima de zero neste ciclo.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = top
    .map((p) => {
      const sev = sevClass(p.severity);
      const findings = (p.findings || []).map((f) => f.kind);
      const chain = (p.chain?.findings || []).map((f) => f.kind);
      const all = [...findings, ...chain];
      const tooltip = all.length > 0 ? all.join(", ") : "sem findings";
      const badgeClass = sev.replace("kpi-", "sev-");
      return `
        <a class="top-row" href="#proc-${p.pid}" title="${esc(tooltip)}">
          <span class="top-pid">${p.pid}</span>
          <span class="top-name">${esc(p.name)}</span>
          <span class="top-score">${p.final_score}</span>
          <span class="top-badge">
            <span class="sev-badge ${badgeClass}">${sevLabel(p.severity)}</span>
          </span>
        </a>
      `;
    })
    .join("");
}

// ---------------------------------------------------------------------------
// Tabela de processos
// ---------------------------------------------------------------------------

function processFiltered() {
  const snap = state.snapshot;
  if (!snap) return [];

  const { search, severity, sort, onlyFlagged } = state.filters;
  const q = search.trim().toLowerCase();

  let list = snap.processes.slice();

  if (onlyFlagged) list = list.filter((p) => p.final_score > 0);
  if (severity) list = list.filter((p) => p.severity === severity);
  if (q) {
    list = list.filter(
      (p) => String(p.pid).includes(q) || p.name.toLowerCase().includes(q),
    );
  }

  switch (sort) {
    case "chain_depth":
      list.sort(
        (a, b) =>
          b.chain.depth - a.chain.depth || b.final_score - a.final_score,
      );
      break;
    case "name":
      list.sort((a, b) => a.name.localeCompare(b.name));
      break;
    case "pid":
      list.sort((a, b) => a.pid - b.pid);
      break;
    case "final_score":
    default:
      list.sort((a, b) => b.final_score - a.final_score || a.pid - b.pid);
      break;
  }

  return list;
}

function renderTable() {
  const container = document.getElementById("securityTable");
  if (!container) return;
  const list = processFiltered();

  if (list.length === 0) {
    container.innerHTML = `
      <div class="sec-empty">
        <span class="icon">🛡️</span>
        <p>Nenhum processo corresponde aos filtros atuais.</p>
      </div>
    `;
    return;
  }

  const rows = list.map(renderRow).join("");
  container.innerHTML = `
    <table class="sec-table">
      <thead>
        <tr>
          <th class="sortable" data-sort="pid">PID</th>
          <th class="sortable" data-sort="name">Processo</th>
          <th class="sortable" data-sort="final_score">Score</th>
          <th>Severidade</th>
          <th>Findings</th>
          <th class="sortable hide-sm" data-sort="chain_depth">Cadeia</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;

  container.querySelectorAll("thead th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      state.filters.sort = th.dataset.sort;
      const sel = document.getElementById("filterSort");
      if (sel) sel.value = state.filters.sort;
      renderTable();
    });
  });

  container.querySelectorAll("tbody tr.sec-row").forEach((tr) => {
    tr.addEventListener("click", (ev) => {
      if (ev.target.closest("a, button")) return;
      const pid = Number(tr.dataset.pid);
      if (state.expandedPids.has(pid)) {
        state.expandedPids.delete(pid);
      } else {
        state.expandedPids.add(pid);
      }
      renderTable();
    });
  });
}

function renderRow(p) {
  const sev = sevClass(p.severity).replace("kpi-", "sev-");
  const pct = Math.min(100, p.final_score);
  const findings = p.findings || [];
  const chainFindings = (p.chain && p.chain.findings) || [];
  const expanded = state.expandedPids.has(p.pid) || state.filters.expanded;

  const findingsPills = [
    ...findings.map(
      (f) =>
        `<span class="finding-pill" title="${esc(f.detail)}">${esc(f.kind)} <span class="weight">+${f.weight}</span></span>`,
    ),
    ...chainFindings.map(
      (f) =>
        `<span class="finding-pill chain" title="${esc(f.detail)}">${esc(f.kind)} <span class="weight">+${f.weight}</span></span>`,
    ),
  ].join("");

  const depth = p.chain ? p.chain.depth : 1;
  const depthCell =
    depth > 1
      ? `<span class="depth">${depth}</span> níveis`
      : `<span class="depth">1</span>`;

  const attMark = p.attenuated
    ? ` <span class="attenuated-mark" title="Atenuado pelo baseline">·aten.</span>`
    : "";

  const row = `
    <tr class="sec-row ${sev}" data-pid="${p.pid}" id="proc-${p.pid}">
      <td class="pid">${p.pid}</td>
      <td>${esc(p.name)}${attMark}</td>
      <td>
        <span class="score-cell">
          <span class="score-num">${p.final_score}</span>
          <span class="score-bar">
            <span class="score-fill ${sev}" style="width:${pct}%"></span>
          </span>
        </span>
      </td>
      <td><span class="sev-badge ${sev}">${sevLabel(p.severity)}</span></td>
      <td><div class="findings-cell">${findingsPills || "—"}</div></td>
      <td class="chain-cell hide-sm">${depthCell}</td>
    </tr>
  `;

  const detail = expanded ? renderDetail(p) : "";
  return row + detail;
}

function renderDetail(p) {
  const findings = p.findings || [];
  const chainFindings = (p.chain && p.chain.findings) || [];

  const renderFinding = (f) => {
    const tech = f.technique
      ? `<div class="technique">MITRE ${esc(f.technique.id)} — ${esc(f.technique.name)}</div>`
      : "";
    return `
      <div class="detail-finding">
        <span class="kind">${esc(f.kind)}</span>
        <span class="detail-text">${esc(f.detail)}</span>
        <span class="weight">+${f.weight}</span>
        ${tech}
      </div>
    `;
  };

  const chainNodes = (p.chain && p.chain.node_pids) || [];
  const chainHtml =
    chainNodes.length > 0
      ? `<div class="chain-nodes">
           ${chainNodes
             .map((pid) => `<span class="chain-node">${pid}</span>`)
             .join('<span class="chain-arrow">→</span>')}
         </div>`
      : "<p>—</p>";

  return `
    <tr class="detail-row">
      <td colspan="6">
        <div class="detail-block">
          <h4>Scores</h4>
          <div>
            original <strong>${p.original_score}</strong>
            · baseline <strong>${p.baseline_score}</strong>
            · final <strong>${p.final_score}</strong>
            ${p.attenuated ? " · <em>atenuado pelo baseline</em>" : ""}
          </div>

          ${
            findings.length > 0
              ? `<h4>Findings deste processo</h4>${findings.map(renderFinding).join("")}`
              : ""
          }

          ${
            chainFindings.length > 0
              ? `<h4>Findings de correlação (cadeia)</h4>${chainFindings.map(renderFinding).join("")}`
              : ""
          }

          ${
            chainNodes.length > 1
              ? `<h4>Cadeia (raiz → processo)</h4>${chainHtml}`
              : ""
          }

          ${
            p.chain && p.chain.has_orphan_root
              ? `<p><strong>⚠️ Raiz órfã:</strong> o processo pai não está mais na árvore (possível injeção ou parent spoofing).</p>`
              : ""
          }
        </div>
      </td>
    </tr>
  `;
}

// ---------------------------------------------------------------------------
// Página: Portas
// ---------------------------------------------------------------------------

function renderPortsPage(snap, idx) {
  const ports = snap.sockets?.listening ?? [];

  const tcp = ports.filter((p) => p.protocol === "tcp").length;
  const udp = ports.filter((p) => p.protocol === "udp").length;
  const flagged = ports.filter((p) => isPortFlagged(p, idx)).length;

  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  };
  set("portsTotal", ports.length);
  set("portsTcp", tcp);
  set("portsUdp", udp);
  set("portsFlagged", flagged);

  const container = document.getElementById("portsTable");
  if (!container) return;

  const list = portsFiltered(idx);
  const meta = document.getElementById("portsMeta");
  if (meta) {
    meta.textContent =
      list.length === ports.length
        ? `${ports.length} portas`
        : `${list.length} de ${ports.length}`;
  }

  if (list.length === 0) {
    container.innerHTML = `
      <div class="sec-empty">
        <span class="icon">🔌</span>
        <p>Nenhuma porta corresponde aos filtros atuais.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <table class="sec-table net-table">
      <thead>
        <tr>
          <th class="sortable" data-ports-sort="proto">Proto</th>
          <th class="sortable" data-ports-sort="pid">PID</th>
          <th class="sortable" data-ports-sort="addr">Endereço</th>
          <th class="sortable" data-ports-sort="port">Porta</th>
          <th>Alerta</th>
        </tr>
      </thead>
      <tbody>
        ${list
          .map((p) => {
            const flagged = isPortFlagged(p, idx);
            const cls = flagged ? "net-row flagged" : "net-row";
            const addrCls = addrClass(p.bind_addr);
            return `
              <tr class="${cls}">
                <td>${protoBadge(p.protocol)}</td>
                <td class="pid">${p.pid}</td>
                <td class="addr addr-${addrCls}">${esc(p.bind_addr)}</td>
                <td class="num">${p.port}</td>
                <td>${
                  flagged
                    ? `<span class="alert-badge" title="Porta alta incomum">⚠️</span>`
                    : "—"
                }</td>
              </tr>
            `;
          })
          .join("")}
      </tbody>
    </table>
  `;

  container.querySelectorAll("thead th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      state.ports.sort = th.dataset.portsSort;
      const sel = document.getElementById("portsSort");
      if (sel) sel.value = state.ports.sort;
      renderPortsPage(state.snapshot, findingsIndex(state.snapshot ?? {}));
    });
  });
}

function portsFiltered(idx) {
  const snap = state.snapshot;
  if (!snap?.sockets?.listening) return [];

  const { search, protocol, sort, onlyFlagged } = state.ports;
  const q = search.trim().toLowerCase();

  let list = snap.sockets.listening.slice();

  if (protocol) list = list.filter((p) => p.protocol === protocol);
  if (onlyFlagged) list = list.filter((p) => isPortFlagged(p, idx));
  if (q) {
    list = list.filter(
      (p) =>
        String(p.pid).includes(q) ||
        String(p.port).includes(q) ||
        p.bind_addr.toLowerCase().includes(q),
    );
  }

  switch (sort) {
    case "pid":
      list.sort((a, b) => a.pid - b.pid || a.port - b.port);
      break;
    case "addr":
      list.sort(
        (a, b) => a.bind_addr.localeCompare(b.bind_addr) || a.port - b.port,
      );
      break;
    case "proto":
      list.sort(
        (a, b) =>
          a.protocol.localeCompare(b.protocol) ||
          a.port - b.port ||
          a.pid - b.pid,
      );
      break;
    case "port":
    default:
      list.sort((a, b) => a.port - b.port || a.pid - b.pid);
      break;
  }

  return list;
}

// ---------------------------------------------------------------------------
// Página: Rede
// ---------------------------------------------------------------------------

function renderNetworkPage(snap, idx) {
  const conns = snap.sockets?.connections ?? [];

  const established = conns.filter((c) => c.state === "established").length;
  const publics = conns.filter(
    (c) => c.remote_addr && addrClass(c.remote_addr) === "public",
  ).length;
  const flagged = conns.filter((c) => isConnectionFlagged(c, idx)).length;

  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  };
  set("netTotal", conns.length);
  set("netEstablished", established);
  set("netPublic", publics);
  set("netFlagged", flagged);

  const container = document.getElementById("netTable");
  if (!container) return;

  const list = netFiltered(idx);
  const meta = document.getElementById("netMeta");
  if (meta) {
    meta.textContent =
      list.length === conns.length
        ? `${conns.length} conexões`
        : `${list.length} de ${conns.length}`;
  }

  if (list.length === 0) {
    container.innerHTML = `
      <div class="sec-empty">
        <span class="icon">🌐</span>
        <p>Nenhuma conexão corresponde aos filtros atuais.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <table class="sec-table net-table">
      <thead>
        <tr>
          <th class="sortable" data-net-sort="state">Estado</th>
          <th>Proto</th>
          <th class="sortable" data-net-sort="pid">PID</th>
          <th>Local</th>
          <th class="sortable" data-net-sort="remote_addr">Remoto</th>
          <th>Alerta</th>
        </tr>
      </thead>
      <tbody>
        ${list
          .map((c) => {
            const flagged = isConnectionFlagged(c, idx);
            const cls = flagged ? "net-row flagged" : "net-row";
            const remoteCls = c.remote_addr
              ? `addr-${addrClass(c.remote_addr)}`
              : "addr-unknown";
            return `
              <tr class="${cls}">
                <td>${stateBadge(c.state)}</td>
                <td>${protoBadge(c.protocol)}</td>
                <td class="pid">${c.pid}</td>
                <td class="addr">${fmtAddrPort(c.local_addr, c.local_port)}</td>
                <td class="addr ${remoteCls}">${
                  c.remote_addr
                    ? fmtAddrPort(c.remote_addr, c.remote_port)
                    : "—"
                }</td>
                <td>${
                  flagged
                    ? `<span class="alert-badge" title="Conexão externa incomum">⚠️</span>`
                    : "—"
                }</td>
              </tr>
            `;
          })
          .join("")}
      </tbody>
    </table>
  `;

  container.querySelectorAll("thead th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      state.net.sort = th.dataset.netSort;
      const sel = document.getElementById("netSort");
      if (sel) sel.value = state.net.sort;
      renderNetworkPage(state.snapshot, findingsIndex(state.snapshot ?? {}));
    });
  });
}

function netFiltered(idx) {
  const snap = state.snapshot;
  if (!snap?.sockets?.connections) return [];

  const { search, state: fstate, sort, onlyFlagged, onlyPublic } = state.net;
  const q = search.trim().toLowerCase();

  let list = snap.sockets.connections.slice();

  if (fstate) list = list.filter((c) => c.state === fstate);
  if (onlyFlagged) list = list.filter((c) => isConnectionFlagged(c, idx));
  if (onlyPublic) {
    list = list.filter(
      (c) => c.remote_addr && addrClass(c.remote_addr) === "public",
    );
  }
  if (q) {
    list = list.filter((c) => {
      const remote = c.remote_addr ?? "";
      const rport = c.remote_port ? String(c.remote_port) : "";
      return (
        String(c.pid).includes(q) ||
        c.local_addr.toLowerCase().includes(q) ||
        remote.toLowerCase().includes(q) ||
        String(c.local_port).includes(q) ||
        rport.includes(q)
      );
    });
  }

  switch (sort) {
    case "remote_port":
      list.sort(
        (a, b) => (a.remote_port ?? 0) - (b.remote_port ?? 0) || a.pid - b.pid,
      );
      break;
    case "state":
      list.sort((a, b) => a.state.localeCompare(b.state) || a.pid - b.pid);
      break;
    case "remote_addr":
      list.sort((a, b) => {
        const ra = a.remote_addr ?? "";
        const rb = b.remote_addr ?? "";
        return ra.localeCompare(rb) || a.pid - b.pid;
      });
      break;
    case "pid":
    default:
      list.sort(
        (a, b) => a.pid - b.pid || (a.remote_port ?? 0) - (b.remote_port ?? 0),
      );
      break;
  }

  return list;
}

// ---------------------------------------------------------------------------
// Controles
// ---------------------------------------------------------------------------

function wireControls() {
  // -- Hub -------------------------------------------------------------
  // (nada além dos links já no HTML)

  // -- Processos -------------------------------------------------------
  $("filterSearch")?.addEventListener("input", (e) => {
    state.filters.search = e.target.value;
    renderTable();
  });

  $("filterSeverity")?.addEventListener("change", (e) => {
    state.filters.severity = e.target.value;
    renderTable();
  });

  $("filterSort")?.addEventListener("change", (e) => {
    state.filters.sort = e.target.value;
    renderTable();
  });

  $("filterOnlyFlagged")?.addEventListener("change", (e) => {
    state.filters.onlyFlagged = e.target.checked;
    renderTable();
  });

  $("filterExpanded")?.addEventListener("change", (e) => {
    state.filters.expanded = e.target.checked;
    renderTable();
  });

  $$(".kpi[data-sev]").forEach((card) => {
    card.addEventListener("click", () => {
      const sev = card.dataset.sev;
      const sel = $("filterSeverity");
      if (!sel) return;
      sel.value = sel.value === sev ? "" : sev;
      state.filters.severity = sel.value;
      renderTable();
    });
  });

  // -- Portas ----------------------------------------------------------
  $("portsSearch")?.addEventListener("input", (e) => {
    state.ports.search = e.target.value;
    renderAll();
  });

  $("portsProtocol")?.addEventListener("change", (e) => {
    state.ports.protocol = e.target.value;
    renderAll();
  });

  $("portsSort")?.addEventListener("change", (e) => {
    state.ports.sort = e.target.value;
    renderAll();
  });

  $("portsOnlyFlagged")?.addEventListener("change", (e) => {
    state.ports.onlyFlagged = e.target.checked;
    renderAll();
  });

  $$(".kpi[data-ports-kpi]").forEach((card) => {
    card.addEventListener("click", () => {
      const v = card.dataset.portsKpi;
      const sel = $("portsProtocol");
      const onlyEl = $("portsOnlyFlagged");

      if (v === "__flagged__") {
        if (onlyEl) {
          onlyEl.checked = !onlyEl.checked;
          state.ports.onlyFlagged = onlyEl.checked;
        }
      } else {
        if (sel) {
          sel.value = sel.value === v ? "" : v;
          state.ports.protocol = sel.value;
        }
        if (onlyEl && onlyEl.checked) {
          onlyEl.checked = false;
          state.ports.onlyFlagged = false;
        }
      }
      renderAll();
    });
  });

  // -- Rede ------------------------------------------------------------
  $("netSearch")?.addEventListener("input", (e) => {
    state.net.search = e.target.value;
    renderAll();
  });

  $("netState")?.addEventListener("change", (e) => {
    state.net.state = e.target.value;
    renderAll();
  });

  $("netSort")?.addEventListener("change", (e) => {
    state.net.sort = e.target.value;
    renderAll();
  });

  $("netOnlyFlagged")?.addEventListener("change", (e) => {
    state.net.onlyFlagged = e.target.checked;
    renderAll();
  });

  $("netOnlyPublic")?.addEventListener("change", (e) => {
    state.net.onlyPublic = e.target.checked;
    renderAll();
  });

  $$(".kpi[data-net-kpi]").forEach((card) => {
    card.addEventListener("click", () => {
      const v = card.dataset.netKpi;
      const stateSel = $("netState");
      const onlyFlaggedEl = $("netOnlyFlagged");
      const onlyPublicEl = $("netOnlyPublic");

      if (v === "__flagged__") {
        if (onlyFlaggedEl) {
          onlyFlaggedEl.checked = !onlyFlaggedEl.checked;
          state.net.onlyFlagged = onlyFlaggedEl.checked;
        }
      } else if (v === "__public__") {
        if (onlyPublicEl) {
          onlyPublicEl.checked = !onlyPublicEl.checked;
          state.net.onlyPublic = onlyPublicEl.checked;
        }
      } else {
        if (stateSel) {
          stateSel.value = stateSel.value === v ? "" : v;
          state.net.state = stateSel.value;
        }
      }
      renderAll();
    });
  });

  // -- Topbar ----------------------------------------------------------
  $("btnRefresh")?.addEventListener("click", () => {
    toast("Atualizando…", "info");
    fetchSnapshot();
  });

  $("btnTheme")?.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("painel_theme", next);
    $("btnTheme").textContent = next === "dark" ? "🌙" : "☀️";
  });

  document.addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return;
    if (e.key === "r" || e.key === "R") $("btnRefresh")?.click();
  });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

function initTheme() {
  const t = localStorage.getItem("painel_theme") || "dark";
  document.documentElement.setAttribute("data-theme", t);
  const btn = document.getElementById("btnTheme");
  if (btn) btn.textContent = t === "dark" ? "🌙" : "☀️";
}

function initClock() {
  const el = document.getElementById("clock");
  if (!el) return;
  const tick = () => {
    el.textContent = new Date().toLocaleTimeString();
  };
  tick();
  setInterval(tick, 1000);
}

async function fetchSnapshot() {
  try {
    const res = await apiFetch("/api/security/snapshot");

    if (res.status === 503) return;
    if (!res.ok) {
      toast(`Erro HTTP ${res.status}`, "err");
      return;
    }

    state.snapshot = await res.json();
    state.lastUpdate = Date.now();
    renderAll();
  } catch (e) {
    console.warn("fetchSnapshot falhou:", e);
  }
}

function main() {
  initTheme();
  initClock();
  wireControls();
  fetchSnapshot();
  connectStream();

  setInterval(() => {
    if (state.learningRemainingSecs > 0) {
      state.learningRemainingSecs -= 1;
      updateLearningCountdown();
    }
  }, 1000);

  setInterval(() => {
    const age = Date.now() - state.lastUpdate;
    if (state.lastUpdate === 0 || age > 10000) {
      fetchSnapshot();
    }
  }, 5000);
}

main();
