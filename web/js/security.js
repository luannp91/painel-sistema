import "./utils/token-init.js";
import { apiFetch } from "./api/rest.js";
import { $$, esc } from "./utils/dom.js";

// `$` local: sempre getElementById. O `$` de utils/dom.js é querySelector
// (precisa de "#") — usar aqui quebrava todos os `$("algumId")`.
const $ = (id) => document.getElementById(id);

// ============================================================================
// Segurança — 5 páginas, um só script
// ============================================================================
//
// `data-page` no <html> define o que renderizar:
//   - "hub"       → cards de escolha com contadores ao vivo
//   - "processes" → KPIs, health, top, tabela completa
//   - "ports"     → KPIs, tabela de portas em escuta
//   - "network"   → KPIs, tabela de conexões ativas
//   - "findings"  → histórico persistido (REST, sem SSE)
//
// SSE entrega dois eventos:
//   - default    → SystemSnapshot   → health strip (só em "processes")
//   - "security" → SecuritySnapshot → todo o resto (exceto "findings")
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
  findings: {
    search: "",
    kind: "",
    severity: "",
    sort: "last_seen",
    onlyOutside: false,
    onlyHash: false,
  },
  findingsData: [],
  findingsEmpty: true,
  findingsLoadedAt: 0,
  expandedPids: new Set(),
  lastUpdate: 0,
  learningRemainingSecs: 0,
};

/// Rastreia transição `true → false` do aprendizado para disparar toast.
let previousLearning = null;

/// Evita re-fetch do resumo de findings a cada ciclo do SSE no hub.
let hubFindingsFetched = false;

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
  const el = $("toast");
  if (!el) return;
  el.textContent = msg;
  el.className = `toast show ${kind}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.className = "toast"), 3500);
}

function setStreamStatus(status, label) {
  const el = $("streamStatus");
  const lbl = $("streamLabel");
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

function setText(id, v) {
  const el = $(id);
  if (el) el.textContent = v;
}

/// "5s atrás", "3min atrás", "2d atrás", "1mo atrás".
function relativeTime(ms) {
  if (!ms) return "—";
  const diff = Date.now() - ms;
  if (diff < 0) return "agora";
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s atrás`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}min atrás`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h atrás`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d atrás`;
  const mo = Math.floor(d / 30);
  return `${mo}mo atrás`;
}

function shortHash(h) {
  if (!h) return null;
  return h.slice(0, 12);
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

// -- Célula de detecção ------------------------------------------------------
//
// `flagged` + `alert` vêm prontos do backend (engine marca cada socket
// que disparou finding). Sem parsing de texto, sem falso-positivo entre
// sockets irmãos do mesmo PID.

function detectionCellFromAlert(flagged, alert) {
  if (!flagged || !alert) return `<td class="detection-cell">—</td>`;
  return `
    <td class="detection-cell">
      <span class="alert-badge">⚠️</span>
      <span class="alert-detail" title="${esc(alert)}">${esc(alert)}</span>
    </td>
  `;
}

// ---------------------------------------------------------------------------
// Health strip — SystemSnapshot (evento default do SSE)
// ---------------------------------------------------------------------------

function renderHealth(snap) {
  const setBar = (id, pct) => {
    const el = $(id);
    if (!el) return;
    el.style.width = `${Math.min(100, pct).toFixed(1)}%`;
    el.className = `health-fill ${barClass(pct)}`;
  };

  const cpu = snap.cpu?.usage_percent ?? 0;
  setText("healthCpu", `${cpu.toFixed(1)}%`);
  setBar("healthCpuBar", cpu);

  const mem = snap.memory?.percent ?? 0;
  setText("healthMem", `${mem.toFixed(1)}%`);
  setBar("healthMemBar", mem);

  const disk = snap.disk?.percent ?? 0;
  setText("healthDisk", `${disk.toFixed(1)}%`);
  setBar("healthDiskBar", disk);

  setText("healthProcs", snap.processes?.count ?? "—");
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
    if (PAGE === "findings") return;
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
  if (PAGE === "findings") return;

  const snap = state.snapshot;
  if (!snap) return;

  if (PAGE !== "hub") {
    state.learningRemainingSecs = snap.learning_remaining_secs ?? 0;
    renderLearning(snap.learning);
  }

  switch (PAGE) {
    case "processes":
      renderProcessesPage(snap);
      break;
    case "ports":
      renderPortsPage(snap);
      break;
    case "network":
      renderNetworkPage(snap);
      break;
    case "hub":
    default:
      renderHub(snap);
      break;
  }
}

// ---------------------------------------------------------------------------
// Página: Hub
// ---------------------------------------------------------------------------

function renderHub(snap) {
  const processes = snap.processes ?? [];
  const ports = snap.sockets?.listening ?? [];
  const conns = snap.sockets?.connections ?? [];

  const alertProcesses =
    snap.counts.attention + snap.counts.suspicious + snap.counts.critical;
  const flaggedPorts = ports.filter((p) => p.flagged === true).length;
  const flaggedConns = conns.filter((c) => c.flagged === true).length;

  setHubStat("hubProcesses", processes.length, alertProcesses, "processos");
  setHubStat("hubPorts", ports.length, flaggedPorts, "portas");
  setHubStat("hubNetwork", conns.length, flaggedConns, "conexões");

  // Histórico: o card é alimentado por fetch REST, não pelo SSE.
  fetchFindingsSummary();
}

async function fetchFindingsSummary() {
  if (hubFindingsFetched) return;
  hubFindingsFetched = true;
  try {
    const res = await apiFetch("/api/security/findings?limit=1000");
    if (!res.ok) return;
    const data = await res.json();
    const total = data.count ?? 0;
    const critical = (data.findings || []).filter(
      (f) => f.max_severity === "critical",
    ).length;
    setHubStat("hubFindings", total, critical, "findings");
  } catch (e) {
    console.warn("fetchFindingsSummary falhou:", e);
  }
}

function setHubStat(id, total, alerts, unit) {
  const el = $(id);
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
  setText("kpiClean", snap.counts.clean);
  setText("kpiAttention", snap.counts.attention);
  setText("kpiSuspicious", snap.counts.suspicious);
  setText("kpiCritical", snap.counts.critical);

  setText("healthCycle", `${snap.elapsed_ms} ms`);

  const total = snap.processes.length;
  const alertas =
    snap.counts.attention + snap.counts.suspicious + snap.counts.critical;
  setText("secCount", `${alertas} com alerta`);
  setText("secMeta", `${total} processos analisados`);
  setText("secUpdated", `Atualizado às ${new Date().toLocaleTimeString()}`);

  renderTop(snap.processes);
  renderTable();
}

// ---------------------------------------------------------------------------
// Aprendizado (compartilhado entre sub-páginas)
// ---------------------------------------------------------------------------

function renderLearning(isLearning) {
  const banner = $("learningBanner");
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
  const el = $("learningRemaining");
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
// Top processos
// ---------------------------------------------------------------------------

function renderTop(processes) {
  const container = $("topProcesses");
  const meta = $("topMeta");
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
  const container = $("securityTable");
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
      const sel = $("filterSort");
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
            p.integrity_hash
              ? `<h4>Integridade</h4>
                 <div class="hash-row"><code class="hash-full">${esc(p.integrity_hash)}</code></div>`
              : ""
          }

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

function renderPortsPage(snap) {
  const ports = snap.sockets?.listening ?? [];

  const tcp = ports.filter((p) => p.protocol === "tcp").length;
  const udp = ports.filter((p) => p.protocol === "udp").length;
  const flagged = ports.filter((p) => p.flagged === true).length;

  setText("portsTotal", ports.length);
  setText("portsTcp", tcp);
  setText("portsUdp", udp);
  setText("portsFlagged", flagged);

  const container = $("portsTable");
  if (!container) return;

  const list = portsFiltered();
  const meta = $("portsMeta");
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
          <th>Detecção</th>
        </tr>
      </thead>
      <tbody>
        ${list
          .map((p) => {
            const cls = p.flagged ? "net-row flagged" : "net-row";
            const addrCls = addrClass(p.bind_addr);
            return `
              <tr class="${cls}">
                <td>${protoBadge(p.protocol)}</td>
                <td class="pid">${p.pid}</td>
                <td class="addr addr-${addrCls}">${esc(p.bind_addr)}</td>
                <td class="num">${p.port}</td>
                ${detectionCellFromAlert(p.flagged, p.alert)}
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
      const sel = $("portsSort");
      if (sel) sel.value = state.ports.sort;
      renderPortsPage(state.snapshot);
    });
  });
}

function portsFiltered() {
  const snap = state.snapshot;
  if (!snap?.sockets?.listening) return [];

  const { search, protocol, sort, onlyFlagged } = state.ports;
  const q = search.trim().toLowerCase();

  let list = snap.sockets.listening.slice();

  if (protocol) list = list.filter((p) => p.protocol === protocol);
  if (onlyFlagged) list = list.filter((p) => p.flagged === true);
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

function renderNetworkPage(snap) {
  const conns = snap.sockets?.connections ?? [];

  const established = conns.filter((c) => c.state === "established").length;
  const publics = conns.filter(
    (c) => c.remote_addr && addrClass(c.remote_addr) === "public",
  ).length;
  const flagged = conns.filter((c) => c.flagged === true).length;

  setText("netTotal", conns.length);
  setText("netEstablished", established);
  setText("netPublic", publics);
  setText("netFlagged", flagged);

  const container = $("netTable");
  if (!container) return;

  const list = netFiltered();
  const meta = $("netMeta");
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
          <th>Detecção</th>
        </tr>
      </thead>
      <tbody>
        ${list
          .map((c) => {
            const cls = c.flagged ? "net-row flagged" : "net-row";
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
                ${detectionCellFromAlert(c.flagged, c.alert)}
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
      const sel = $("netSort");
      if (sel) sel.value = state.net.sort;
      renderNetworkPage(state.snapshot);
    });
  });
}

function netFiltered() {
  const snap = state.snapshot;
  if (!snap?.sockets?.connections) return [];

  const { search, state: fstate, sort, onlyFlagged, onlyPublic } = state.net;
  const q = search.trim().toLowerCase();

  let list = snap.sockets.connections.slice();

  if (fstate) list = list.filter((c) => c.state === fstate);
  if (onlyFlagged) list = list.filter((c) => c.flagged === true);
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
// Página: Histórico de Findings (REST)
// ---------------------------------------------------------------------------

async function fetchFindings() {
  try {
    const res = await apiFetch("/api/security/findings?limit=1000");
    if (!res.ok) {
      toast(`Erro HTTP ${res.status}`, "err");
      return;
    }
    const data = await res.json();
    state.findingsData = data.findings || [];
    state.findingsEmpty = data.empty ?? false;
    state.findingsLoadedAt = Date.now();
    renderFindingsPage();
  } catch (e) {
    console.warn("fetchFindings falhou:", e);
    toast("Falha ao carregar histórico", "err");
  }
}

function findingsFiltered() {
  const { search, kind, severity, sort, onlyOutside, onlyHash } =
    state.findings;
  const q = search.trim().toLowerCase();

  const sevRank = { clean: 0, attention: 1, suspicious: 2, critical: 3 };
  const minRank = severity ? (sevRank[severity] ?? 0) : 0;

  let list = state.findingsData.slice();

  if (kind) list = list.filter((f) => f.kind === kind);
  if (minRank > 0) {
    list = list.filter((f) => (sevRank[f.max_severity] ?? 0) >= minRank);
  }
  if (onlyOutside) list = list.filter((f) => f.seen_outside_learning);
  if (onlyHash) list = list.filter((f) => !!f.integrity_hash);
  if (q) {
    list = list.filter(
      (f) =>
        f.name.toLowerCase().includes(q) ||
        f.exe_path.toLowerCase().includes(q) ||
        f.detail.toLowerCase().includes(q),
    );
  }

  switch (sort) {
    case "first_seen":
      list.sort((a, b) => b.first_seen_ms - a.first_seen_ms);
      break;
    case "occurrences":
      list.sort((a, b) => b.occurrences - a.occurrences);
      break;
    case "score":
      list.sort((a, b) => b.max_score_seen - a.max_score_seen);
      break;
    case "name":
      list.sort((a, b) => a.name.localeCompare(b.name));
      break;
    case "last_seen":
    default:
      list.sort((a, b) => b.last_seen_ms - a.last_seen_ms);
      break;
  }

  return list;
}

function renderFindingsPage() {
  const all = state.findingsData;

  const total = all.length;
  const critical = all.filter((f) => f.max_severity === "critical").length;
  const outside = all.filter((f) => f.seen_outside_learning).length;
  const obs = all.reduce((acc, f) => acc + (f.occurrences || 0), 0);

  setText("findingsTotal", total);
  setText("findingsCritical", critical);
  setText("findingsOutside", outside);
  setText("findingsObs", obs);

  if (all.length > 0) {
    const oldest = Math.min(...all.map((f) => f.first_seen_ms));
    const newest = Math.max(...all.map((f) => f.last_seen_ms));
    setText(
      "findingsRange",
      `primeiro ${relativeTime(oldest)} · último ${relativeTime(newest)}`,
    );
  } else {
    setText("findingsRange", "—");
  }

  setText("findingsUpdated", `Carregado às ${new Date().toLocaleTimeString()}`);

  const container = $("findingsTable");
  if (!container) return;

  if (state.findingsEmpty && all.length === 0) {
    container.innerHTML = `
      <div class="sec-empty">
        <span class="icon">💾</span>
        <p>Persistência desabilitada ou tabela vazia. Habilite <code>[database]</code> no <code>config.toml</code>.</p>
      </div>
    `;
    setText("findingsMeta", "—");
    return;
  }

  const list = findingsFiltered();
  const meta = $("findingsMeta");
  if (meta) {
    meta.textContent =
      list.length === total
        ? `${total} findings`
        : `${list.length} de ${total}`;
  }

  if (list.length === 0) {
    container.innerHTML = `
      <div class="sec-empty">
        <span class="icon">📚</span>
        <p>Nenhum finding corresponde aos filtros atuais.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <table class="sec-table findings-table">
      <thead>
        <tr>
          <th>Severidade</th>
          <th>Tipo</th>
          <th>Nome</th>
          <th class="hide-sm">Caminho</th>
          <th class="num">Ocorr.</th>
          <th>Última vez</th>
          <th class="num hide-sm">Score</th>
          <th class="hide-sm">Hash</th>
        </tr>
      </thead>
      <tbody>
        ${list
          .map((f) => {
            const sevCls = `sev-${f.max_severity}`;
            const hash = shortHash(f.integrity_hash);
            const outside = f.seen_outside_learning
              ? ""
              : ` <span class="learning-pill" title="Visto só durante o aprendizado">🎓</span>`;
            return `
              <tr class="findings-row" title="${esc(f.detail)}">
                <td>
                  <span class="sev-badge ${sevCls}">${sevLabel(f.max_severity)}</span>
                </td>
                <td><span class="kind-badge">${esc(f.kind)}</span></td>
                <td>${esc(f.name)}${outside}</td>
                <td class="path-cell hide-sm" title="${esc(f.exe_path)}">${esc(f.exe_path || "—")}</td>
                <td class="num">${f.occurrences}</td>
                <td class="time-cell" title="${new Date(f.last_seen_ms).toLocaleString()}">${relativeTime(f.last_seen_ms)}</td>
                <td class="num hide-sm">${f.max_score_seen}</td>
                <td class="hash-cell hide-sm" title="${f.integrity_hash ? esc(f.integrity_hash) : "sem hash"}">${hash ? esc(hash) : "—"}</td>
              </tr>
            `;
          })
          .join("")}
      </tbody>
    </table>
  `;
}

// ---------------------------------------------------------------------------
// Controles
// ---------------------------------------------------------------------------

function wireControls() {
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

  // -- Histórico de findings -------------------------------------------
  $("findingsSearch")?.addEventListener("input", (e) => {
    state.findings.search = e.target.value;
    renderFindingsPage();
  });

  $("findingsKind")?.addEventListener("change", (e) => {
    state.findings.kind = e.target.value;
    renderFindingsPage();
  });

  $("findingsSeverity")?.addEventListener("change", (e) => {
    state.findings.severity = e.target.value;
    renderFindingsPage();
  });

  $("findingsSort")?.addEventListener("change", (e) => {
    state.findings.sort = e.target.value;
    renderFindingsPage();
  });

  $("findingsOnlyOutside")?.addEventListener("change", (e) => {
    state.findings.onlyOutside = e.target.checked;
    renderFindingsPage();
  });

  $("findingsOnlyHash")?.addEventListener("change", (e) => {
    state.findings.onlyHash = e.target.checked;
    renderFindingsPage();
  });

  $$(".kpi[data-findings-kpi]").forEach((card) => {
    card.addEventListener("click", () => {
      const v = card.dataset.findingsKpi;
      const sevSel = $("findingsSeverity");
      const outsideEl = $("findingsOnlyOutside");

      if (v === "__outside__") {
        if (outsideEl) {
          outsideEl.checked = !outsideEl.checked;
          state.findings.onlyOutside = outsideEl.checked;
        }
      } else if (v === "critical") {
        if (sevSel) {
          sevSel.value = sevSel.value === "critical" ? "" : "critical";
          state.findings.severity = sevSel.value;
        }
      }
      renderFindingsPage();
    });
  });

  // -- Topbar ----------------------------------------------------------
  $("btnRefresh")?.addEventListener("click", () => {
    toast("Atualizando…", "info");
    if (PAGE === "findings") {
      fetchFindings();
    } else {
      fetchSnapshot();
    }
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
  const btn = $("btnTheme");
  if (btn) btn.textContent = t === "dark" ? "🌙" : "☀️";
}

function initClock() {
  const el = $("clock");
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

/// Atualiza todos os `<span class="version">` com a versão do binário.
/// Roda em toda página que carrega este módulo.
async function loadVersion() {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) return;
    const data = await res.json();
    const v = data.version ? `v${data.version}` : "—";
    document.querySelectorAll(".version").forEach((el) => {
      el.textContent = v;
    });
  } catch (e) {
    console.warn("loadVersion falhou:", e);
  }
}

function main() {
  initTheme();
  initClock();
  wireControls();
  loadVersion();

  if (PAGE === "findings") {
    setStreamStatus("", "estático");
    fetchFindings();
  } else {
    fetchSnapshot();
    connectStream();
  }

  setInterval(() => {
    if (state.learningRemainingSecs > 0) {
      state.learningRemainingSecs -= 1;
      updateLearningCountdown();
    }
  }, 1000);

  if (PAGE !== "findings") {
    setInterval(() => {
      const age = Date.now() - state.lastUpdate;
      if (state.lastUpdate === 0 || age > 10000) {
        fetchSnapshot();
      }
    }, 5000);
  }

  if (PAGE === "findings") {
    setInterval(fetchFindings, 60_000);
  }
}

main();
