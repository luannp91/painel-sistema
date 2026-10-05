// ============================================================================
// Segurança — consumo de /api/security/snapshot + SSE 'event: security'
// ============================================================================
//
// Self-contained: sem imports de api/rest.js pra não acoplar a convenções
// internas do projeto. Se o projeto já tem um wrapper de token, é uma
// linha pra trocar em `readToken()`.

const TOKEN_KEY = "painel_token"; // ajuste aqui se a chave real for outra

// ---------------------------------------------------------------------------
// Estado
// ---------------------------------------------------------------------------

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
  expandedPids: new Set(),
  lastUpdate: 0,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readToken() {
  const t = localStorage.getItem(TOKEN_KEY) ?? localStorage.getItem("token");
  if (t) return t;
  const prompted = prompt(
    "Token de autenticação (config.toml → [auth] token):",
    "",
  );
  if (prompted) {
    localStorage.setItem(TOKEN_KEY, prompted);
    return prompted;
  }
  return null;
}

function esc(s) {
  return String(s).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c],
  );
}

function sevClass(sev) {
  switch (sev) {
    case "clean":
      return "sev-clean";
    case "attention":
      return "sev-attention";
    case "suspicious":
      return "sev-suspicious";
    case "critical":
      return "sev-critical";
    default:
      return "sev-clean";
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
  el._t = setTimeout(() => (el.className = "toast"), 2800);
}

function setStreamStatus(status, label) {
  const el = document.getElementById("streamStatus");
  const lbl = document.getElementById("streamLabel");
  if (!el || !lbl) return;
  el.className = `live-indicator${status ? ` ${status}` : ""}`;
  lbl.textContent = label;
}

// ---------------------------------------------------------------------------
// Fetch inicial + SSE
// ---------------------------------------------------------------------------

async function fetchSnapshot() {
  const token = readToken();
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const res = await fetch("/api/security/snapshot", { headers });
    if (res.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      toast("Token inválido — recarregue e informe de novo", "err");
      return;
    }
    if (res.status === 503) {
      // publisher ainda não rodou o primeiro ciclo
      return;
    }
    if (!res.ok) {
      toast(`Erro HTTP ${res.status}`, "err");
      return;
    }
    const snap = await res.json();
    applySnapshot(snap);
  } catch (e) {
    console.warn("fetchSnapshot falhou:", e);
  }
}

function connectStream() {
  const token = readToken();
  const url = token
    ? `/api/stream?token=${encodeURIComponent(token)}`
    : "/api/stream";

  try {
    state.es = new EventSource(url);
  } catch (e) {
    setStreamStatus("offline", "offline");
    return;
  }

  state.es.addEventListener("open", () => {
    setStreamStatus("", "ao vivo");
  });

  // Só evento nomeado 'security' — não interfere no onmessage que o
  // resto da aplicação usa pro SystemSnapshot.
  state.es.addEventListener("security", (e) => {
    try {
      const snap = JSON.parse(e.data);
      applySnapshot(snap);
    } catch (err) {
      console.warn("parse security SSE falhou:", err);
    }
  });

  state.es.addEventListener("error", () => {
    setStreamStatus("stale", "reconectando…");
    // EventSource reconecta sozinho; se ficar offline >10s, marca offline.
    setTimeout(() => {
      if (state.es && state.es.readyState !== EventSource.OPEN) {
        setStreamStatus("offline", "offline");
      }
    }, 10000);
  });
}

// ---------------------------------------------------------------------------
// Aplicar snapshot + render
// ---------------------------------------------------------------------------

function applySnapshot(snap) {
  state.snapshot = snap;
  state.lastUpdate = Date.now();
  renderAll();
}

function renderAll() {
  const snap = state.snapshot;
  if (!snap) return;

  // Cards de resumo
  document.getElementById("countClean").textContent = snap.counts.clean;
  document.getElementById("countAttention").textContent = snap.counts.attention;
  document.getElementById("countSuspicious").textContent =
    snap.counts.suspicious;
  document.getElementById("countCritical").textContent = snap.counts.critical;
  document.getElementById("cycleMeta").textContent = `${snap.elapsed_ms} ms`;

  // Banner de aprendizado
  document.getElementById("learningBanner").hidden = !snap.learning;

  // Contadores meta
  const total = snap.processes.length;
  document.getElementById("secCount").textContent =
    `${total} processos analisados · ${snap.counts.attention + snap.counts.suspicious + snap.counts.critical} com alerta`;
  document.getElementById("secUpdated").textContent =
    `Atualizado às ${new Date().toLocaleTimeString()}`;

  renderTable();
}

function processFiltered() {
  const snap = state.snapshot;
  if (!snap) return [];

  const { search, severity, sort, onlyFlagged } = state.filters;
  const q = search.trim().toLowerCase();

  let list = snap.processes.slice();

  if (onlyFlagged) {
    list = list.filter((p) => p.final_score > 0);
  }
  if (severity) {
    list = list.filter((p) => p.severity === severity);
  }
  if (q) {
    list = list.filter((p) => {
      return String(p.pid).includes(q) || p.name.toLowerCase().includes(q);
    });
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
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;

  // Delegação: click na linha → toggle detalhe; click no th → sort.
  container.querySelectorAll("thead th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      state.filters.sort = th.dataset.sort;
      document.getElementById("filterSort").value = state.filters.sort;
      renderTable();
    });
  });

  container.querySelectorAll("tbody tr.sec-row").forEach((tr) => {
    tr.addEventListener("click", (ev) => {
      // Não expande se clicou num link/botão
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
  const sev = sevClass(p.severity);
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
    <tr class="sec-row ${sev}" data-pid="${p.pid}">
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
// Filtros + ações
// ---------------------------------------------------------------------------

function wireControls() {
  const $ = (id) => document.getElementById(id);

  $("filterSearch").addEventListener("input", (e) => {
    state.filters.search = e.target.value;
    renderTable();
  });

  $("filterSeverity").addEventListener("change", (e) => {
    state.filters.severity = e.target.value;
    renderTable();
  });

  $("filterSort").addEventListener("change", (e) => {
    state.filters.sort = e.target.value;
    renderTable();
  });

  $("filterOnlyFlagged").addEventListener("change", (e) => {
    state.filters.onlyFlagged = e.target.checked;
    renderTable();
  });

  $("filterExpanded").addEventListener("change", (e) => {
    state.filters.expanded = e.target.checked;
    renderTable();
  });

  document.querySelectorAll(".summary-card[data-sev]").forEach((card) => {
    card.addEventListener("click", () => {
      const sev = card.dataset.sev;
      const sel = $("filterSeverity");
      sel.value = sel.value === sev ? "" : sev;
      state.filters.severity = sel.value;
      renderTable();
    });
  });

  $("btnRefresh").addEventListener("click", () => {
    toast("Atualizando…", "info");
    fetchSnapshot();
  });

  // Tema
  $("btnTheme").addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("painel_theme", next);
    $("btnTheme").textContent = next === "dark" ? "🌙" : "☀️";
  });

  // Atalhos
  document.addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return;
    if (e.key === "r" || e.key === "R") $("btnRefresh").click();
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

function main() {
  initTheme();
  initClock();
  wireControls();
  fetchSnapshot();
  connectStream();

  // Se o SSE não mandar nada em 10s, faz polling de fallback.
  setInterval(() => {
    const age = Date.now() - state.lastUpdate;
    if (state.lastUpdate === 0 || age > 10000) {
      fetchSnapshot();
    }
  }, 5000);
}

main();
