/* =========================================================
   Página de processos com ação de kill
   ========================================================= */

import { $ } from "./utils/dom.js";
import { apiFetch } from "./api/rest.js";
import { showToast } from "./ui/toast.js";
import { initTheme } from "./ui/theme.js";
import { startClock } from "./ui/clock.js";

let allProcs = [];
let filtered = [];
let sortKey = "memory_bytes";
let sortAsc = false;
let autoTimer = null;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

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

function fmtBytes(n) {
  if (n === undefined || n === null || isNaN(n)) return "—";
  if (n === 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

function fmtUptime(sec) {
  if (!sec && sec !== 0) return "—";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

/* ------------------------------------------------------------------ */
/* Filtro + ordenação                                                  */
/* ------------------------------------------------------------------ */

function applyFilters() {
  const search = ($("#filterSearch")?.value || "").toLowerCase().trim();
  const user = $("#filterUser")?.value || "";

  filtered = allProcs.filter((p) => {
    if (user && p.user !== user) return false;
    if (search) {
      const hay =
        `${p.name} ${p.pid} ${p.user || ""} ${p.exe || ""}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  // Ordena
  const numeric = sortKey !== "name";
  filtered.sort((a, b) => {
    let av = a[sortKey] ?? (numeric ? 0 : "");
    let bv = b[sortKey] ?? (numeric ? 0 : "");

    if (numeric) {
      return sortAsc ? av - bv : bv - av;
    }
    return sortAsc
      ? String(av).localeCompare(String(bv))
      : String(bv).localeCompare(String(av));
  });

  render();
}

/* ------------------------------------------------------------------ */
/* Renderização                                                        */
/* ------------------------------------------------------------------ */

function render() {
  const container = $("#processesTable");
  if (!container) return;

  if (!filtered.length) {
    container.innerHTML = `<div class="event-empty">
      Nenhum processo ${allProcs.length ? "corresponde aos filtros" : "disponível"}.
    </div>`;
    updateMeta();
    return;
  }

  const rows = filtered
    .map((p) => {
      const cpu = p.cpu_percent ?? 0;
      const cpuCls = cpu > 50 ? "hi" : cpu > 10 ? "mid" : "lo";
      const isCritical = p.pid === 0 || p.pid === 4;

      return `
        <div class="proc-row" data-pid="${p.pid}">
          <span class="proc-pid">${p.pid}</span>
          <span class="proc-name" title="${esc(p.exe || p.name)}">${esc(p.name)}</span>
          <span class="proc-user">${esc(p.user || "—")}</span>
          <span class="proc-mem">${fmtBytes(p.memory_bytes)}</span>
          <span class="proc-cpu ${cpuCls}">${cpu.toFixed(1)}%</span>
          <span class="proc-status" title="${esc(p.status)}">${esc(p.status)}</span>
          <span class="proc-actions">
            <button
              class="proc-kill"
              data-pid="${p.pid}"
              data-name="${esc(p.name)}"
              ${isCritical ? 'disabled title="Processo crítico do sistema"' : ""}
            >✕ Matar</button>
          </span>
        </div>
      `;
    })
    .join("");

  const arrowCls = (key) =>
    sortKey === key ? (sortAsc ? "sorted asc" : "sorted") : "";

  container.innerHTML = `
    <div class="proc-header">
      <span data-sort="pid" class="${arrowCls("pid")}" style="text-align:right">PID</span>
      <span data-sort="name" class="${arrowCls("name")}">Nome</span>
      <span data-sort="user" class="${arrowCls("user")}">Usuário</span>
      <span data-sort="memory_bytes" class="${arrowCls("memory_bytes")}" style="text-align:right">RAM</span>
      <span data-sort="cpu_percent" class="${arrowCls("cpu_percent")}" style="text-align:right">CPU</span>
      <span data-sort="status" class="${arrowCls("status")}">Status</span>
      <span>Ações</span>
    </div>
    ${rows}
  `;

  // Cliques no cabeçalho → ordenar
  container.querySelectorAll(".proc-header span[data-sort]").forEach((el) => {
    el.addEventListener("click", () => {
      const key = el.dataset.sort;
      if (sortKey === key) {
        sortAsc = !sortAsc;
      } else {
        sortKey = key;
        sortAsc = key === "name" || key === "user" || key === "status";
      }
      applyFilters();
    });
  });

  // Botões de kill
  container.querySelectorAll(".proc-kill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pid = parseInt(btn.dataset.pid, 10);
      const name = btn.dataset.name;
      killProcess(pid, name, btn);
    });
  });

  updateMeta();
}

function updateMeta() {
  const countEl = $("#procCount");
  const updatedEl = $("#procUpdated");

  if (countEl) {
    const total =
      allProcs.length === filtered.length
        ? `${allProcs.length} processos`
        : `${filtered.length} de ${allProcs.length}`;
    countEl.textContent = total;
  }

  if (updatedEl) {
    updatedEl.textContent = `Atualizado às ${new Date().toLocaleTimeString("pt-BR")}`;
  }
}

/* ------------------------------------------------------------------ */
/* Kill                                                                */
/* ------------------------------------------------------------------ */

async function killProcess(pid, name, btn) {
  const ok = confirm(
    `Encerrar o processo "${name}" (PID ${pid})?\n\n` +
      `⚠️ Isso pode causar perda de dados se o processo estiver salvando algo.`,
  );
  if (!ok) return;

  btn.disabled = true;
  btn.textContent = "…";

  try {
    const res = await apiFetch(`/api/processes/${pid}/kill`, {
      method: "POST",
    });
    const data = await res.json().catch(() => ({}));

    if (res.ok && data.status === "ok") {
      showToast(`✅ "${name}" (PID ${pid}) encerrado`);
      // Remove da lista local e re-renderiza imediatamente
      allProcs = allProcs.filter((p) => p.pid !== pid);
      applyFilters();
    } else {
      showToast(`❌ ${data.message || "Falha ao encerrar"}`);
      btn.disabled = false;
      btn.textContent = "✕ Matar";
    }
  } catch (err) {
    console.error("[processes] kill erro:", err);
    showToast("❌ Erro de rede ao encerrar processo");
    btn.disabled = false;
    btn.textContent = "✕ Matar";
  }
}

/* ------------------------------------------------------------------ */
/* Carregamento                                                        */
/* ------------------------------------------------------------------ */

async function loadProcesses(showSpinner = false) {
  const container = $("#processesTable");

  if (showSpinner && container && !allProcs.length) {
    container.innerHTML = `
      <div class="loading">
        <div class="spinner"></div>
        <p>Carregando processos…</p>
      </div>`;
  }

  try {
    const res = await apiFetch("/api/processes");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    allProcs = await res.json();
    if (!Array.isArray(allProcs)) allProcs = [];

    populateUserFilter();
    applyFilters();
  } catch (err) {
    console.error("[processes] erro:", err);
    if (container) {
      container.innerHTML = `<div class="event-empty">
        ❌ Não foi possível carregar os processos.<br>
        <small>${esc(err.message)}</small>
      </div>`;
    }
  }
}

function populateUserFilter() {
  const sel = $("#filterUser");
  if (!sel) return;

  const current = sel.value;
  const users = [
    ...new Set(allProcs.map((p) => p.user).filter(Boolean)),
  ].sort();

  const html = ['<option value="">Todos os usuários</option>']
    .concat(users.map((u) => `<option value="${esc(u)}">${esc(u)}</option>`))
    .join("");

  sel.innerHTML = html;
  if (users.includes(current)) sel.value = current;
}

/* ------------------------------------------------------------------ */
/* Bootstrap                                                           */
/* ------------------------------------------------------------------ */

function startAutoRefresh() {
  stopAutoRefresh();
  autoTimer = setInterval(() => loadProcesses(false), 5000);
}

function stopAutoRefresh() {
  if (autoTimer) {
    clearInterval(autoTimer);
    autoTimer = null;
  }
}

function init() {
  initTheme();
  startClock();

  $("#btnRefresh")?.addEventListener("click", () => {
    loadProcesses(false);
    showToast("🔄 Atualizando processos…", 800);
  });

  $("#filterSearch")?.addEventListener("input", applyFilters);
  $("#filterUser")?.addEventListener("change", applyFilters);

  $("#filterSort")?.addEventListener("change", (e) => {
    const val = e.target.value;
    const map = {
      memory_bytes: { key: "memory_bytes", asc: false },
      cpu_percent: { key: "cpu_percent", asc: false },
      name: { key: "name", asc: true },
      pid: { key: "pid", asc: true },
      run_time_seconds: { key: "run_time_seconds", asc: false },
    };
    const cfg = map[val];
    if (cfg) {
      sortKey = cfg.key;
      sortAsc = cfg.asc;
      applyFilters();
    }
  });

  $("#autoRefresh")?.addEventListener("change", (e) => {
    if (e.target.checked) startAutoRefresh();
    else stopAutoRefresh();
  });

  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    if (e.key === "r" || e.key === "R") loadProcesses(false);
    if (e.key === "f" || e.key === "F") $("#filterSearch")?.focus();
  });

  loadProcesses(true);
  startAutoRefresh();
}

document.addEventListener("DOMContentLoaded", init);
