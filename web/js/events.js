/* =========================================================
   Página de eventos do sistema
   ========================================================= */

import { $ } from "./utils/dom.js";
import { showToast } from "./ui/toast.js";
import { initTheme } from "./ui/theme.js";
import { startClock } from "./ui/clock.js";
import { apiFetch } from "./api/rest.js";

let allEvents = [];
let filtered = [];

/* ------------------------------------------------------------------ */
/* Formatação                                                          */
/* ------------------------------------------------------------------ */

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
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

function normalizeLevel(raw) {
  if (!raw) return "Information";
  const s = String(raw).trim().toLowerCase();
  if (
    [
      "error",
      "erro",
      "crítico",
      "critico",
      "critical",
      "critical error",
    ].includes(s)
  )
    return "Error";
  if (["warning", "aviso", "alerta", "advertencia"].includes(s))
    return "Warning";
  if (
    ["information", "informação", "informacao", "info", "informativo"].includes(
      s,
    )
  )
    return "Information";
  if (["verbose", "detalhado", "detalhe"].includes(s)) return "Verbose";
  return "Information";
}

/* ------------------------------------------------------------------ */
/* Filtros                                                             */
/* ------------------------------------------------------------------ */

function applyFilters() {
  const level = $("#filterLevel")?.value || "";
  const search = ($("#filterSearch")?.value || "").toLowerCase().trim();

  filtered = allEvents.filter((e) => {
    const lvl = normalizeLevel(e.level);
    if (level && lvl !== level) return false;
    if (search) {
      const haystack = `${e.source} ${e.message} ${e.id}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  render();
}

/* ------------------------------------------------------------------ */
/* Renderização                                                        */
/* ------------------------------------------------------------------ */

function render() {
  const container = $("#eventsTable");
  if (!container) return;

  if (!filtered.length) {
    container.innerHTML = `<div class="event-empty">
      Nenhum evento ${allEvents.length ? "corresponde aos filtros" : "disponível"}.
    </div>`;
    updateMeta();
    return;
  }

  const rows = filtered
    .map((e, i) => {
      const level = normalizeLevel(e.level);
      return `
        <div class="event-row collapsed" data-idx="${i}" data-level="${esc(level)}">
          <span class="event-time">${esc(fmtTime(e.time))}</span>
          <span class="event-level ${esc(level)}">${esc(level)}</span>
          <span class="event-source" title="${esc(e.source)}">${esc(e.source || "—")}</span>
          <span class="event-id">${e.id || "—"}</span>
          <span class="event-message" title="Clique para expandir">${esc(e.message || "—")}</span>
        </div>`;
    })
    .join("");

  container.innerHTML = `
    <div class="events-header">
      <span>Data/Hora</span>
      <span>Nível</span>
      <span>Origem</span>
      <span>ID</span>
      <span>Mensagem</span>
    </div>
    ${rows}
  `;

  container.querySelectorAll(".event-message").forEach((el) => {
    el.addEventListener("click", () => {
      const row = el.closest(".event-row");
      row?.classList.toggle("collapsed");
    });
  });

  updateMeta();
}

function updateMeta() {
  const countEl = $("#eventsCount");
  const updatedEl = $("#eventsUpdated");

  const counts = { Error: 0, Warning: 0, Information: 0, Other: 0 };
  for (const e of filtered) {
    const lvl = normalizeLevel(e.level);
    if (lvl === "Error") counts.Error++;
    else if (lvl === "Warning") counts.Warning++;
    else if (lvl === "Information") counts.Information++;
    else counts.Other++;
  }

  if (countEl) {
    const total =
      allEvents.length === filtered.length
        ? `${allEvents.length} eventos`
        : `${filtered.length} de ${allEvents.length}`;

    countEl.innerHTML = `
      <span>${total}</span>
      <span class="count-badge error" title="Erros">🔴 ${counts.Error}</span>
      <span class="count-badge warn"  title="Avisos">🟡 ${counts.Warning}</span>
      <span class="count-badge info"  title="Informações">🔵 ${counts.Information}</span>
    `;
  }

  if (updatedEl) {
    updatedEl.textContent = `Atualizado às ${new Date().toLocaleTimeString("pt-BR")}`;
  }
}

/* ------------------------------------------------------------------ */
/* Carregamento                                                        */
/* ------------------------------------------------------------------ */

async function loadEvents(showSpinner = false) {
  const container = $("#eventsTable");
  const limit = $("#filterLimit")?.value || "100";

  if (showSpinner && container) {
    container.innerHTML = `
      <div class="loading">
        <div class="spinner"></div>
        <p>Carregando eventos do sistema…</p>
      </div>`;
  }

  try {
    const res = await apiFetch(`/api/events?limit=${limit}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    allEvents = await res.json();

    if (!Array.isArray(allEvents)) allEvents = [];
    applyFilters();
  } catch (err) {
    console.error("[events] erro:", err);
    if (container) {
      container.innerHTML = `<div class="event-empty">
        ❌ Não foi possível carregar os eventos.<br>
        <small>${esc(err.message)}</small>
      </div>`;
    }
    showToast("❌ Falha ao carregar eventos");
  }
}

/* ------------------------------------------------------------------ */
/* Bootstrap                                                           */
/* ------------------------------------------------------------------ */

function init() {
  initTheme();
  startClock();

  $("#btnRefresh")?.addEventListener("click", () => {
    loadEvents(false);
    showToast("🔄 Atualizando eventos…", 1200);
  });

  $("#filterLevel")?.addEventListener("change", applyFilters);
  $("#filterSearch")?.addEventListener("input", applyFilters);

  $("#filterLimit")?.addEventListener("change", () => {
    loadEvents(true);
  });

  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    if (e.key === "r" || e.key === "R") loadEvents(false);
    if (e.key === "f" || e.key === "F") $("#filterSearch")?.focus();
  });

  loadEvents(true);
  setInterval(() => loadEvents(false), 30000);
}

document.addEventListener("DOMContentLoaded", init);
