/* =========================================================
   Página de Padrões Detectados
   Dois modos: ao vivo (memória, últimos minutos) e histórico
   (SQLite, retenção de 90 dias).
   ========================================================= */

import { $, $$ } from "./utils/dom.js";
import { showToast } from "./ui/toast.js";
import { initTheme } from "./ui/theme.js";
import { startClock } from "./ui/clock.js";
import { apiFetch } from "./api/rest.js";
import "./ui/version.js";
import "./utils/token-init.js";

const state = {
  mode: "live", // "live" | "history"
  allPatterns: [],
  filtered: [],
  history: [], // samples em memória, só no modo live
  lastPayload: null,
};

const ACTIVE_WINDOW_MS = 60_000;

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

function pad2(n) {
  return String(n).padStart(2, "0");
}

function fmtTime(ms) {
  const d = new Date(ms);
  return `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

function fmtDuration(fromMs, toMs) {
  const s = Math.max(0, Math.round((toMs - fromMs) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r ? `${m}min ${r}s` : `${m}min`;
}

/// "há 3h", "há 2d" — usado no modo histórico pra dar contexto.
function relTime(ms) {
  if (!ms) return "—";
  const diff = Date.now() - ms;
  if (diff < 0) return "agora";
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s atrás`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}min atrás`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h atrás`;
  const d = Math.floor(h / 24);
  return `${d}d atrás`;
}

function isActive(p, now) {
  return now - p.last_detected_ms < ACTIVE_WINDOW_MS;
}

/* ------------------------------------------------------------------ */
/* Modo                                                                */
/* ------------------------------------------------------------------ */

function setMode(mode) {
  if (mode !== "live" && mode !== "history") return;
  state.mode = mode;

  $$(".mode-btn").forEach((btn) => {
    const active = btn.dataset.mode === mode;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });

  const chartWrap = $("#chartWrap");
  const note = $("#historyNote");
  const hint = $("#modeHint");
  const labelActiveOnly = $("#labelActiveOnly");
  const labelActive = $("#labelActive");
  const labelTotal = $("#labelTotal");

  if (mode === "history") {
    if (chartWrap) chartWrap.hidden = true;
    if (note) note.hidden = false;
    if (hint) hint.textContent = "Persistido em SQLite — retenção de 90 dias";
    if (labelActiveOnly) labelActiveOnly.hidden = true;
    if (labelActive) labelActive.textContent = "Últimos 7 dias";
    if (labelTotal) labelTotal.textContent = "Total histórico (90d)";
    // Desabilita o filtro "apenas ativos" (não faz sentido no histórico).
    const activeOnlyEl = $("#filterActiveOnly");
    if (activeOnlyEl) {
      activeOnlyEl.checked = false;
      activeOnlyEl.disabled = true;
    }
  } else {
    if (chartWrap) chartWrap.hidden = false;
    if (note) note.hidden = true;
    if (hint) hint.textContent = "Análise em memória — últimos minutos";
    if (labelActiveOnly) labelActiveOnly.hidden = false;
    if (labelActive) labelActive.textContent = "Ativos agora";
    if (labelTotal) labelTotal.textContent = "Total histórico";
    const activeOnlyEl = $("#filterActiveOnly");
    if (activeOnlyEl) {
      activeOnlyEl.disabled = false;
      activeOnlyEl.checked = true;
    }
  }

  loadPatterns();
}

/* ------------------------------------------------------------------ */
/* Filtros                                                             */
/* ------------------------------------------------------------------ */

function applyFilters() {
  const level = $("#filterLevel")?.value || "";
  const kind = $("#filterKind")?.value || "";
  const search = ($("#filterSearch")?.value || "").toLowerCase().trim();
  const activeOnly =
    state.mode === "live" && ($("#filterActiveOnly")?.checked ?? true);
  const now = Date.now();

  state.filtered = state.allPatterns.filter((p) => {
    if (level && p.level !== level) return false;
    if (kind && p.kind !== kind) return false;
    if (activeOnly && !isActive(p, now)) return false;
    if (search) {
      const hay = `${p.title} ${p.detail} ${p.kind}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  render();
  syncKpiActive();
}

/* ------------------------------------------------------------------ */
/* Renderização                                                        */
/* ------------------------------------------------------------------ */

function render() {
  const container = $("#eventsTable");
  if (!container) return;

  const now = Date.now();

  if (!state.filtered.length) {
    const total = state.allPatterns.length;
    const msg = total
      ? "Nenhum padrão corresponde aos filtros."
      : state.mode === "history"
        ? "Nenhum padrão persistido ainda."
        : "Nenhum padrão detectado ainda.<br><small>O sistema está saudável no momento.</small>";
    container.innerHTML = `<div class="event-empty">${msg}</div>`;
    updateMeta();
    return;
  }

  const rows = state.filtered
    .map((p) => {
      const active = state.mode === "live" && isActive(p, now);
      const badge =
        state.mode === "live"
          ? active
            ? '<span class="pattern-badge-active">ativo</span>'
            : '<span class="pattern-badge-resolved">resolvido</span>'
          : "";

      const countCell =
        state.mode === "history"
          ? `${p.occurrences}× · ${esc(fmtTime(p.first_detected_ms))} → ${esc(relTime(p.last_detected_ms))}`
          : `${p.occurrences}× · ${esc(fmtDuration(p.first_detected_ms, p.last_detected_ms))}`;

      return `
        <div class="pattern-row${active ? "" : " resolved"}" data-level="${esc(p.level)}">
          <span class="pattern-time">${esc(fmtTime(p.last_detected_ms))}</span>
          <span class="pattern-level ${esc(p.level)}">${esc(p.level)}</span>
          <span class="pattern-title">${esc(p.title)}${badge}</span>
          <span class="pattern-detail">${esc(p.detail)}</span>
          <span class="pattern-count">${countCell}</span>
        </div>`;
    })
    .join("");

  container.innerHTML = `
    <div class="pattern-header">
      <span>Última vez</span>
      <span>Nível</span>
      <span>Padrão</span>
      <span>Detalhe</span>
      <span>Ocorrências</span>
    </div>
    ${rows}
  `;

  updateMeta();
}

function updateMeta() {
  const countEl = $("#eventsCount");
  const updatedEl = $("#eventsUpdated");
  const now = Date.now();

  // Contagens por nível — em live, só ativos; em history, tudo.
  const counts = { Error: 0, Warning: 0, Information: 0 };
  if (state.mode === "live") {
    for (const p of state.allPatterns) {
      if (isActive(p, now) && counts[p.level] !== undefined) counts[p.level]++;
    }
  } else {
    for (const p of state.allPatterns) {
      if (counts[p.level] !== undefined) counts[p.level]++;
    }
  }

  if (countEl) {
    const total =
      state.allPatterns.length === state.filtered.length
        ? `${state.allPatterns.length} padrões`
        : `${state.filtered.length} de ${state.allPatterns.length}`;

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

  // Summary cards
  const sActive = $("#summaryActive");
  const sErr = $("#summaryErrors");
  const sWarn = $("#summaryWarnings");
  const sInfo = $("#summaryInfo");
  const sTotal = $("#summaryTotal");

  if (state.mode === "live") {
    const active = state.allPatterns.filter((p) => isActive(p, now));
    if (sActive) sActive.textContent = active.length;
  } else {
    // No histórico, "últimos 7 dias" — filtro temporal simples.
    const weekAgo = now - 7 * 24 * 3600 * 1000;
    const recent = state.allPatterns.filter(
      (p) => p.last_detected_ms >= weekAgo,
    );
    if (sActive) sActive.textContent = recent.length;
  }

  if (sErr) sErr.textContent = counts.Error;
  if (sWarn) sWarn.textContent = counts.Warning;
  if (sInfo) sInfo.textContent = counts.Information;
  if (sTotal) sTotal.textContent = state.allPatterns.length;
}

/* ------------------------------------------------------------------ */
/* Gráfico histórico (sparkline) — só no modo ao vivo                  */
/* ------------------------------------------------------------------ */

function drawChart() {
  if (state.mode !== "live") return;

  const canvas = $("#historyChart");
  if (!canvas || !state.history.length) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const W = rect.width;
  const H = 160;

  canvas.width = W * dpr;
  canvas.height = H * dpr;
  canvas.style.height = H + "px";

  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);

  const pad = { top: 10, right: 10, bottom: 20, left: 30 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  const n = state.history.length;

  ctx.strokeStyle = "rgba(255,255,255,0.06)";
  ctx.lineWidth = 1;
  for (const pct of [25, 50, 75]) {
    const y = pad.top + plotH * (1 - pct / 100);
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(pad.left + plotW, y);
    ctx.stroke();

    ctx.fillStyle = "rgba(255,255,255,0.35)";
    ctx.font = "10px ui-monospace, Consolas, monospace";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    ctx.fillText(`${pct}%`, pad.left - 4, y);
  }

  const xFor = (i) => pad.left + (plotW * i) / Math.max(1, n - 1);
  const yFor = (pct) =>
    pad.top + plotH * (1 - Math.min(100, Math.max(0, pct)) / 100);

  const drawLine = (key, color, fill = false) => {
    const pts = state.history.map((s, i) => [xFor(i), yFor(s[key])]);

    if (fill) {
      ctx.beginPath();
      ctx.moveTo(pts[0][0], pad.top + plotH);
      for (const [x, y] of pts) ctx.lineTo(x, y);
      ctx.lineTo(pts[pts.length - 1][0], pad.top + plotH);
      ctx.closePath();
      ctx.fillStyle = color + "22";
      ctx.fill();
    }

    ctx.beginPath();
    ctx.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i][0], pts[i][1]);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.stroke();
  };

  drawLine("cpu_percent", "#ff6b35", true);
  drawLine("mem_percent", "#22d3ee", true);
  drawLine("disk_percent", "#a855f7", false);

  if (n > 0) {
    const last = state.history[n - 1];
    ctx.beginPath();
    ctx.arc(xFor(n - 1), yFor(last.cpu_percent), 3, 0, Math.PI * 2);
    ctx.fillStyle = "#ff6b35";
    ctx.fill();
  }

  const meta = $("#chartMeta");
  if (meta) {
    meta.textContent = `${n} amostras · ${fmtDuration(
      state.history[0].timestamp_ms,
      state.history[n - 1].timestamp_ms,
    )}`;
  }
}

/* ------------------------------------------------------------------ */
/* Carregamento                                                        */
/* ------------------------------------------------------------------ */

async function loadLive() {
  const res = await apiFetch(`/api/patterns?limit=200`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const payload = await res.json();

  state.allPatterns = Array.isArray(payload.patterns) ? payload.patterns : [];
  state.history = Array.isArray(payload.history) ? payload.history : [];
  state.lastPayload = payload;

  applyFilters();
  drawChart();
}

async function loadHistory() {
  const res = await apiFetch(`/api/patterns/history?limit=1000`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const payload = await res.json();

  state.allPatterns = Array.isArray(payload.patterns) ? payload.patterns : [];
  state.history = []; // sem samples no modo histórico
  state.lastPayload = payload;

  const counter = $("#historyCount");
  if (counter) {
    counter.textContent = payload.empty ? "—" : String(payload.count ?? 0);
    counter.classList.toggle("has-alert", (payload.count ?? 0) > 0);
  }

  applyFilters();
}

async function loadPatterns() {
  try {
    if (state.mode === "history") {
      await loadHistory();
    } else {
      await loadLive();
    }
  } catch (err) {
    console.error("[patterns] erro:", err);
    const container = $("#eventsTable");
    if (container) {
      container.innerHTML = `<div class="event-empty">
        ❌ Não foi possível carregar os padrões.<br>
        <small>${esc(err.message)}</small>
      </div>`;
    }
  }
}

/* ------------------------------------------------------------------ */
/* Bootstrap                                                           */
/* ------------------------------------------------------------------ */

function init() {
  initTheme();
  startClock();
  wireKpis();

  $("#btnRefresh")?.addEventListener("click", () => {
    loadPatterns();
    showToast("🔄 Reanalisando…", 1000);
  });

  // Toggle de modo
  $$(".mode-btn").forEach((btn) => {
    btn.addEventListener("click", () => setMode(btn.dataset.mode));
  });

  // Filtros
  ["filterLevel", "filterKind", "filterActiveOnly"].forEach((id) => {
    $("#" + id)?.addEventListener("change", applyFilters);
  });
  $("#filterSearch")?.addEventListener("input", applyFilters);

  // Re-renderiza a cada 10s pra atualizar "ativo/resolvido".
  setInterval(() => {
    if (state.allPatterns.length) applyFilters();
  }, 10_000);

  // Resize do canvas (só relevante no modo live)
  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(drawChart, 250);
  });

  // Carga inicial + polling.
  // Em live: a cada 3s (dados quentes).
  // Em history: a cada 60s (dados frios).
  loadPatterns();
  setInterval(() => {
    if (state.mode === "live") loadPatterns();
  }, 3000);
  setInterval(() => {
    if (state.mode === "history") loadPatterns();
  }, 60_000);

  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    if (e.key === "r" || e.key === "R") loadPatterns();
  });
}

/* ------------------------------------------------------------------ */
/* KPIs clicáveis                                                      */
/* ------------------------------------------------------------------ */

/// Marca visualmente qual card está ativo. Só faz sentido pro filtro
/// de nível — o toggle "apenas ativos" tem checkbox próprio.
function syncKpiActive() {
  const level = $("#filterLevel")?.value || "";
  $$(".summary-card[data-kpi]").forEach((card) => {
    const k = card.dataset.kpi;
    card.classList.toggle("kpi-active", k === level && !!level);
  });
}

function wireKpis() {
  $$(".summary-card[data-kpi]").forEach((card) => {
    card.addEventListener("click", () => {
      const k = card.dataset.kpi;

      if (k === "__reset__") {
        // Limpa tudo
        const levelSel = $("#filterLevel");
        const kindSel = $("#filterKind");
        const searchEl = $("#filterSearch");
        const activeEl = $("#filterActiveOnly");
        if (levelSel) levelSel.value = "";
        if (kindSel) kindSel.value = "";
        if (searchEl) searchEl.value = "";
        if (activeEl && state.mode === "live") activeEl.checked = true;
      } else if (k === "__recent__") {
        // Toggle "apenas ativos" (só no modo live)
        const activeEl = $("#filterActiveOnly");
        if (activeEl && !activeEl.disabled) {
          activeEl.checked = !activeEl.checked;
        }
      } else {
        // Nível: clica de novo pra limpar
        const levelSel = $("#filterLevel");
        if (levelSel) {
          levelSel.value = levelSel.value === k ? "" : k;
        }
      }

      applyFilters();
      syncKpiActive();
    });
  });
}

document.addEventListener("DOMContentLoaded", init);
