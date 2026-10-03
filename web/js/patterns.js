/* =========================================================
   Página de Padrões Detectados
   ========================================================= */

import { $ } from "./utils/dom.js";
import { showToast } from "./ui/toast.js";
import { initTheme } from "./ui/theme.js";
import { startClock } from "./ui/clock.js";

let allPatterns = [];
let filtered = [];
let history = [];
let lastPayload = null;

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

function isActive(p, now) {
  return now - p.last_detected_ms < ACTIVE_WINDOW_MS;
}

/* ------------------------------------------------------------------ */
/* Filtros                                                             */
/* ------------------------------------------------------------------ */

function applyFilters() {
  const level = $("#filterLevel")?.value || "";
  const kind = $("#filterKind")?.value || "";
  const search = ($("#filterSearch")?.value || "").toLowerCase().trim();
  const activeOnly = $("#filterActiveOnly")?.checked ?? true;
  const now = Date.now();

  filtered = allPatterns.filter((p) => {
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
}

/* ------------------------------------------------------------------ */
/* Renderização                                                        */
/* ------------------------------------------------------------------ */

function render() {
  const container = $("#eventsTable");
  if (!container) return;

  const now = Date.now();

  if (!filtered.length) {
    container.innerHTML = `<div class="event-empty">
      Nenhum padrão ${allPatterns.length ? "corresponde aos filtros" : "detectado ainda"}.
      ${allPatterns.length ? "" : "<br><small>O sistema está saudável no momento.</small>"}
    </div>`;
    updateMeta();
    return;
  }

  const rows = filtered
    .map((p) => {
      const active = isActive(p, now);
      const badge = active
        ? '<span class="pattern-badge-active">ativo</span>'
        : '<span class="pattern-badge-resolved">resolvido</span>';

      return `
        <div class="pattern-row${active ? "" : " resolved"}" data-level="${esc(p.level)}">
          <span class="pattern-time">${esc(fmtTime(p.last_detected_ms))}</span>
          <span class="pattern-level ${esc(p.level)}">${esc(p.level)}</span>
          <span class="pattern-title">${esc(p.title)}${badge}</span>
          <span class="pattern-detail">${esc(p.detail)}</span>
          <span class="pattern-count">${p.occurrences}× · ${esc(fmtDuration(p.first_detected_ms, p.last_detected_ms))}</span>
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

  const active = allPatterns.filter((p) => isActive(p, now));
  const counts = { Error: 0, Warning: 0, Information: 0 };
  for (const p of active) {
    if (counts[p.level] !== undefined) counts[p.level]++;
  }

  if (countEl) {
    const total =
      allPatterns.length === filtered.length
        ? `${allPatterns.length} padrões`
        : `${filtered.length} de ${allPatterns.length}`;

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

  // Resumo no topo
  const totalActive = active.length;
  $("#summaryActive").textContent = totalActive;
  $("#summaryErrors").textContent = counts.Error;
  $("#summaryWarnings").textContent = counts.Warning;
  $("#summaryInfo").textContent = counts.Information;
  $("#summaryTotal").textContent = allPatterns.length;
}

/* ------------------------------------------------------------------ */
/* Gráfico histórico (sparkline)                                       */
/* ------------------------------------------------------------------ */

function drawChart() {
  const canvas = $("#historyChart");
  if (!canvas || !history.length) return;

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

  const n = history.length;

  // Linhas de grade (25/50/75)
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
    const pts = history.map((s, i) => [xFor(i), yFor(s[key])]);

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

  // Último ponto destacado
  if (n > 0) {
    const last = history[n - 1];
    ctx.beginPath();
    ctx.arc(xFor(n - 1), yFor(last.cpu_percent), 3, 0, Math.PI * 2);
    ctx.fillStyle = "#ff6b35";
    ctx.fill();
  }

  // Meta
  const meta = $("#chartMeta");
  if (meta) {
    meta.textContent = `${n} amostras · ${fmtDuration(history[0].timestamp_ms, history[n - 1].timestamp_ms)}`;
  }
}

/* ------------------------------------------------------------------ */
/* Carregamento                                                        */
/* ------------------------------------------------------------------ */

async function loadPatterns() {
  const limit = 200;

  try {
    const res = await fetch(`/api/patterns?limit=${limit}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();

    allPatterns = Array.isArray(payload.patterns) ? payload.patterns : [];
    history = Array.isArray(payload.history) ? payload.history : [];
    lastPayload = payload;

    applyFilters();
    drawChart();
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

  $("#btnRefresh")?.addEventListener("click", () => {
    loadPatterns();
    showToast("🔄 Reanalisando…", 1000);
  });

  ["filterLevel", "filterKind", "filterActiveOnly"].forEach((id) => {
    $("#" + id)?.addEventListener("change", applyFilters);
  });
  $("#filterSearch")?.addEventListener("input", applyFilters);

  // Re-renderiza a cada 10s para mover padrões de "ativo" para "resolvido"
  setInterval(() => {
    if (allPatterns.length) applyFilters();
  }, 10_000);

  // Redesenha o gráfico em resize
  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(drawChart, 250);
  });

  // Carrega a cada 3s
  loadPatterns();
  setInterval(loadPatterns, 3000);

  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    if (e.key === "r" || e.key === "R") loadPatterns();
  });
}

document.addEventListener("DOMContentLoaded", init);
