/* =========================================================
   Página de histórico com gráficos interativos (uPlot)
   ========================================================= */

import { $ } from "./utils/dom.js";
import { apiFetch } from "./api/rest.js";
import { showToast } from "./ui/toast.js";
import { initTheme } from "./ui/theme.js";
import { startClock } from "./ui/clock.js";

/* uPlot é carregado via <script> global (window.uPlot) */
const uPlot = window.uPlot;

let currentMinutes = 60;
let chart1 = null;
let chart2 = null;
let autoTimer = null;
let lastData = null;

const PALETTE = {
  cpu: "#ff6b35",
  mem: "#22d3ee",
  disk: "#a855f7",
  rx: "#34d399",
  tx: "#fbbf24",
  procs: "#f472b6",
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

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
  return `${v.toFixed(1)} ${u[i]}`;
}

function readThemeColors() {
  const styles = getComputedStyle(document.documentElement);
  return {
    text: styles.getPropertyValue("--text").trim() || "#e9eefc",
    dim: styles.getPropertyValue("--text-dim").trim() || "#a9b3d0",
    muted: styles.getPropertyValue("--muted").trim() || "#7b87a8",
    grid:
      document.documentElement.dataset.theme === "light"
        ? "rgba(0,0,0,0.06)"
        : "rgba(255,255,255,0.06)",
  };
}

/* ------------------------------------------------------------------ */
/* Conversão de dados                                                  */
/* ------------------------------------------------------------------ */

/**
 * Converte array de samples em [x, y1, y2, ...] para o uPlot.
 * uPlot espera timestamps em SEGUNDOS (unix).
 */
function toUPlotData(samples) {
  const x = [];
  const cpu = [];
  const mem = [];
  const disk = [];
  const rx = [];
  const tx = [];
  const procs = [];

  for (const s of samples) {
    x.push(Math.floor(s.timestamp_ms / 1000));
    cpu.push(s.cpu_percent);
    mem.push(s.mem_percent);
    disk.push(s.disk_percent);
    rx.push(s.net_rx);
    tx.push(s.net_tx);
    procs.push(s.proc_count);
  }

  return [x, cpu, mem, disk, rx, tx, procs];
}

/* ------------------------------------------------------------------ */
/* Configuração dos gráficos                                           */
/* ------------------------------------------------------------------ */

function makeChart1Options(width) {
  const c = readThemeColors();

  return {
    width,
    height: 340,
    padding: [12, 20, 0, 0],
    cursor: {
      drag: { x: true, y: false, setScale: true },
      focus: { prox: 30 },
    },
    scales: {
      x: { time: true },
      y: { auto: true, range: [0, 100] },
      y2: { auto: true },
    },
    axes: [
      {
        stroke: c.dim,
        grid: { stroke: c.grid, width: 1 },
        ticks: { stroke: c.grid },
        font: "11px ui-monospace, Consolas, monospace",
      },
      {
        scale: "y",
        label: "Uso (%)",
        labelSize: 20,
        stroke: c.dim,
        grid: { stroke: c.grid, width: 1 },
        ticks: { stroke: c.grid },
        font: "11px ui-monospace, Consolas, monospace",
      },
    ],
    series: [
      {},
      {
        label: "CPU %",
        scale: "y",
        stroke: PALETTE.cpu,
        width: 2,
        fill: "rgba(255,107,53,0.12)",
        value: (_, v) => (v == null ? "—" : `${v.toFixed(1)}%`),
      },
      {
        label: "Memória %",
        scale: "y",
        stroke: PALETTE.mem,
        width: 2,
        fill: "rgba(34,211,238,0.10)",
        value: (_, v) => (v == null ? "—" : `${v.toFixed(1)}%`),
      },
      {
        label: "Disco %",
        scale: "y",
        stroke: PALETTE.disk,
        width: 2,
        fill: "rgba(168,85,247,0.08)",
        value: (_, v) => (v == null ? "—" : `${v.toFixed(1)}%`),
      },
    ],
    legend: { live: true },
  };
}

function makeChart2Options(width) {
  const c = readThemeColors();

  return {
    width,
    height: 300,
    padding: [12, 20, 0, 0],
    cursor: {
      drag: { x: true, y: false, setScale: true },
      focus: { prox: 30 },
    },
    scales: {
      x: { time: true },
      y: { auto: true }, // bytes
      y2: { auto: true }, // processos
    },
    axes: [
      {
        stroke: c.dim,
        grid: { stroke: c.grid, width: 1 },
        ticks: { stroke: c.grid },
        font: "11px ui-monospace, Consolas, monospace",
      },
      {
        scale: "y",
        label: "Bytes",
        labelSize: 20,
        stroke: c.dim,
        grid: { stroke: c.grid, width: 1 },
        ticks: { stroke: c.grid },
        font: "11px ui-monospace, Consolas, monospace",
        values: (_, vals) => vals.map(fmtBytes),
      },
      {
        scale: "y2",
        side: 1,
        label: "Processos",
        labelSize: 20,
        stroke: c.dim,
        grid: { show: false },
        ticks: { stroke: c.grid },
        font: "11px ui-monospace, Consolas, monospace",
      },
    ],
    series: [
      {},
      {
        label: "RX",
        scale: "y",
        stroke: PALETTE.rx,
        width: 2,
        fill: "rgba(52,211,153,0.10)",
        value: (_, v) => (v == null ? "—" : fmtBytes(v)),
      },
      {
        label: "TX",
        scale: "y",
        stroke: PALETTE.tx,
        width: 2,
        fill: "rgba(251,191,36,0.08)",
        value: (_, v) => (v == null ? "—" : fmtBytes(v)),
      },
      {
        label: "Processos",
        scale: "y2",
        stroke: PALETTE.procs,
        width: 2,
        dash: [4, 3],
        points: { show: false },
        value: (_, v) => (v == null ? "—" : String(v)),
      },
    ],
    legend: { live: true },
  };
}

/* ------------------------------------------------------------------ */
/* Render                                                              */
/* ------------------------------------------------------------------ */

function renderCharts(samples) {
  if (!uPlot) {
    console.error("[history] uPlot não carregado. Verifique /vendor/uplot/");
    return;
  }

  const container1 = $("#chart");
  const container2 = $("#chart2");
  if (!container1 || !container2) return;

  const width = container1.clientWidth || 800;
  const data = toUPlotData(samples);

  const opts1 = makeChart1Options(width);
  const opts2 = makeChart2Options(width);

  if (!chart1) {
    chart1 = new uPlot(opts1, data, container1);
  } else {
    chart1.setSize({ width, height: opts1.height });
    chart1.setData(data);
  }

  if (!chart2) {
    chart2 = new uPlot(opts2, data, container2);
  } else {
    chart2.setSize({ width, height: opts2.height });
    chart2.setData(data);
  }

  // Meta
  const meta1 = $("#chartMeta");
  const meta2 = $("#chartMeta2");
  const info = `${samples.length} pontos`;
  if (meta1) meta1.textContent = info;
  if (meta2) meta2.textContent = info;
}

/* ------------------------------------------------------------------ */
/* Carregamento                                                        */
/* ------------------------------------------------------------------ */

async function loadHistory() {
  const metaEl = $("#historyMeta");

  try {
    const res = await apiFetch(
      `/api/history?minutes=${currentMinutes}&limit=5000`,
    );
    if (res.status === 503) {
      if (metaEl)
        metaEl.textContent = "⚠️ Persistência desabilitada no config.toml";
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const payload = await res.json();
    const samples = Array.isArray(payload.samples) ? payload.samples : [];

    if (!samples.length) {
      if (metaEl) metaEl.textContent = "Nenhuma amostra no período selecionado";
      renderCharts([]);
      return;
    }

    lastData = payload;
    renderCharts(samples);

    if (metaEl) {
      const dur = (payload.to_ms - payload.from_ms) / 60000;
      metaEl.textContent = `${payload.count} amostras · ${dur.toFixed(0)} min`;
    }

    // Estatísticas do DB
    try {
      const st = await apiFetch("/api/db-stats");
      if (st.ok) {
        const s = await st.json();
        const el = $("#dbStats");
        if (el)
          el.textContent = `💾 DB: ${s.samples} amostras · ${s.patterns} padrões`;
      }
    } catch {
      /* opcional */
    }
  } catch (err) {
    console.error("[history] erro:", err);
    if (metaEl) metaEl.textContent = `❌ ${err.message}`;
    showToast("❌ Falha ao carregar histórico");
  }
}

/* ------------------------------------------------------------------ */
/* Auto-refresh                                                        */
/* ------------------------------------------------------------------ */

function startAuto() {
  stopAuto();
  autoTimer = setInterval(loadHistory, 30000);
}

function stopAuto() {
  if (autoTimer) {
    clearInterval(autoTimer);
    autoTimer = null;
  }
}

/* ------------------------------------------------------------------ */
/* Bootstrap                                                           */
/* ------------------------------------------------------------------ */

function init() {
  initTheme();
  startClock();

  // Botões de intervalo
  document.querySelectorAll(".range-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll(".range-btn")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentMinutes = parseInt(btn.dataset.min, 10);
      loadHistory();
    });
  });

  // Refresh manual
  $("#btnRefresh")?.addEventListener("click", () => {
    loadHistory();
    showToast("🔄 Atualizando histórico…", 800);
  });

  // Auto-refresh toggle
  $("#autoRefresh")?.addEventListener("change", (e) => {
    if (e.target.checked) startAuto();
    else stopAuto();
  });

  // Atalhos
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    if (e.key === "r" || e.key === "R") loadHistory();
  });

  // Redimensionamento
  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (lastData?.samples) renderCharts(lastData.samples);
    }, 250);
  });

  // Primeira carga
  loadHistory();
  startAuto();
}

document.addEventListener("DOMContentLoaded", init);
