/* =========================================================
   Cards de tempo real alimentados pelo SSE do agente Rust
   ========================================================= */

import { fetchSnapshot } from "../api/rest.js";
import { createLiveStream } from "../api/sse.js";

const state = { stream: null, last: null };

/* ------------------------------------------------------------------ */
/* Formatação                                                          */
/* ------------------------------------------------------------------ */

function fmtBytes(n) {
  if (n === undefined || n === null || isNaN(n)) return "—";
  if (n === 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i === 0 ? 0 : 2)} ${u[i]}`;
}

function fmtUptime(sec) {
  if (!sec && sec !== 0) return "—";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (!parts.length) parts.push("< 1m");
  return parts.join(" ");
}

function filterInterfaces(ifaces) {
  if (!ifaces) return [];
  return ifaces.filter((i) => {
    if (!i.name) return false;
    if (/Light-Weight Filter|NDIS|QoS|VirtualBox/i.test(i.name)) return false;
    if (i.rx_bytes === 0 && i.tx_bytes === 0) return false;
    return true;
  });
}

/* ------------------------------------------------------------------ */
/* Skeleton HTML                                                       */
/* ------------------------------------------------------------------ */

export function buildLiveCards() {
  const wrap = document.getElementById("live-cards");
  if (!wrap || wrap.dataset.built === "1") return wrap;

  wrap.className = "live-wrap";
  wrap.innerHTML = `
    <header class="group-header">
      <span class="group-icon">⚡</span>
      <h2 class="group-title">Tempo Real — Agente Rust</h2>
      <span class="group-count" id="live-status">conectando…</span>
    </header>

    <div class="grid">
      <article class="card live-card">
        <header class="card-head">
          <span class="card-icon">🧠</span>
          <div><h2>CPU</h2><p id="live-cpu-label">aguardando…</p></div>
        </header>
        <div class="live-body live-body-cpu">
          <div class="gauge">
            <svg viewBox="0 0 100 100" class="gauge-svg">
              <circle cx="50" cy="50" r="42" class="gauge-bg"/>
              <circle cx="50" cy="50" r="42" class="gauge-fg" id="cpu-arc"/>
            </svg>
            <div class="gauge-value" id="cpu-value">—</div>
          </div>
          <div class="per-core" id="cpu-cores"></div>
        </div>
        <ul class="live-list rows" id="cpu-details"></ul>
      </article>

      <article class="card live-card">
        <header class="card-head">
          <span class="card-icon">💾</span>
          <div><h2>Memória</h2><p id="live-mem-label">aguardando…</p></div>
        </header>
        <div class="live-body">
          <div class="gauge">
            <svg viewBox="0 0 100 100" class="gauge-svg">
              <circle cx="50" cy="50" r="42" class="gauge-bg"/>
              <circle cx="50" cy="50" r="42" class="gauge-fg mem" id="mem-arc"/>
            </svg>
            <div class="gauge-value" id="mem-value">—</div>
          </div>
          <ul class="live-list" id="mem-details"></ul>
        </div>
        <ul class="live-list rows" id="swap-details"></ul>
      </article>

      <article class="card live-card">
        <header class="card-head">
          <span class="card-icon">📊</span>
          <div><h2>Sistema</h2><p>Informações do host</p></div>
        </header>
        <ul class="live-list rows" id="sys-details"></ul>
      </article>

      <article class="card live-card">
        <header class="card-head">
          <span class="card-icon">💽</span>
          <div><h2>Disco</h2><p id="disk-label">aguardando…</p></div>
        </header>
        <div class="live-body">
          <div class="gauge">
            <svg viewBox="0 0 100 100" class="gauge-svg">
              <circle cx="50" cy="50" r="42" class="gauge-bg"/>
              <circle cx="50" cy="50" r="42" class="gauge-fg disk" id="disk-arc"/>
            </svg>
            <div class="gauge-value" id="disk-value">—</div>
          </div>
          <ul class="live-list" id="disk-details"></ul>
        </div>
        <ul class="live-list rows" id="disk-mounts"></ul>
      </article>

      <article class="card live-card">
        <header class="card-head">
          <span class="card-icon">📡</span>
          <div><h2>Rede</h2><p>Tráfego acumulado</p></div>
        </header>
        <ul class="live-list rows" id="net-details"></ul>
        <div class="net-ifaces" id="net-ifaces"></div>
      </article>

      <article class="card live-card">
        <header class="card-head">
          <span class="card-icon">⚙️</span>
          <div><h2>Processos</h2><p id="proc-label">aguardando…</p></div>
        </header>
        <ul class="proc-list" id="proc-list"></ul>
      </article>
    </div>
  `;

  wrap.dataset.built = "1";
  return wrap;
}

/* ------------------------------------------------------------------ */
/* Renderização                                                        */
/* ------------------------------------------------------------------ */

const CIRCUMFERENCE = 2 * Math.PI * 42;

function setGauge(prefix, percent) {
  const arc = document.getElementById(`${prefix}-arc`);
  const val = document.getElementById(`${prefix}-value`);
  if (!arc || !val) return;
  const p = Math.min(100, Math.max(0, percent || 0));
  arc.style.strokeDasharray = CIRCUMFERENCE;
  arc.style.strokeDashoffset = CIRCUMFERENCE * (1 - p / 100);
  val.textContent = `${p.toFixed(1)}%`;
}

function setRows(id, rows) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = rows
    .map(
      ([k, v]) =>
        `<li class="row"><span class="k">${k}</span><span class="v">${v}</span></li>`,
    )
    .join("");
}

function renderPerCore(cores) {
  const el = document.getElementById("cpu-cores");
  if (!el) return;
  if (!cores || !cores.length) {
    el.innerHTML = "";
    return;
  }
  el.innerHTML = cores
    .map((v, i) => {
      const p = Math.min(100, Math.max(0, v));
      const level = p > 80 ? "hi" : p > 50 ? "mid" : "lo";
      return `
        <div class="core-bar" title="Núcleo ${i}: ${p.toFixed(1)}%">
          <div class="core-fill ${level}" style="height:${p}%"></div>
        </div>`;
    })
    .join("");
}

function renderProcesses(procs) {
  const el = document.getElementById("proc-list");
  if (!el) return;
  if (!procs || !procs.length) {
    el.innerHTML = '<li class="proc-empty">sem dados</li>';
    return;
  }
  el.innerHTML = procs
    .map((p) => {
      const cpu = p.cpu_percent ?? 0;
      const cpuCls = cpu > 50 ? "hi" : cpu > 10 ? "mid" : "lo";
      return `
        <li class="proc-row">
          <span class="proc-name" title="${p.name} (PID ${p.pid})">${p.name}</span>
          <span class="proc-mem">${fmtBytes(p.memory_bytes)}</span>
          <span class="proc-cpu ${cpuCls}">${cpu.toFixed(1)}%</span>
        </li>`;
    })
    .join("");
}

function renderInterfaces(ifaces) {
  const el = document.getElementById("net-ifaces");
  if (!el) return;
  const list = filterInterfaces(ifaces);
  if (!list.length) {
    el.innerHTML = "";
    return;
  }
  el.innerHTML = list
    .map(
      (i) => `
        <div class="iface-row">
          <span class="iface-name">${i.name}</span>
          <span class="iface-stat">↓ ${fmtBytes(i.rx_bytes)}</span>
          <span class="iface-stat">↑ ${fmtBytes(i.tx_bytes)}</span>
        </div>`,
    )
    .join("");
}

/* ------------------------------------------------------------------ */
/* Atualização                                                         */
/* ------------------------------------------------------------------ */

export function updateLive(snap) {
  if (!snap) return;

  /* CPU */
  const cpu = snap.cpu || {};
  setGauge("cpu", cpu.usage_percent ?? 0);
  const cpuLabel = document.getElementById("live-cpu-label");
  if (cpuLabel && cpu.brand) cpuLabel.textContent = cpu.brand;
  renderPerCore(cpu.per_core_usage);
  setRows("cpu-details", [
    ["Modelo", cpu.brand || "—"],
    [
      "Núcleos",
      `${cpu.cores_logical ?? "?"} lógicos / ${cpu.cores_physical ?? "?"} físicos`,
    ],
    ["Frequência", cpu.frequency_mhz ? `${cpu.frequency_mhz} MHz` : "—"],
  ]);

  /* Memória */
  const mem = snap.memory || {};
  setGauge("mem", mem.percent ?? 0);
  const memLabel = document.getElementById("live-mem-label");
  if (memLabel)
    memLabel.textContent = `${fmtBytes(mem.used)} / ${fmtBytes(mem.total)}`;
  setRows("mem-details", [
    ["Total", fmtBytes(mem.total)],
    ["Usada", fmtBytes(mem.used)],
    ["Livre", fmtBytes(mem.free)],
    ["Disponível", fmtBytes(mem.available)],
  ]);
  const swap = snap.swap || {};
  setRows("swap-details", [
    ["Swap total", fmtBytes(swap.total)],
    ["Swap usado", fmtBytes(swap.used)],
    ["Swap livre", fmtBytes(swap.free)],
  ]);

  /* Sistema */
  const os = snap.os || {};
  const host = snap.host || {};
  setRows("sys-details", [
    ["SO", `${os.name || "—"} ${os.version || ""}`.trim()],
    ["Família", os.family || "—"],
    ["Kernel", os.kernel || "—"],
    ["Arquitetura", os.arch || "—"],
    ["Hostname", host.hostname || "—"],
    ["Usuário", host.username || "—"],
    ["Uptime", fmtUptime(host.uptime_seconds)],
    ["Processos", snap.processes?.count ?? "—"],
  ]);

  /* Disco */
  const disk = snap.disk || {};
  setGauge("disk", disk.percent ?? 0);
  const diskLabel = document.getElementById("disk-label");
  if (diskLabel) diskLabel.textContent = `${fmtBytes(disk.used)} usados`;
  setRows("disk-details", [
    ["Total", fmtBytes(disk.total)],
    ["Usado", fmtBytes(disk.used)],
    ["Livre", fmtBytes(disk.free)],
  ]);
  const mounts = disk.mounts || [];
  const mountsEl = document.getElementById("disk-mounts");
  if (mountsEl) {
    mountsEl.innerHTML = mounts
      .map(
        (m) => `
        <li class="row">
          <span class="k">${m.mount_point || m.name || "—"} <small>(${m.fs})</small></span>
          <span class="v">${fmtBytes(m.free)} livre</span>
        </li>`,
      )
      .join("");
  }

  /* Rede */
  const net = snap.network || {};
  setRows("net-details", [
    ["Recebido", fmtBytes(net.rx_bytes)],
    ["Enviado", fmtBytes(net.tx_bytes)],
    ["Total", fmtBytes((net.rx_bytes || 0) + (net.tx_bytes || 0))],
  ]);
  renderInterfaces(net.interfaces);

  /* Processos */
  const procs = snap.processes || {};
  const procLabel = document.getElementById("proc-label");
  if (procLabel) procLabel.textContent = `${procs.count ?? 0} em execução`;
  renderProcesses(procs.top_memory);
}

/* ------------------------------------------------------------------ */
/* Bootstrap                                                           */
/* ------------------------------------------------------------------ */

export async function initLive() {
  buildLiveCards();

  const status = document.getElementById("live-status");

  try {
    const snap = await fetchSnapshot();
    state.last = snap;
    updateLive(snap);

    state.stream = createLiveStream({
      onOpen: () => {
        if (status) {
          status.textContent = "● online";
          status.style.color = "var(--ok)";
        }
      },
      onData: (data) => {
        state.last = data;
        updateLive(data);
      },
      onError: () => {
        if (status) {
          status.textContent = "● reconectando…";
          status.style.color = "var(--warn)";
        }
      },
    });
  } catch (err) {
    console.error("[live] agente indisponível:", err);
    if (status) {
      status.textContent = "● offline";
      status.style.color = "var(--err)";
    }

    const wrap = document.getElementById("live-cards");
    if (wrap && !wrap.querySelector(".context-warning")) {
      wrap.insertAdjacentHTML(
        "beforeend",
        `<div class="context-warning">
           <strong>⚠️ Agente não encontrado</strong>
           <p>Rode <code>cargo run --release</code> no projeto.</p>
         </div>`,
      );
    }
  }
}
