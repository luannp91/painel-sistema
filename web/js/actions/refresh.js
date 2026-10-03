/* =========================================================
   Coleta informações do navegador + agente Rust
   ========================================================= */

import { esc } from "../utils/dom.js";
import { NA } from "../utils/safe.js";

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

const yesNo = (v) => (v ? "Sim" : "Não");

function fmtBytes(n) {
  if (n === undefined || n === null || isNaN(n)) return NA;
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
  if (!sec && sec !== 0) return NA;
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}min`);
  parts.push(`${s}s`);
  return parts.join(" ");
}

/* ------------------------------------------------------------------ */
/* Detecção pelo userAgent                                             */
/* ------------------------------------------------------------------ */

function detectOS() {
  const ua = navigator.userAgent;
  if (/Windows NT 10/.test(ua)) return "Windows 10/11";
  if (/Windows NT 6\.1/.test(ua)) return "Windows 7";
  if (/Android/.test(ua)) return "Android";
  if (/iPhone|iPad|iPod/.test(ua)) return "iOS/iPadOS";
  if (/Mac OS X/.test(ua)) return "macOS";
  if (/CrOS/.test(ua)) return "ChromeOS";
  if (/Linux/.test(ua)) return "Linux";
  return navigator.platform || NA;
}

function detectBrowser() {
  const ua = navigator.userAgent;
  if (/Edg\//.test(ua)) return "Microsoft Edge";
  if (/OPR\//.test(ua)) return "Opera";
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/Chrome\//.test(ua)) return "Google Chrome";
  if (/Safari\//.test(ua)) return "Safari";
  return NA;
}

function detectEngine() {
  const ua = navigator.userAgent;
  if (/Firefox\//.test(ua)) return "Gecko";
  if (/Chrome\/|Edg\/|OPR\//.test(ua)) return "Blink";
  if (/Safari\//.test(ua)) return "WebKit";
  return NA;
}

/* ------------------------------------------------------------------ */
/* Agente Rust — dados exatos                                          */
/* ------------------------------------------------------------------ */

async function fetchAgent() {
  try {
    const res = await fetch("/api/snapshot", {
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Coletores                                                           */
/* ------------------------------------------------------------------ */

async function collectSistema(agent) {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || NA;

  // Arquitetura: agente > UA
  let arch = agent?.os?.arch || NA;
  if (arch === NA) {
    const ua = navigator.userAgent;
    if (/x64|WOW64|Win64/.test(ua)) arch = "x86_64 (64-bit)";
    else if (/aarch64|arm64/.test(ua)) arch = "arm64";
  }

  // RAM: agente > navigator.deviceMemory (só Chrome/Edge)
  let ram = NA;
  if (agent?.memory?.total) {
    const gb = (agent.memory.total / 1024 ** 3).toFixed(1);
    ram = `${gb} GB (exato)`;
  } else if (navigator.deviceMemory) {
    ram = `${navigator.deviceMemory} GB (aprox.)`;
  } else {
    ram = "Indisponível no Firefox";
  }

  // CPU: agente > hardwareConcurrency
  let cpuCores = navigator.hardwareConcurrency ?? NA;
  if (agent?.cpu?.cores_logical) {
    const l = agent.cpu.cores_logical;
    const p = agent.cpu.cores_physical || "?";
    cpuCores = `${l} lógicos / ${p} físicos`;
  }

  // SO: agente > UA
  let osName = detectOS();
  if (agent?.os?.name) {
    osName = agent.os.version
      ? `${agent.os.name} ${agent.os.version}`
      : agent.os.name;
  }

  return [
    ["Sistema operacional", osName],
    ["Plataforma", navigator.platform || NA],
    ["Arquitetura", arch],
    ["Núcleos de CPU", cpuCores],
    ["Memória RAM", ram],
    ["Idioma do sistema", navigator.language || NA],
    ["Idiomas preferidos", (navigator.languages || []).join(", ") || NA],
    ["Fuso horário", tz],
    [
      "Fonte dos dados do SO",
      agent ? "🦀 Agente Rust (exato)" : "🌐 Apenas navegador",
    ],
  ];
}

async function collectNavegador(agent) {
  let vendor = navigator.vendor || "";
  if (!vendor && /Firefox/.test(navigator.userAgent)) vendor = "Mozilla";

  const brands = (navigator.userAgentData?.brands || [])
    .filter((b) => !/Not.?A.?Brand/i.test(b.brand))
    .map((b) => `${b.brand} ${b.version}`)
    .join(", ");

  return [
    ["Navegador", detectBrowser()],
    ["Motor", detectEngine()],
    ["Fabricante", vendor || NA],
    ["Marcas (UA-CH)", brands || NA],
    ["Cookies habilitados", yesNo(navigator.cookieEnabled)],
    ["Do Not Track", navigator.doNotTrack ?? NA],
    ["WebDriver (automação)", yesNo(navigator.webdriver)],
    ["Rodando em", agent?.os?.family || "SO não detectado"],
    ["User Agent", navigator.userAgent],
  ];
}

async function collectTela() {
  const s = screen;
  const mq = (q) => window.matchMedia(q).matches;
  return [
    ["Resolução", `${s.width} × ${s.height} px`],
    ["Área disponível", `${s.availWidth} × ${s.availHeight} px`],
    ["Profundidade de cor", `${s.colorDepth} bits`],
    ["Device Pixel Ratio", window.devicePixelRatio ?? NA],
    ["Orientação", s.orientation?.type ?? NA],
    ["Viewport interno", `${window.innerWidth} × ${window.innerHeight} px`],
    ["Tema preferido", mq("(prefers-color-scheme: dark)") ? "Escuro" : "Claro"],
    ["Toque", yesNo(mq("(pointer: coarse)"))],
    ["Mouse", yesNo(mq("(any-pointer: fine)"))],
    ["Movimento reduzido", yesNo(mq("(prefers-reduced-motion: reduce)"))],
  ];
}

async function collectTempo() {
  const now = new Date();
  const intl = Intl.DateTimeFormat().resolvedOptions();
  const offsetMin = -now.getTimezoneOffset();
  const sign = offsetMin >= 0 ? "+" : "-";
  const abs = Math.abs(offsetMin);
  const offset = `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;

  return [
    ["Data e hora local", now.toLocaleString("pt-BR")],
    ["UTC", now.toUTCString()],
    ["Fuso horário", intl.timeZone || NA],
    ["Offset", offset],
    ["Locale", intl.locale || NA],
    ["Uptime da página", fmtUptime(performance.now() / 1000)],
  ];
}

async function collectArmazenamento() {
  const rows = [];
  try {
    const est = await navigator.storage?.estimate?.();
    if (est) {
      rows.push(["Cota total", fmtBytes(est.quota)]);
      rows.push(["Uso atual", fmtBytes(est.usage)]);
      rows.push([
        "Uso (%)",
        est.quota ? `${((est.usage / est.quota) * 100).toFixed(2)}%` : NA,
      ]);
    } else {
      rows.push(["Storage API", "Não disponível"]);
    }
  } catch {
    rows.push(["Storage API", "Erro ao consultar"]);
  }
  return rows;
}

async function collectRecursos() {
  const check = (fn) => {
    try {
      return yesNo(fn());
    } catch {
      return NA;
    }
  };
  return [
    ["WebAssembly", yesNo(typeof WebAssembly === "object")],
    ["Service Worker", yesNo("serviceWorker" in navigator)],
    ["WebRTC", yesNo(!!window.RTCPeerConnection)],
    ["Notificações", yesNo("Notification" in window)],
    ["Geolocalização", yesNo("geolocation" in navigator)],
    ["Bluetooth", yesNo("bluetooth" in navigator)],
    ["USB", yesNo("usb" in navigator)],
    ["Web Share", yesNo(!!navigator.share)],
    ["Clipboard", check(() => !!navigator.clipboard)],
    ["Vibração", check(() => typeof navigator.vibrate === "function")],
  ];
}

/* ------------------------------------------------------------------ */
/* Seções                                                              */
/* ------------------------------------------------------------------ */

const SECTIONS = [
  {
    id: "sistema",
    icon: "🖥️",
    title: "Sistema Operacional",
    subtitle: "Navegador + agente",
    collect: collectSistema,
  },
  {
    id: "navegador",
    icon: "🌐",
    title: "Navegador",
    subtitle: "UA e capacidades",
    collect: collectNavegador,
  },
  {
    id: "tela",
    icon: "📺",
    title: "Tela & Display",
    subtitle: "Resolução e mídia",
    collect: collectTela,
  },
  {
    id: "armazenamento",
    icon: "💾",
    title: "Armazenamento",
    subtitle: "Cota do site",
    collect: collectArmazenamento,
  },
  {
    id: "tempo",
    icon: "⏰",
    title: "Tempo & Localização",
    subtitle: "Fuso e formatos",
    collect: collectTempo,
  },
  {
    id: "recursos",
    icon: "🧩",
    title: "Recursos",
    subtitle: "APIs disponíveis",
    collect: collectRecursos,
  },
];

/* ------------------------------------------------------------------ */
/* Renderização                                                        */
/* ------------------------------------------------------------------ */

function createCard(section, rows) {
  const el = document.createElement("section");
  el.className = "card";
  el.dataset.id = section.id;

  const head = document.createElement("header");
  head.className = "card-head";
  head.innerHTML = `
    <span class="card-icon" aria-hidden="true">${esc(section.icon)}</span>
    <div>
      <h2>${esc(section.title)}</h2>
      ${section.subtitle ? `<p>${esc(section.subtitle)}</p>` : ""}
    </div>
  `;

  const body = document.createElement("div");
  body.className = "rows";

  for (const [key, value] of rows) {
    const row = document.createElement("div");
    const text = String(value);
    const isLong = text.length > 40;
    row.className = "row" + (isLong ? " long" : "");

    const k = document.createElement("span");
    k.className = "k";
    k.textContent = key;

    const v = document.createElement("span");
    v.className = "v";
    if (value === "Sim") v.classList.add("ok");
    else if (value === "Não" || value === NA)
      v.classList.add(value === NA ? "err" : "warn");

    v.textContent = text;
    if (isLong) v.title = text;

    row.append(k, v);
    body.appendChild(row);
  }

  el.append(head, body);
  return el;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

export async function refresh() {
  const grid =
    document.getElementById("browser-cards") || document.getElementById("grid");
  if (!grid) {
    console.error(
      "[refresh] contêiner não encontrado (#browser-cards / #grid)",
    );
    return;
  }

  grid.setAttribute("aria-busy", "true");

  // Busca o snapshot do agente UMA vez, antes de coletar
  const agent = await fetchAgent();

  // Coleta tudo em paralelo
  const results = await Promise.all(
    SECTIONS.map(async (s) => {
      try {
        return { section: s, rows: await s.collect(agent) };
      } catch (err) {
        console.warn(`[refresh] erro em ${s.id}:`, err);
        return { section: s, rows: [["Erro", String(err.message || err)]] };
      }
    }),
  );

  // Monta fora do DOM
  const frag = document.createDocumentFragment();
  results.forEach(({ section, rows }, i) => {
    const card = createCard(section, rows);
    card.style.animationDelay = `${Math.min(i * 40, 400)}ms`;
    frag.appendChild(card);
  });

  // Troca atômica
  grid.replaceChildren(frag);
  grid.setAttribute("aria-busy", "false");

  const at = document.getElementById("collectedAt");
  const count = document.getElementById("sectionCount");
  if (at) at.textContent = new Date().toLocaleString("pt-BR");
  if (count) count.textContent = results.length;

  console.log(`[refresh] ${results.length} cards renderizados`, {
    agente: agent ? "online" : "offline",
  });
}
