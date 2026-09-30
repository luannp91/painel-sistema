import { esc } from "../utils/dom.js";
import { NA } from "../utils/safe.js";
import { SECTIONS_META, GROUPS } from "../config.js";

/* ------------------------------------------------------------------ */
/* Card comum                                                          */
/* ------------------------------------------------------------------ */

export function createCard(section) {
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

    for (const [key, value] of section.rows) {
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
        else if (value === "Não" || value === NA) v.classList.add(value === NA ? "err" : "warn");

        v.textContent = text;
        if (isLong) v.title = text;

        row.append(k, v);
        body.appendChild(row);
    }

    el.append(head, body);
    return el;
}

/* ------------------------------------------------------------------ */
/* Card de resumo (hero)                                               */
/* ------------------------------------------------------------------ */

export function createSummaryCard(data) {
    const card = document.createElement("section");
    card.className = "card summary-card";
    card.dataset.id = "resumo";

    const stats = [
        {
            icon: data.iconOS,
            label: "Sistema",
            value: data.osName,
            meta: data.osVersion
        },
        {
            icon: data.iconBrowser,
            label: "Navegador",
            value: data.browserName,
            meta: data.browserVersion
        },
        {
            icon: "📺",
            label: "Tela",
            value: data.screenRes,
            meta: "pixels"
        },
        {
            icon: "⚙️",
            label: "CPU",
            value: `${data.cores} núcleos`,
            meta: `RAM ${data.ram}`
        },
        {
            icon: data.online === "Online" ? "🟢" : "🔴",
            label: "Rede",
            value: data.online,
            meta: "status atual"
        }
    ];

    const html = stats
        .map(
            (s) => `
      <div class="summary-item">
        <span class="summary-icon" aria-hidden="true">${esc(s.icon)}</span>
        <div class="summary-body">
          <span class="summary-label">${esc(s.label)}</span>
          <span class="summary-value">${esc(String(s.value))}</span>
          <span class="summary-meta">${esc(String(s.meta))}</span>
        </div>
      </div>`
        )
        .join("");

    card.innerHTML = `<div class="summary-grid">${html}</div>`;
    return card;
}

/* ------------------------------------------------------------------ */
/* Render principal — agora com grupos                                 */
/* ------------------------------------------------------------------ */

/**
 * @param {object} payload
 * @param {object} payload.summary   Dados do card de destaque
 * @param {Array}  payload.sections  Lista de seções ({ id, rows })
 * @param {HTMLElement} container    Elemento onde renderizar
 */
/* Adicione este bloco no início de renderDashboard() */
export function renderDashboard(payload, container) {
    container.innerHTML = "";
    const frag = document.createDocumentFragment();

    // Aviso de contexto inseguro
    if (typeof window !== "undefined" && window.isSecureContext === false) {
        const warn = document.createElement("div");
        warn.className = "context-warning";
        warn.innerHTML = `
      <strong>⚠️ Contexto inseguro detectado</strong>
      <p>Você está em <code>${esc(location.protocol)}</code>. Várias APIs
      (Storage, MediaDevices, Service Worker, Serial, etc.) só funcionam em
      <code>https://</code> ou <code>http://localhost</code>.
      Rode <code>node server.js</code> e acesse
      <code>http://localhost:8000</code>.</p>
    `;
        frag.appendChild(warn);
    }

    // ...resto do código continua igual
}

export function renderDashboard(payload, container) {
    container.innerHTML = "";
    const frag = document.createDocumentFragment();

    // 1) Card de resumo (ocupa a largura toda)
    frag.appendChild(createSummaryCard(payload.summary));

    // 2) Mapa de seções por id, para lookup rápido
    const byId = Object.fromEntries(payload.sections.map((s) => [s.id, s]));

    // 3) Itera os grupos, criando um bloco por grupo
    for (const group of GROUPS) {
        const groupSections = group.sections
            .map((id) => {
                const s = byId[id];
                if (!s) return null;
                return {
                    id,
                    ...SECTIONS_META[id],
                    rows: s.rows
                };
            })
            .filter(Boolean);

        // Grupo vazio (ex.: sem Firefox) — pula
        if (!groupSections.length) continue;

        const groupEl = document.createElement("section");
        groupEl.className = "group";
        groupEl.dataset.group = group.id;

        const header = document.createElement("header");
        header.className = "group-header";
        header.innerHTML = `
      <span class="group-icon" aria-hidden="true">${esc(group.icon)}</span>
      <h2 class="group-title">${esc(group.title)}</h2>
      <span class="group-count">${groupSections.length}</span>
    `;

        const grid = document.createElement("div");
        grid.className = "grid";

        groupSections.forEach((section, i) => {
            const card = createCard(section);
            card.style.animationDelay = `${Math.min(i * 40, 400)}ms`;
            grid.appendChild(card);
        });

        groupEl.append(header, grid);
        frag.appendChild(groupEl);
    }

    container.appendChild(frag);
}
