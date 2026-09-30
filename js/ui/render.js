import { esc } from "../utils/dom.js";
import { NA } from "../utils/safe.js";

/** Cria o elemento DOM de um card a partir de uma seção. */
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

/** Renderiza todas as seções na grade, com animação escalonada. */
export function renderSections(sections, gridEl) {
    gridEl.innerHTML = "";
    const frag = document.createDocumentFragment();

    sections.forEach((s, i) => {
        const card = createCard(s);
        card.style.animationDelay = `${Math.min(i * 40, 400)}ms`;
        frag.appendChild(card);
    });

    gridEl.appendChild(frag);
}
