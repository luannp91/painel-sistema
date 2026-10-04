/* =========================================================
   Banner de auto-update
   Consulta /api/update-check na inicialização e a cada 6h.
   ========================================================= */

import { apiFetch } from "../api/rest.js";

const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 horas
const DISMISSED_KEY = "sysinfo-update-dismissed";

let bannerEl = null;
let checkTimer = null;

function isDismissed(version) {
  try {
    return localStorage.getItem(DISMISSED_KEY) === version;
  } catch {
    return false;
  }
}

function dismiss(version) {
  try {
    localStorage.setItem(DISMISSED_KEY, version);
  } catch {
    /* ignora */
  }
}

function ensureBanner() {
  if (bannerEl) return bannerEl;

  bannerEl = document.createElement("div");
  bannerEl.id = "update-banner";
  bannerEl.className = "update-banner";
  bannerEl.setAttribute("role", "alert");
  bannerEl.setAttribute("aria-live", "polite");
  bannerEl.style.display = "none";

  const app = document.querySelector(".app") || document.body;
  const header = document.querySelector(".topbar");
  if (header && header.parentNode) {
    header.parentNode.insertBefore(bannerEl, header.nextSibling);
  } else {
    app.insertBefore(bannerEl, app.firstChild);
  }

  return bannerEl;
}

function showBanner(info) {
  const el = ensureBanner();

  const notes = info.release_notes
    ? `<details><summary>Notas da versão</summary><pre>${escapeHtml(info.release_notes.slice(0, 2000))}</pre></details>`
    : "";

  const downloadBtn = info.download_url
    ? `<a class="btn" href="${info.download_url}" target="_blank" rel="noopener">⬇️ Baixar ${escapeHtml(info.latest)}</a>`
    : "";

  const releaseLink = info.html_url
    ? `<a class="btn ghost" href="${info.html_url}" target="_blank" rel="noopener">Ver no GitHub</a>`
    : "";

  el.innerHTML = `
    <div class="update-content">
      <span class="update-icon" aria-hidden="true">🎉</span>
      <div class="update-text">
        <strong>Nova versão disponível!</strong>
        <p>
          Você está usando a <code>${escapeHtml(info.current)}</code>,
          mas a <code>${escapeHtml(info.latest)}</code> já foi lançada.
        </p>
        ${notes}
      </div>
      <div class="update-actions">
        ${downloadBtn}
        ${releaseLink}
        <button class="btn ghost update-close" data-dismiss="${escapeHtml(info.latest)}" title="Dispensar">
          ✕
        </button>
      </div>
    </div>
  `;

  el.style.display = "block";

  el.querySelector(".update-close")?.addEventListener("click", (e) => {
    const v = e.currentTarget.dataset.dismiss;
    dismiss(v);
    el.style.display = "none";
  });
}

function escapeHtml(s) {
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

async function checkNow() {
  try {
    const res = await apiFetch("/api/update-check", {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return;

    const info = await res.json();
    if (!info.has_update) return;
    if (isDismissed(info.latest)) return;

    showBanner(info);
  } catch {
    // Falha silenciosa — não incomoda o usuário
  }
}

export function initUpdateCheck() {
  // Primeira checagem 5s depois do carregamento (não bloqueia o boot)
  setTimeout(checkNow, 5000);

  // Recorrente
  if (checkTimer) clearInterval(checkTimer);
  checkTimer = setInterval(checkNow, CHECK_INTERVAL_MS);
}
