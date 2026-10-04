/* =========================================================
   Banner de auto-update
   Mostra apenas downloads compatíveis com o SO/arch detectado
   pelo backend.
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
  if (!n && n !== 0) return "";
  const u = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

/** Label amigável por tipo de artefato. */
function kindLabel(kind) {
  return (
    {
      exe: "Windows (.exe)",
      msi: "Windows (.msi)",
      deb: "Linux (.deb)",
      rpm: "Linux (.rpm)",
      binary: "Binário",
      dmg: "macOS (.dmg)",
      pkg: "macOS (.pkg)",
      appimage: "Linux (.AppImage)",
      tarball: "Tarball (.tar.gz)",
    }[kind] || kind
  );
}

function platformLabel(platform, arch) {
  const os =
    {
      windows: "Windows",
      linux: "Linux",
      macos: "macOS",
      freebsd: "FreeBSD",
    }[platform] || platform;

  const a =
    {
      x86_64: "x64",
      aarch64: "ARM64",
      x86: "x86",
    }[arch] || arch;

  return `${os} ${a}`;
}

function ensureBanner() {
  if (bannerEl) return bannerEl;

  bannerEl = document.createElement("div");
  bannerEl.id = "update-banner";
  bannerEl.className = "update-banner";
  bannerEl.setAttribute("role", "alert");
  bannerEl.setAttribute("aria-live", "polite");
  bannerEl.style.display = "none";

  const header = document.querySelector(".topbar");
  if (header && header.parentNode) {
    header.parentNode.insertBefore(bannerEl, header.nextSibling);
  } else {
    document.body.insertBefore(bannerEl, document.body.firstChild);
  }

  return bannerEl;
}

function showBanner(info) {
  const el = ensureBanner();

  const downloads = Array.isArray(info.downloads) ? info.downloads : [];

  // Se não houver download compatível, mostra aviso
  if (!downloads.length) {
    el.innerHTML = `
      <div class="update-content">
        <span class="update-icon" aria-hidden="true">🎉</span>
        <div class="update-text">
          <strong>Nova versão disponível!</strong>
          <p>
            Você está usando a <code>${esc(info.current)}</code>,
            mas a <code>${esc(info.latest)}</code> já foi lançada.
          </p>
          <p class="update-warn">
            ⚠️ Nenhum pacote compatível com <strong>${esc(platformLabel(info.platform, info.arch))}</strong>
            foi encontrado nesta release.
          </p>
        </div>
        <div class="update-actions">
          ${info.html_url ? `<a class="btn" href="${esc(info.html_url)}" target="_blank" rel="noopener">Ver no GitHub</a>` : ""}
          <button class="btn ghost update-close" data-dismiss="${esc(info.latest)}" title="Dispensar">✕</button>
        </div>
      </div>
    `;
    el.style.display = "block";
    attachClose(el);
    return;
  }

  const primary = downloads[0];
  const others = downloads.slice(1);

  const sizeStr = primary.size_bytes
    ? ` · ${fmtBytes(primary.size_bytes)}`
    : "";

  const othersHtml = others.length
    ? `<div class="update-others">
         <span class="update-others-label">Também disponível:</span>
         ${others
           .map(
             (d) =>
               `<a class="update-other-link" href="${esc(d.url)}" target="_blank" rel="noopener"
               title="${esc(d.name)}${d.size_bytes ? " · " + fmtBytes(d.size_bytes) : ""}">
              ${esc(kindLabel(d.kind))}
            </a>`,
           )
           .join("")}
       </div>`
    : "";

  const notes = info.release_notes
    ? `<details><summary>Notas da versão</summary><pre>${esc(info.release_notes.slice(0, 2000))}</pre></details>`
    : "";

  el.innerHTML = `
    <div class="update-content">
      <span class="update-icon" aria-hidden="true">🎉</span>
      <div class="update-text">
        <strong>Nova versão disponível!</strong>
        <p>
          Você está usando a <code>${esc(info.current)}</code>,
          mas a <code>${esc(info.latest)}</code> já foi lançada.
          <span class="update-platform">Detectado: ${esc(platformLabel(info.platform, info.arch))}</span>
        </p>
        ${othersHtml}
        ${notes}
      </div>
      <div class="update-actions">
        <a class="btn update-primary" href="${esc(primary.url)}" target="_blank" rel="noopener"
           title="${esc(primary.name)}">
          ⬇️ Baixar ${esc(kindLabel(primary.kind))}${esc(sizeStr)}
        </a>
        ${info.html_url ? `<a class="btn ghost" href="${esc(info.html_url)}" target="_blank" rel="noopener">Ver no GitHub</a>` : ""}
        <button class="btn ghost update-close" data-dismiss="${esc(info.latest)}" title="Dispensar">✕</button>
      </div>
    </div>
  `;

  el.style.display = "block";
  attachClose(el);
}

function attachClose(el) {
  el.querySelector(".update-close")?.addEventListener("click", (e) => {
    const v = e.currentTarget.dataset.dismiss;
    dismiss(v);
    el.style.display = "none";
  });
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
    // Falha silenciosa
  }
}

export function initUpdateCheck() {
  setTimeout(checkNow, 5000);

  if (checkTimer) clearInterval(checkTimer);
  checkTimer = setInterval(checkNow, CHECK_INTERVAL_MS);
}
