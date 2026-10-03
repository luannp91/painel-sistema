/* =========================================================
   Notificações nativas do sistema (Windows/Linux/macOS)
   Consulta /api/patterns periodicamente e dispara toast do SO
   para padrões de nível "Error" que ainda não foram notificados.
   ========================================================= */

import { apiFetch } from "../api/rest.js";

const STORAGE_KEY = "sysinfo-notif-state";
const NOTIFIED_KEY = "sysinfo-notified-patterns";
const POLL_INTERVAL_MS = 3000;

const LEVELS_TO_NOTIFY = new Set(["Error"]); // só erros disparam toast

let state = {
  enabled: false,
  supported: false,
  permission: "default",
  pollTimer: null,
  notifiedIds: new Set(),
};

/* ------------------------------------------------------------------ */
/* Persistência leve                                                   */
/* ------------------------------------------------------------------ */

function loadPrefs() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === "on") state.enabled = true;
    if (raw === "off") state.enabled = false;
  } catch {
    /* ignora */
  }

  try {
    const raw = sessionStorage.getItem(NOTIFIED_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) state.notifiedIds = new Set(arr);
    }
  } catch {
    /* ignora */
  }
}

function savePrefs() {
  try {
    localStorage.setItem(STORAGE_KEY, state.enabled ? "on" : "off");
  } catch {
    /* ignora */
  }
}

function saveNotified() {
  try {
    // Limita o conjunto a 500 IDs para não crescer indefinidamente
    const arr = Array.from(state.notifiedIds).slice(-500);
    sessionStorage.setItem(NOTIFIED_KEY, JSON.stringify(arr));
  } catch {
    /* ignora */
  }
}

/* ------------------------------------------------------------------ */
/* Suporte e permissão                                                 */
/* ------------------------------------------------------------------ */

function checkSupport() {
  state.supported = typeof Notification !== "undefined";
  if (!state.supported) {
    state.permission = "unsupported";
    return;
  }
  state.permission = Notification.permission;
}

async function requestPermission() {
  if (!state.supported) return "unsupported";
  if (Notification.permission === "granted") return "granted";
  if (Notification.permission === "denied") return "denied";

  try {
    const p = await Notification.requestPermission();
    state.permission = p;
    return p;
  } catch {
    return "denied";
  }
}

/* ------------------------------------------------------------------ */
/* Envio de notificação                                                */
/* ------------------------------------------------------------------ */

function notify(pattern) {
  if (!state.supported || Notification.permission !== "granted") return;

  const title = `🔴 ${pattern.title}`;
  const body = pattern.detail || "Padrão crítico detectado";

  try {
    const n = new Notification(title, {
      body,
      tag: pattern.id, // evita duplicatas no próprio SO
      requireInteraction: false,
      silent: false,
      icon: "/assets/icons/favicon.svg",
    });

    // Se o usuário clicar, foca a aba e abre a página de padrões
    n.onclick = () => {
      window.focus();
      location.href = "/patterns.html";
      n.close();
    };

    // Auto-fecha em 8s (navegadores ignoram se o SO gerencia)
    setTimeout(() => {
      try {
        n.close();
      } catch {
        /* */
      }
    }, 8000);
  } catch (err) {
    console.warn("[notifications] falha ao exibir:", err);
  }
}

/* ------------------------------------------------------------------ */
/* Polling                                                             */
/* ------------------------------------------------------------------ */

async function pollPatterns() {
  if (!state.enabled) return;

  try {
    const res = await apiFetch("/api/patterns?limit=100");
    if (!res.ok) return;

    const payload = await res.json();
    const patterns = Array.isArray(payload.patterns) ? payload.patterns : [];

    let fired = 0;

    for (const p of patterns) {
      if (!p || !p.id) continue;
      if (state.notifiedIds.has(p.id)) continue;
      if (!LEVELS_TO_NOTIFY.has(p.level)) {
        // Marca como visto sem notificar, para não reavaliar a cada poll
        state.notifiedIds.add(p.id);
        continue;
      }

      notify(p);
      state.notifiedIds.add(p.id);
      fired++;
    }

    if (fired > 0) {
      saveNotified();
      updateButtonUI();
    }
  } catch (err) {
    console.warn("[notifications] erro no polling:", err);
  }
}

function startPolling() {
  if (state.pollTimer) return;
  state.pollTimer = setInterval(pollPatterns, POLL_INTERVAL_MS);
  pollPatterns(); // imediato
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

/* ------------------------------------------------------------------ */
/* API pública                                                         */
/* ------------------------------------------------------------------ */

export async function enableNotifications() {
  checkSupport();

  if (!state.supported) {
    return { ok: false, reason: "unsupported" };
  }

  const perm = await requestPermission();
  if (perm !== "granted") {
    return { ok: false, reason: perm };
  }

  state.enabled = true;
  state.permission = "granted";
  savePrefs();
  startPolling();
  updateButtonUI();
  return { ok: true };
}

export function disableNotifications() {
  state.enabled = false;
  savePrefs();
  stopPolling();
  updateButtonUI();
}

export function toggleNotifications() {
  if (state.enabled) {
    disableNotifications();
    return { enabled: false };
  }
  return enableNotifications();
}

export function getNotificationState() {
  return {
    enabled: state.enabled,
    supported: state.supported,
    permission: state.permission,
  };
}

/* ------------------------------------------------------------------ */
/* UI — estado do botão no topbar                                      */
/* ------------------------------------------------------------------ */

function updateButtonUI() {
  const btn = document.getElementById("btnNotifications");
  if (!btn) return;

  btn.classList.toggle("active", state.enabled);
  btn.textContent = state.enabled ? "🔔" : "🔕";

  let title;
  if (!state.supported) {
    title = "Notificações não suportadas neste navegador";
  } else if (state.permission === "denied") {
    title = "Notificações bloqueadas — reative nas configurações do navegador";
  } else if (state.enabled) {
    title = "Notificações ativas — clique para desativar";
  } else {
    title = "Notificações desativadas — clique para ativar";
  }

  btn.title = title;
  btn.setAttribute("aria-label", title);
}

/* ------------------------------------------------------------------ */
/* Bootstrap                                                           */
/* ------------------------------------------------------------------ */

export function initNotifications() {
  loadPrefs();
  checkSupport();
  updateButtonUI();

  // Se já estava habilitado e a permissão continua valendo, retoma o polling
  if (state.enabled && state.permission === "granted") {
    startPolling();
  } else if (state.enabled && state.permission !== "granted") {
    // Usuário tinha ativado mas revogou a permissão — desliga
    state.enabled = false;
    savePrefs();
    updateButtonUI();
  }

  // Se o usuário mudar a permissão nas configs do navegador
  if (state.supported && navigator.permissions?.query) {
    try {
      navigator.permissions
        .query({ name: "notifications" })
        .then((status) => {
          status.addEventListener?.("change", () => {
            checkSupport();
            if (state.permission !== "granted") {
              state.enabled = false;
              savePrefs();
              stopPolling();
            } else if (state.enabled) {
              startPolling();
            }
            updateButtonUI();
          });
        })
        .catch(() => {
          /* ignora */
        });
    } catch {
      /* ignora */
    }
  }
}
