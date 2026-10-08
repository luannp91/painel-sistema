/* =========================================================
   API REST do agente Rust (mesma origem) + sessão por cookie
   ========================================================= */

import { tokenReady } from "../utils/token-init.js";

/// Stubs vazios mantidos só pra não quebrar imports antigos.
/// A autenticação real vai por cookie HttpOnly — JS não vê o token.
export function getToken() {
  return "";
}
export function setToken() {}
export function clearToken() {}

let refreshing = null;

/// Pede o token ao usuário e tenta virar uma sessão (cookie).
/// Retorna `true` se conseguiu.
async function ensureSession() {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    const novo = prompt("Token de acesso necessário:");
    if (!novo) return false;
    try {
      const res = await fetch("/api/auth/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: novo.trim() }),
      });
      return res.ok;
    } catch {
      return false;
    }
  })();
  try {
    return await refreshing;
  } finally {
    refreshing = null;
  }
}

/**
 * fetch com sessão por cookie. Se receber 401 na primeira tentativa,
 * pede o token ao usuário, converte em sessão via `/api/auth/session`
 * e tenta uma vez mais.
 */
export async function apiFetch(path, opts = {}, retried = false) {
  await tokenReady.catch(() => {});

  const res = await fetch(path, opts);

  if (res.status === 401 && !retried) {
    if (await ensureSession()) {
      return apiFetch(path, opts, true);
    }
  }
  return res;
}

export async function fetchSnapshot() {
  const res = await apiFetch("/api/snapshot");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function checkHealth() {
  try {
    const res = await apiFetch("/api/health", {
      signal: AbortSignal.timeout(1500),
    });
    return res.ok;
  } catch {
    return false;
  }
}
