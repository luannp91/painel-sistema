/* =========================================================
   API REST do agente Rust (mesma origem) + token
   ========================================================= */

const TOKEN_KEY = "painel_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

export function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function authHeaders() {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

/**
 * fetch com token. Se receber 401 na primeira tentativa, pede o
 * token ao usuario e tenta uma vez mais. Se falhar de novo, propaga.
 */
export async function apiFetch(path, opts = {}, retried = false) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...(opts.headers || {}), ...authHeaders() },
  });

  if (res.status === 401 && !retried) {
    const novo = prompt("Token de acesso necessario:");
    if (novo) {
      setToken(novo.trim());
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
