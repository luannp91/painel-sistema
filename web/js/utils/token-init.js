// ============================================================================
// Absorve ?otk=<chave> da URL, troca pelo token real e limpa a URL.
// ============================================================================
//
// O tray abre o browser com `?otk=...` (chave de bootstrap efêmera).
// Esse módulo:
//   1. remove a `otk` da URL IMEDIATAMENTE (antes de qualquer fetch)
//   2. POSTa pra `/api/auth/exchange` com a chave
//   3. salva o token real em localStorage['painel_token']
//
// O token real nunca aparece na URL — só a chave efêmera, que rotaciona
// a cada 5 min no servidor.
//
// Suporta também o formato antigo `?token=` (compat): salva direto sem
// trocar. Útil durante transição, pode ser removido depois.

const TOKEN_KEY = "painel_token";

function cleanUrl(params) {
  const qs = params.toString();
  const clean = location.pathname + (qs ? "?" + qs : "");
  history.replaceState(null, "", clean);
}

async function absorbFromUrl() {
  try {
    const params = new URLSearchParams(location.search);
    const otk = params.get("otk");
    const legacy = params.get("token");

    // Compat com formato antigo
    if (legacy) {
      localStorage.setItem(TOKEN_KEY, legacy);
      params.delete("token");
      cleanUrl(params);
      return;
    }

    if (!otk) return;

    // Remove a OTK da URL antes do fetch — minimiza exposição visual
    params.delete("otk");
    cleanUrl(params);

    const res = await fetch("/api/auth/exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ otk }),
    });

    if (!res.ok) {
      console.warn("[token-init] exchange falhou:", res.status);
      return;
    }

    const data = await res.json();
    if (data.token) {
      localStorage.setItem(TOKEN_KEY, data.token);
    }
  } catch (e) {
    console.warn("[token-init] erro:", e);
  }
}

/// Promise que resolve quando a troca termina (ou imediatamente se não
/// havia `otk`). `rest.js` e `sse.js` aguardam antes de fazer requests.
export const tokenReady = absorbFromUrl();
