// ============================================================================
// Absorve ?otk=<chave> da URL, troca por cookie de sessão e limpa a URL.
// ============================================================================
//
// O tray abre o browser com `?otk=<chave-efêmera>`. Este módulo:
//   1. Remove `otk` da URL ANTES de qualquer fetch.
//   2. POSTa em `/api/auth/exchange` com a chave.
//   3. O servidor responde `Set-Cookie: painel_session=...`.
//
// Nada é salvo em localStorage — o cookie HttpOnly faz o resto.
// Compat: `?token=` na URL ainda é aceito, mas o browser também
// derruba ele depois de estabelecer o cookie.
//
// Roda como efeito colateral do import.

function cleanUrl(params) {
  const qs = params.toString();
  history.replaceState(null, "", location.pathname + (qs ? "?" + qs : ""));
}

async function absorbFromUrl() {
  const params = new URLSearchParams(location.search);
  const otk = params.get("otk");
  const legacy = params.get("token");

  if (!otk && !legacy) return;

  params.delete("otk");
  params.delete("token");
  cleanUrl(params);

  try {
    if (otk) {
      await fetch("/api/auth/exchange", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ otk }),
      });
    } else if (legacy) {
      // Compat: token direto na URL antiga → converte pra cookie.
      await fetch("/api/auth/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: legacy }),
      });
    }
  } catch (e) {
    console.warn("[token-init] falha ao estabelecer sessão:", e);
  }
}

/// Promise que resolve quando a troca termina (ou imediatamente se não
/// havia nem `otk` nem `token`). `rest.js` e `sse.js` aguardam antes de
/// fazer requests.
export const tokenReady = absorbFromUrl();
