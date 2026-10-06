// ============================================================================
// Absorve ?token=xxx da URL pra localStorage e limpa a URL.
// ============================================================================
//
// O tray abre o browser com `?token=...` quando auth está habilitada.
// Este módulo pega esse token, grava em `painel_token` (mesma chave que
// `api/rest.js` usa) e reescreve a URL sem o parâmetro — assim o token
// não fica no histórico do browser nem em bookmarks acidentais.
//
// Roda como efeito colateral do import.

const TOKEN_KEY = "painel_token";

function absorbTokenFromUrl() {
  try {
    const params = new URLSearchParams(location.search);
    const token = params.get("token");
    if (!token) return;

    localStorage.setItem(TOKEN_KEY, token);
    params.delete("token");

    const clean =
      location.pathname + (params.toString() ? "?" + params.toString() : "");
    history.replaceState(null, "", clean);
  } catch {
    // silencioso — não vale quebrar a página por isso
  }
}

absorbTokenFromUrl();
