// ============================================================================
// Preenche todos os <span class="version"> da página com a versão do binário.
// ============================================================================
//
// Roda como efeito colateral do import — basta `import "./ui/version.js";`
// no topo do módulo de cada página. Lê /api/health (endpoint público, sem
// token) que agora expõe `version`.

async function fillVersion() {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) return;
    const data = await res.json();
    if (!data.version) return;
    const label = `v${data.version}`;
    document.querySelectorAll(".version").forEach((el) => {
      el.textContent = label;
    });
  } catch {
    // Silencioso: se falhar, o placeholder "v…" fica visível — melhor
    // que derrubar o console com erro de rede.
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", fillVersion);
} else {
  fillVersion();
}
