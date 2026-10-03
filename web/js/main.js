import { $ } from "./utils/dom.js";
import { initTheme } from "./ui/theme.js";
import { startClock } from "./ui/clock.js";
import { showToast } from "./ui/toast.js";
import { refresh } from "./actions/refresh.js";
import { copyJSON } from "./actions/copy.js";
import { exportJSON } from "./actions/export.js";
import { buildLiveCards, initLive } from "./ui/live.js";

function init() {
  console.log("[main] iniciando…");

  initTheme();
  startClock();

  // Preenche #live-cards (que já existe no HTML)
  buildLiveCards();
  initLive();

  // Preenche #browser-cards (que já existe no HTML)
  refresh();

  window.addEventListener("online", () => showToast("📡 Reconectado"));
  window.addEventListener("offline", () => showToast("📴 Offline"));

  $("#btnRefresh")?.addEventListener("click", () => {
    refresh();
    showToast("🔄 Atualizando…", 1200);
  });
  $("#btnCopy")?.addEventListener("click", copyJSON);
  $("#btnExport")?.addEventListener("click", exportJSON);

  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, textarea")) return;
    if (e.key === "r" || e.key === "R") refresh();
    if (e.key === "c" || e.key === "C") copyJSON();
    if (e.key === "e" || e.key === "E") exportJSON();
  });
}

document.addEventListener("DOMContentLoaded", init);
