import { $ } from "./utils/dom.js";
import { initTheme } from "./ui/theme.js";
import { startClock } from "./ui/clock.js";
import { showToast } from "./ui/toast.js";
import { refresh } from "./actions/refresh.js";
import { copyJSON } from "./actions/copy.js";
import { exportJSON } from "./actions/export.js";
import { buildLiveCards, initLive } from "./ui/live.js";
import { initNotifications, toggleNotifications } from "./ui/notifications.js";
import { initUpdateCheck } from "./ui/updateBanner.js";

function init() {
  console.log("[main] iniciando…");

  initTheme();
  startClock();

  // Preenche #live-cards (que já existe no HTML)
  buildLiveCards();
  initLive();

  // Preenche #browser-cards (que já existe no HTML)
  refresh();

  // Notificações nativas
  initNotifications();

  initUpdateCheck();

  // Listeners
  window.addEventListener("online", () => showToast("📡 Reconectado"));
  window.addEventListener("offline", () => showToast("📴 Offline"));

  $("#btnRefresh")?.addEventListener("click", () => {
    refresh();
    showToast("🔄 Atualizando…", 1200);
  });
  $("#btnCopy")?.addEventListener("click", copyJSON);
  $("#btnExport")?.addEventListener("click", exportJSON);

  $("#btnNotifications")?.addEventListener("click", async () => {
    const result = await toggleNotifications();

    if (result?.ok === false) {
      if (result.reason === "unsupported") {
        showToast("❌ Notificações não suportadas neste navegador");
      } else if (result.reason === "denied") {
        showToast(
          "🔒 Permissão negada — reative nas configurações do navegador",
        );
      }
      return;
    }

    if (result?.enabled === false || result?.ok === false) {
      showToast("🔕 Notificações desativadas");
    } else {
      showToast("🔔 Notificações ativadas!");
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, textarea")) return;
    if (e.key === "r" || e.key === "R") refresh();
    if (e.key === "c" || e.key === "C") copyJSON();
    if (e.key === "e" || e.key === "E") exportJSON();
    if (e.key === "n" || e.key === "N") {
      $("#btnNotifications")?.click();
    }
  });
}

document.addEventListener("DOMContentLoaded", init);
