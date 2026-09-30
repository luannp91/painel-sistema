import { $ } from "./utils/dom.js";
import { initTheme } from "./ui/theme.js";
import { startClock } from "./ui/clock.js";
import { showToast } from "./ui/toast.js";
import { refresh } from "./actions/refresh.js";
import { copyJSON } from "./actions/copy.js";
import { exportJSON } from "./actions/export.js";

function initNetworkListeners() {
    window.addEventListener("online", () => {
        showToast("📡 Conexão restabelecida. Atualizando…");
        refresh();
    });
    window.addEventListener("offline", () => {
        showToast("📴 Você está offline.");
    });
}

function init() {
    initTheme();
    startClock();
    initNetworkListeners();

    $("#btnRefresh").addEventListener("click", () => {
        refresh();
        showToast("🔄 Atualizando informações…", 1200);
    });

    $("#btnCopy").addEventListener("click", copyJSON);
    $("#btnExport").addEventListener("click", exportJSON);

    // Atalhos de teclado
    document.addEventListener("keydown", (e) => {
        if (e.target.matches("input, textarea")) return;
        if (e.key === "r" || e.key === "R") refresh();
        if (e.key === "c" || e.key === "C") copyJSON();
        if (e.key === "e" || e.key === "E") exportJSON();
    });

    refresh();
}

document.addEventListener("DOMContentLoaded", init);
