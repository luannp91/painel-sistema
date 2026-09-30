/* =========================================================
   Coletor: resumo em destaque (hero card)
   Retorna estrutura pronta para o card de resumo.
   ========================================================= */

import { NA } from "../utils/safe.js";
import { detectOS, detectBrowser } from "../utils/detect.js";

export async function collectResumo() {
    const os = detectOS();
    const browser = detectBrowser();

    const screenRes = `${screen.width}×${screen.height}`;
    const cores = navigator.hardwareConcurrency ?? NA;
    const ram = navigator.deviceMemory ? `${navigator.deviceMemory} GB` : NA;
    const online = navigator.onLine ? "Online" : "Offline";

    // Ícone do SO
    const iconOS = os.name.includes("Windows")
        ? "🪟"
        : os.name.includes("macOS") || os.name.includes("iOS")
          ? "🍎"
          : os.name.includes("Android")
            ? "🤖"
            : os.name.includes("Linux")
              ? "🐧"
              : os.name.includes("ChromeOS")
                ? "💠"
                : "🖥️";

    // Ícone do navegador
    const iconBrowser = browser.name.includes("Firefox")
        ? "🦊"
        : browser.name.includes("Edge")
          ? "🌊"
          : browser.name.includes("Chrome")
            ? "🟢"
            : browser.name.includes("Safari")
              ? "🧭"
              : browser.name.includes("Opera")
                ? "🎭"
                : browser.name.includes("Brave")
                  ? "🦁"
                  : "🌐";

    return {
        iconOS,
        osName: os.name,
        osVersion: os.version,
        iconBrowser,
        browserName: browser.name,
        browserVersion: browser.version,
        screenRes,
        cores,
        ram,
        online
    };
}
