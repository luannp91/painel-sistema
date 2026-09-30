import { NA } from "../utils/safe.js";
import { yesNo } from "../utils/format.js";
import { detectBrowser, detectEngine } from "../utils/detect.js";

export async function collectNavegador(high) {
    const browser = detectBrowser();
    const version = high.uaFullVersion || browser.version;

    const brands = (navigator.userAgentData?.brands || [])
        .filter((b) => !/Not.?A.?Brand/i.test(b.brand))
        .map((b) => `${b.brand} ${b.version}`)
        .join(", ");

    return [
        ["Navegador", browser.name],
        ["Versão", version],
        ["Motor de renderização", detectEngine()],
        ["Fabricante", navigator.vendor || NA],
        ["Marcas (UA-CH)", brands || NA],
        ["Cookies habilitados", yesNo(navigator.cookieEnabled)],
        ["Do Not Track", navigator.doNotTrack ?? NA],
        ["Leitor de PDF nativo", yesNo(navigator.pdfViewerEnabled)],
        ["Automação (WebDriver)", yesNo(navigator.webdriver)],
        ["Plataforma declarada", navigator.platform || NA],
        ["User Agent", navigator.userAgent]
    ];
}
