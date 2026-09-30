/* =========================================================
   Coletor: informações específicas do Firefox
   Retorna [] quando não está no Firefox, fazendo o card
   desaparecer automaticamente.
   ========================================================= */

import { NA } from "../utils/safe.js";
import { getFirefoxInfo, isFirefoxLike } from "../utils/detect.js";

export async function collectFirefox() {
    if (!isFirefoxLike()) return null;

    const info = getFirefoxInfo();
    if (!info) return null;

    const rows = [
        ["Canal", info.channel],
        ["Versão base", info.version],
        ["Build ID", info.buildID],
        ["oscpu", info.oscpu],
        ["SO (via oscpu)", info.osFromOscpu]
    ];

    // Preferências exclusivas do Firefox
    if (typeof navigator.buildID === "string") {
        rows.push(["Assinatura de build", navigator.buildID]);
    }

    // nsIAppStartup — não acessível da web, mas verificamos o product
    if (navigator.product) {
        rows.push(["navigator.product", navigator.product]);
    }

    // Firefox expõe navigator.doNotTrack com valores "1"/"0"/"unspecified"
    if (navigator.doNotTrack !== undefined) {
        const dnt = navigator.doNotTrack;
        rows.push(["Do Not Track (Firefox)", dnt === "1" ? "Ativado" : dnt === "0" ? "Desativado" : dnt]);
    }

    // Verifica resistência a fingerprint (Firefox RFP, padrão em Tor)
    const rfp = navigator.hardwareConcurrency === 2 && navigator.maxTouchPoints === 0 && screen.width === screen.height;

    if (rfp) {
        rows.push(["Anti-fingerprint", "Possível (Tor/RFP ativo)"]);
    }

    return rows;
}
