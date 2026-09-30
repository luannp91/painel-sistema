import { NA, safe } from "../utils/safe.js";
import { yesNo } from "../utils/format.js";
import { detectOS } from "../utils/detect.js";

export async function collectSistema(high) {
    const os = detectOS(high);
    const tz = await safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone, NA);

    return [
        ["Sistema operacional", os.name],
        ["Versão do SO", os.version],
        ["Plataforma", high.platform || navigator.platform || NA],
        ["Versão da plataforma", high.platformVersion || NA],
        ["Arquitetura", high.architecture || NA],
        ["Bitness", high.bitness ? `${high.bitness} bits` : NA],
        ["Modelo do dispositivo", high.model || NA],
        ["Núcleos de CPU", navigator.hardwareConcurrency ?? NA],
        ["Memória RAM (aprox.)", navigator.deviceMemory ? `${navigator.deviceMemory} GB` : NA],
        ["Idioma do sistema", navigator.language || NA],
        ["Idiomas preferidos", (navigator.languages || []).join(", ") || NA],
        ["Fuso horário", tz],
        ["Modo 64-bit (WOW64)", high.wow64 === undefined ? NA : yesNo(high.wow64)]
    ];
}
