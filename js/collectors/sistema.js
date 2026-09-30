import { NA, safe } from "../utils/safe.js";
import { yesNo } from "../utils/format.js";
import { detectOS, detectPlatform, detectArch, deriveBitness } from "../utils/detect.js";

export async function collectSistema(high) {
    const nav = navigator;
    const os = detectOS();
    const platform = detectPlatform();
    const tz = await safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone, NA);

    const arch = detectArch(undefined, high || {});
    const bitness = high?.bitness ? `${high.bitness} bits` : deriveBitness(arch);

    return [
        ["Sistema operacional", os.name],
        ["Versão do SO", os.version],
        ["Plataforma", platform],
        ["Identificador bruto", high?.platform || nav.platform || NA],
        ["Versão da plataforma", high?.platformVersion || NA],
        ["Arquitetura", arch],
        ["Bitness", bitness],
        ["Modelo do dispositivo", high?.model || NA],
        ["Núcleos de CPU", nav.hardwareConcurrency ?? NA],
        ["Memória RAM (aprox.)", nav.deviceMemory ? `${nav.deviceMemory} GB` : NA],
        ["Idioma do sistema", nav.language || NA],
        ["Idiomas preferidos", (nav.languages || []).join(", ") || NA],
        ["Fuso horário", tz],
        ["Modo 64-bit (WOW64)", high?.wow64 === undefined ? NA : yesNo(high.wow64)]
    ];
}
