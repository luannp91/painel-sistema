import { NA } from "../utils/safe.js";
import { yesNo, fmtDuration } from "../utils/format.js";

export async function collectBateria() {
    if (typeof navigator.getBattery !== "function") {
        return [
            ["API de Bateria", "Não suportada neste navegador"],
            ["Observação", "Disponível apenas no Chrome/Edge (contexto seguro)"]
        ];
    }

    try {
        const b = await navigator.getBattery();
        const level = Math.round(b.level * 100);

        return [
            ["Nível da bateria", `${level}%`],
            ["Carregando", yesNo(b.charging)],
            ["Tempo até descarregar", fmtDuration(b.dischargingTime)],
            ["Tempo até carregar", fmtDuration(b.chargingTime)]
        ];
    } catch {
        return [["API de Bateria", NA]];
    }
}
