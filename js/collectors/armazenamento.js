import { safe } from "../utils/safe.js";
import { yesNo, fmtBytes } from "../utils/format.js";

export async function collectArmazenamento() {
    const rows = [];

    const est = await safe(() => navigator.storage?.estimate?.(), null);

    if (est && typeof est === "object") {
        rows.push(["Cota total", fmtBytes(est.quota)]);
        rows.push(["Uso atual", fmtBytes(est.usage)]);
        rows.push(["Uso (%)", est.quota ? `${((est.usage / est.quota) * 100).toFixed(2)}%` : "Não disponível"]);
    } else {
        rows.push(["Storage API", "Não suportada"]);
    }

    if (navigator.storage?.persisted) {
        const persisted = await safe(() => navigator.storage.persisted(), null);
        if (persisted !== null) rows.push(["Armazenamento persistente", yesNo(persisted)]);
    }

    if (performance.memory) {
        rows.push(["Limite do heap JS", fmtBytes(performance.memory.jsHeapSizeLimit)]);
        rows.push(["Heap JS usado", fmtBytes(performance.memory.usedJSHeapSize)]);
        rows.push(["Heap JS total", fmtBytes(performance.memory.totalJSHeapSize)]);
    } else {
        rows.push(["Heap JS", "Métrica não exposta pelo navegador"]);
    }

    return rows;
}
