/* =========================================================
   Formatação — bytes, duração, permissões, booleanos
   ========================================================= */

import { NA, isNA } from "./safe.js";

export const yesNo = (v) => (v ? "Sim" : "Não");

export function pad2(n) {
    return String(n).padStart(2, "0");
}

/** Formata bytes em unidade legível. */
export function fmtBytes(bytes) {
    if (isNA(bytes) || typeof bytes !== "number") return NA;
    const units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let n = bytes;
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
        n /= 1024;
        i++;
    }
    return `${n.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

/** Formata segundos em "1h 20min 5s". */
export function fmtDuration(seconds) {
    if (isNA(seconds) || !Number.isFinite(seconds)) return NA;
    const s = Math.round(seconds);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const parts = [];
    if (h) parts.push(`${h}h`);
    if (m) parts.push(`${m}min`);
    parts.push(`${sec}s`);
    return parts.join(" ");
}

/** Rótulo legível para estados de permissão. */
export function permissionLabel(state) {
    return (
        {
            granted: "Concedida",
            denied: "Negada",
            prompt: "Perguntar"
        }[state] || state
    );
}
