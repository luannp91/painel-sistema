import { NA } from "../utils/safe.js";
import { fmtDuration } from "../utils/format.js";

export async function collectTempo() {
    const now = new Date();
    const offsetMin = -now.getTimezoneOffset();
    const sign = offsetMin >= 0 ? "+" : "-";
    const abs = Math.abs(offsetMin);
    const offset = `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:` + String(abs % 60).padStart(2, "0");

    const intl = Intl.DateTimeFormat().resolvedOptions();

    const rows = [
        ["Data e hora local", now.toLocaleString("pt-BR")],
        ["UTC", now.toUTCString()],
        ["Fuso horário", intl.timeZone || NA],
        ["Offset", offset],
        ["Locale", intl.locale || NA],
        ["Calendário", intl.calendar || NA],
        ["Numeração", intl.numberingSystem || NA],
        ["Uptime da página", fmtDuration(performance.now() / 1000)]
    ];

    try {
        const loc = new Intl.Locale(intl.locale);
        const week = loc.weekInfo || loc.getWeekInfo?.();
        if (week?.firstDay) {
            const days = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"];
            rows.push(["Primeiro dia da semana", days[week.firstDay - 1] || NA]);
        }
    } catch {
        /* ignorado */
    }

    return rows;
}
