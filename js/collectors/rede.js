import { NA } from "../utils/safe.js";
import { yesNo } from "../utils/format.js";

export async function collectRede() {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;

    return [
        ["Status", navigator.onLine ? "Online" : "Offline"],
        ["Tipo efetivo", conn?.effectiveType?.toUpperCase() ?? NA],
        ["Tipo físico", conn?.type ?? NA],
        ["Downlink estimado", conn?.downlink !== undefined ? `${conn.downlink} Mbps` : NA],
        ["Latência (RTT)", conn?.rtt !== undefined ? `${conn.rtt} ms` : NA],
        ["Economia de dados", conn?.saveData !== undefined ? yesNo(conn.saveData) : NA],
        ["Mudança de rede", conn ? "Suportada" : "Não suportada"],
        ["Máx. conexões simultâneas", conn?.downlinkMax ? `${conn.downlinkMax} Mbps` : NA]
    ];
}
