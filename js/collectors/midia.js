import { safe } from "../utils/safe.js";

export async function collectMidia() {
    if (!navigator.mediaDevices?.enumerateDevices) {
        return [["MediaDevices API", "Não suportada"]];
    }

    const devices = await safe(() => navigator.mediaDevices.enumerateDevices(), []);

    if (!Array.isArray(devices) || devices.length === 0) {
        return [["Dispositivos", "Nenhum dispositivo encontrado"]];
    }

    const count = (kind) => devices.filter((d) => d.kind === kind).length;

    return [
        ["Câmeras", count("videoinput")],
        ["Microfones", count("audioinput")],
        ["Saídas de áudio", count("audiooutput")],
        ["Rótulos visíveis", devices.some((d) => d.label) ? "Sim" : "Não (requer permissão)"],
        ["Total de dispositivos", devices.length]
    ];
}
