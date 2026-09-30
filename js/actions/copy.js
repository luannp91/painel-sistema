import { state } from "../state.js";
import { showToast } from "../ui/toast.js";

/** Serializa o estado atual como JSON formatado. */
export function buildJSON() {
    return JSON.stringify(
        {
            geradoEm: new Date().toISOString(),
            userAgent: navigator.userAgent,
            dados: state.json
        },
        null,
        2
    );
}

export async function copyJSON() {
    const text = buildJSON();

    try {
        await navigator.clipboard.writeText(text);
        showToast("✅ Informações copiadas para a área de transferência!");
    } catch {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try {
            document.execCommand("copy");
            showToast("✅ Informações copiadas!");
        } catch {
            showToast("❌ Não foi possível copiar.");
        }
        document.body.removeChild(ta);
    }
}
