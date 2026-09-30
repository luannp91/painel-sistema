import { buildJSON } from "./copy.js";
import { showToast } from "../ui/toast.js";

export function exportJSON() {
    const blob = new Blob([buildJSON()], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    a.href = url;
    a.download = `sistema-info-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast("⬇️ Arquivo JSON exportado!");
}
