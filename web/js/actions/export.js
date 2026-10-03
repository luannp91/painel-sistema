import { apiFetch } from "../api/rest.js";
import { showToast } from "../ui/toast.js";

export async function exportJSON() {
  try {
    const res = await apiFetch("/api/snapshot");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    a.href = url;
    a.download = `sistema-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast("⬇️ Arquivo exportado!");
  } catch (err) {
    console.error("[export] erro:", err);
    showToast("❌ Falha ao exportar.");
  }
}
