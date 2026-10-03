import { apiFetch } from "../api/rest.js";
import { showToast } from "../ui/toast.js";

export async function copyJSON() {
  try {
    const res = await apiFetch("/api/snapshot");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    showToast("✅ Snapshot copiado!");
  } catch (err) {
    console.error("[copy] erro:", err);
    showToast("❌ Falha ao copiar.");
  }
}
