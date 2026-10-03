import { showToast } from "../ui/toast.js";

export async function copyJSON() {
  try {
    const res = await fetch("/api/snapshot");
    const data = await res.json();
    await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    showToast("✅ Snapshot copiado!");
  } catch {
    showToast("❌ Falha ao copiar.");
  }
}
