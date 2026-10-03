export async function fetchSnapshot() {
  const res = await fetch("/api/snapshot");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function checkHealth() {
  try {
    const res = await fetch("/api/health", {
      signal: AbortSignal.timeout(1500),
    });
    return res.ok;
  } catch {
    return false;
  }
}
