export const NA = "Não disponível";

export const isNA = (v) =>
  v === undefined ||
  v === null ||
  v === "" ||
  (typeof v === "number" && !Number.isFinite(v)) ||
  (Array.isArray(v) && v.length === 0);

export async function safe(fn, fallback = NA) {
  try {
    const value = typeof fn === "function" ? await fn() : await fn;
    return isNA(value) ? fallback : value;
  } catch {
    return fallback;
  }
}
