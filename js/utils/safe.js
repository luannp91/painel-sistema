/* =========================================================
   Utilitários de segurança — fallback e verificação de vazio
   ========================================================= */

export const NA = "Não disponível";

/** Verifica se um valor é "vazio" para os nossos propósitos. */
export const isNA = (v) =>
    v === undefined ||
    v === null ||
    v === "" ||
    (typeof v === "number" && !Number.isFinite(v)) ||
    (Array.isArray(v) && v.length === 0);

/**
 * Executa uma função/promise com segurança.
 * Retorna `fallback` em caso de erro ou valor vazio.
 */
export async function safe(fn, fallback = NA) {
    try {
        const value = typeof fn === "function" ? await fn() : await fn;
        return isNA(value) ? fallback : value;
    } catch {
        return fallback;
    }
}
