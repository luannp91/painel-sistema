import { NA, isNA } from "./safe.js";

export const yesNo = (v) => (v ? "Sim" : "Não");
export const pad2 = (n) => String(n).padStart(2, "0");

export function fmtBytes(bytes) {
  if (isNA(bytes) || typeof bytes !== "number") return NA;
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let n = bytes,
    i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

export function fmtDuration(seconds) {
  if (isNA(seconds) || !Number.isFinite(seconds)) return NA;
  const s = Math.round(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}min`);
  parts.push(`${sec}s`);
  return parts.join(" ");
}

export function permissionLabel(state) {
  return (
    { granted: "Concedida", denied: "Negada", prompt: "Perguntar" }[state] ||
    state
  );
}
