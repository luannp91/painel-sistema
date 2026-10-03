import { $ } from "../utils/dom.js";

let timer = null;

export function showToast(msg, duration = 2200) {
  const el = $("#toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(timer);
  timer = setTimeout(() => el.classList.remove("show"), duration);
}
