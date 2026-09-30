import { $ } from "../utils/dom.js";

let toastTimer = null;

export function showToast(message, duration = 2200) {
    const el = $("#toast");
    el.textContent = message;
    el.classList.add("show");

    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), duration);
}
