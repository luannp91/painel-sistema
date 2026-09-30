import { $ } from "../utils/dom.js";
import { STORAGE_KEYS } from "../config.js";

export function initTheme() {
    const btn = $("#btnTheme");
    const saved = localStorage.getItem(STORAGE_KEYS.theme);

    const preferred = saved || (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");

    apply(preferred);

    btn.addEventListener("click", () => {
        const current = document.documentElement.dataset.theme;
        apply(current === "dark" ? "light" : "dark");
    });

    function apply(theme) {
        document.documentElement.dataset.theme = theme;
        btn.textContent = theme === "dark" ? "🌙" : "☀️";
        localStorage.setItem(STORAGE_KEYS.theme, theme);
    }
}
