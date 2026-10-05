import { $ } from "../utils/dom.js";

const KEY = "painel_theme";

export function initTheme() {
  const btn = $("#btnTheme");
  const saved = localStorage.getItem(KEY);
  const preferred =
    saved ||
    (window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark");

  apply(preferred);

  btn.addEventListener("click", () => {
    const cur = document.documentElement.dataset.theme;
    apply(cur === "dark" ? "light" : "dark");
  });

  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    btn.textContent = theme === "dark" ? "🌙" : "☀️";
    localStorage.setItem(KEY, theme);
  }
}
