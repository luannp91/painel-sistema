import { $ } from "../utils/dom.js";

export function startClock() {
  const el = $("#clock");
  const tick = () => {
    el.textContent = new Date().toLocaleTimeString("pt-BR");
  };
  tick();
  setInterval(tick, 1000);
}
