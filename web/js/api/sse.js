/* =========================================================
   Conexão SSE com o agente Rust — token via query string
   ========================================================= */

import { getToken } from "./rest.js";

export function createLiveStream({ onData, onOpen, onError }) {
  let source = null;
  let retryTimer = null;

  function connect() {
    const token = getToken();
    const url = token
      ? `/api/stream?token=${encodeURIComponent(token)}`
      : "/api/stream";

    source = new EventSource(url);

    source.onopen = () => onOpen?.();

    source.onmessage = (ev) => {
      try {
        onData?.(JSON.parse(ev.data));
      } catch (err) {
        console.warn("[SSE] JSON inválido:", err);
      }
    };

    source.onerror = () => {
      onError?.();
      source?.close();
      retryTimer = setTimeout(connect, 3000);
    };
  }

  connect();

  return {
    close() {
      clearTimeout(retryTimer);
      source?.close();
    },
  };
}
