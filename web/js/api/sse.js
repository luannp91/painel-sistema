/* =========================================================
   Conexão SSE com o agente Rust — autenticação via cookie
   ========================================================= */

import { tokenReady } from "../utils/token-init.js";

export function createLiveStream({ onData, onOpen, onError }) {
  let source = null;
  let retryTimer = null;

  async function connect() {
    // Aguarda a troca de OTK terminar (se houver). Sem isso, o
    // EventSource abriria sem cookie e o servidor devolveria 401.
    await tokenReady.catch(() => {});

    source = new EventSource("/api/stream");

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
