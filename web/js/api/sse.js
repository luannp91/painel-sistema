export function createLiveStream({ onData, onOpen, onError }) {
  let source = null;
  let retryTimer = null;

  function connect() {
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
