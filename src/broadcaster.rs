use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use std::sync::{Arc, Mutex};

const CLIENT_CAPACITY: usize = 8;

/// Broadcast de frames SSE para N clientes conectados.
#[derive(Clone)]
pub struct Broadcaster {
    clients: Arc<Mutex<Vec<Sender<Vec<u8>>>>>,
}

impl Broadcaster {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Registra um novo cliente e retorna o receptor.
    pub fn subscribe(&self) -> Receiver<Vec<u8>> {
        let (tx, rx) = bounded(CLIENT_CAPACITY);
        self.clients.lock().unwrap().push(tx);
        rx
    }

    /// Envia um frame para todos. Descarta para clientes lentos.
    pub fn publish(&self, frame: Vec<u8>) {
        let mut clients = self.clients.lock().unwrap();
        clients.retain(|tx| {
            !matches!(
                tx.try_send(frame.clone()),
                Err(TrySendError::Disconnected(_))
            )
        });
    }

    pub fn client_count(&self) -> usize {
        self.clients.lock().unwrap().len()
    }
}

impl Default for Broadcaster {
    fn default() -> Self {
        Self::new()
    }
}
