//! Chave de bootstrap trocada entre o tray e o browser.
//!
//! O tray abre o browser com `?otk=<chave>`. O frontend troca essa
//! chave pelo token real via `POST /api/auth/exchange`. Assim o token
//! real nunca aparece na URL — só uma chave efêmera, local, que
//! rotaciona a cada poucos minutos.
//!
//! Não usa dependência externa de RNG: deriva 256 bits de entropia de
//! `RandomState` (que é semeado pelo SO) combinado com timestamp e PID.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Tempo de vida de cada chave antes de rotacionar.
const KEY_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct BootstrapKey {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    key: String,
    created_at: Instant,
}

impl BootstrapKey {
    pub fn generate() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                key: random_hex_32(),
                created_at: Instant::now(),
            })),
        }
    }

    /// Devolve a chave atual, rotacionando antes se expirou.
    pub fn current(&self) -> String {
        let mut g = self.inner.lock().unwrap();
        self.maybe_rotate(&mut g);
        g.key.clone()
    }

    /// Verifica se `candidate` bate com a chave atual.
    pub fn matches(&self, candidate: &str) -> bool {
        let mut g = self.inner.lock().unwrap();
        self.maybe_rotate(&mut g);
        g.key == candidate
    }

    fn maybe_rotate(&self, g: &mut Inner) {
        if g.created_at.elapsed() >= KEY_TTL {
            g.key = random_hex_32();
            g.created_at = Instant::now();
        }
    }
}

fn random_hex_32() -> String {
    use std::hash::{BuildHasher, Hasher};

    fn seed_u64(x: u64) -> u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(x);
        h.finish()
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;

    let a = seed_u64(now ^ pid);
    let b = seed_u64(a);
    let c = seed_u64(b);
    let d = seed_u64(c);

    format!("{a:016x}{b:016x}{c:016x}{d:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_key_matches() {
        let bk = BootstrapKey::generate();
        let k = bk.current();
        assert!(bk.matches(&k));
        assert!(!bk.matches("nao-e-a-chave"));
    }

    #[test]
    fn key_is_64_hex_chars() {
        let bk = BootstrapKey::generate();
        let k = bk.current();
        assert_eq!(k.len(), 64);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn distinct_keys_differ() {
        let a = BootstrapKey::generate().current();
        let b = BootstrapKey::generate().current();
        assert_ne!(a, b);
    }
}
