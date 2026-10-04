//! Hash SHA256 de executáveis + cache em memória.
//!
//! Usado para (a) detectar binário que muda de conteúdo entre execuções
//! e (b) servir de chave forte para o baseline no futuro. Nesta fase o
//! cache vive só em memória — persistência SQLite fica pra Fase 4.
//!
//! [`hash_file`] faz I/O; [`IntegrityCache`] decide quando recomputar.
//! A separação permite testar a lógica de cache com um hasher mockado.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};

/// Tamanho do buffer de leitura (64 KiB).
const READ_BUF: usize = 64 * 1024;

/// Idade máxima de uma entrada no cache (default 1h).
pub const DEFAULT_MAX_AGE_SECONDS: u64 = 3600;

/// Cap de entradas no cache (default 4096).
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

/// Hash SHA256 de um arquivo, em hexadecimal minúsculo.
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_BUF];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Hash SHA256 de bytes em memória.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// Configuração do cache.
#[derive(Debug, Clone)]
pub struct IntegrityConfig {
    pub max_age: Duration,
    pub max_entries: usize,
}

impl IntegrityConfig {
    pub fn with_defaults() -> Self {
        Self {
            max_age: Duration::from_secs(DEFAULT_MAX_AGE_SECONDS),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Entrada de cache — hash + metadados para validar sem recalcular.
#[derive(Debug, Clone)]
struct CacheEntry {
    hash: String,
    size: u64,
    mtime: Option<SystemTime>,
    computed_at: Instant,
}

/// Cache em memória de hashes por path. Não thread-safe.
pub struct IntegrityCache {
    entries: HashMap<PathBuf, CacheEntry>,
    config: IntegrityConfig,
}

impl IntegrityCache {
    pub fn new(config: IntegrityConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(IntegrityConfig::with_defaults())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Devolve o hash do arquivo, usando cache quando possível.
    ///
    /// Recomputa se: não há entrada, a entrada está mais velha que
    /// `max_age`, ou `size`/`mtime` mudaram.
    pub fn hash_of(&mut self, path: &Path) -> io::Result<String> {
        self.hash_of_at(path, Instant::now())
    }

    /// Como [`hash_of`], com `now` explícito (testável).
    pub fn hash_of_at(&mut self, path: &Path, now: Instant) -> io::Result<String> {
        let meta = std::fs::metadata(path)?;
        let size = meta.len();
        let mtime = meta.modified().ok();

        if let Some(entry) = self.entries.get(path) {
            let fresh = now.saturating_duration_since(entry.computed_at) < self.config.max_age;
            let same_size = entry.size == size;
            let same_mtime = entry.mtime == mtime;
            if fresh && same_size && same_mtime {
                return Ok(entry.hash.clone());
            }
        }

        let hash = hash_file(path)?;
        self.insert(path.to_path_buf(), hash.clone(), size, mtime, now);
        Ok(hash)
    }

    /// Consulta o cache sem tocar em disco. `None` se ausente ou expirado.
    pub fn cached(&self, path: &Path, now: Instant) -> Option<&str> {
        let entry = self.entries.get(path)?;
        if now.saturating_duration_since(entry.computed_at) >= self.config.max_age {
            return None;
        }
        Some(&entry.hash)
    }

    /// Remove entradas mais velhas que `max_age`.
    pub fn prune(&mut self, now: Instant) {
        let max_age = self.config.max_age;
        self.entries
            .retain(|_, e| now.saturating_duration_since(e.computed_at) < max_age);
    }

    fn insert(
        &mut self,
        path: PathBuf,
        hash: String,
        size: u64,
        mtime: Option<SystemTime>,
        now: Instant,
    ) {
        if self.entries.len() >= self.config.max_entries
            && !self.entries.contains_key(&path)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.computed_at)
                .map(|(k, _)| k.clone())
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(
            path,
            CacheEntry {
                hash,
                size,
                mtime,
                computed_at: now,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("painel_integrity_{name}_{nanos}"));
        p
    }

    fn write_tmp(name: &str, data: &[u8]) -> PathBuf {
        let p = tmp_path(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(data).unwrap();
        f.sync_all().unwrap();
        p
    }

    #[test]
    fn hash_bytes_known_vectors() {
        assert_eq!(hash_bytes(b""), SHA256_EMPTY);
        assert_eq!(hash_bytes(b"abc"), SHA256_ABC);
    }

    #[test]
    fn hash_file_matches_hash_bytes() {
        let p = write_tmp("match", b"abc");
        assert_eq!(hash_file(&p).unwrap(), SHA256_ABC);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hash_file_empty() {
        let p = write_tmp("empty", b"");
        assert_eq!(hash_file(&p).unwrap(), SHA256_EMPTY);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hash_file_missing_errors() {
        let p = tmp_path("does_not_exist");
        assert!(hash_file(&p).is_err());
    }

    #[test]
    fn cache_hit_returns_same_hash() {
        let p = write_tmp("cache_hit", b"abc");
        let mut c = IntegrityCache::with_defaults();
        let h1 = c.hash_of(&p).unwrap();
        let h2 = c.hash_of(&p).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(c.len(), 1);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn cache_invalidated_on_content_change() {
        let p = write_tmp("inval", b"abc");
        let mut c = IntegrityCache::with_defaults();
        assert_eq!(c.hash_of(&p).unwrap(), SHA256_ABC);

        std::thread::sleep(Duration::from_millis(20));
        let mut f = File::create(&p).unwrap();
        f.write_all(b"xyz").unwrap();
        f.sync_all().unwrap();

        let h = c.hash_of(&p).unwrap();
        assert_ne!(h, SHA256_ABC);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn cache_expired_recomputes() {
        let p = write_tmp("exp", b"abc");
        let cfg = IntegrityConfig {
            max_age: Duration::from_secs(1),
            max_entries: 16,
        };
        let mut c = IntegrityCache::new(cfg);

        let t0 = Instant::now();
        assert_eq!(c.hash_of_at(&p, t0).unwrap(), SHA256_ABC);

        let later = t0 + Duration::from_secs(2);
        assert!(c.cached(&p, later).is_none());
        assert_eq!(c.hash_of_at(&p, later).unwrap(), SHA256_ABC);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn prune_drops_stale() {
        let p = write_tmp("prune", b"abc");
        let cfg = IntegrityConfig {
            max_age: Duration::from_secs(60),
            max_entries: 16,
        };
        let mut c = IntegrityCache::new(cfg);
        let t0 = Instant::now();
        c.hash_of_at(&p, t0).unwrap();
        assert_eq!(c.len(), 1);

        c.prune(t0 + Duration::from_secs(120));
        assert_eq!(c.len(), 0);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn max_entries_cap_enforced() {
        let cfg = IntegrityConfig {
            max_age: Duration::from_secs(3600),
            max_entries: 2,
        };
        let mut c = IntegrityCache::new(cfg);
        let t0 = Instant::now();
        let paths: Vec<PathBuf> = (0..3)
            .map(|i| write_tmp(&format!("cap{i}"), format!("data{i}").as_bytes()))
            .collect();
        for (i, p) in paths.iter().enumerate() {
            c.hash_of_at(p, t0 + Duration::from_millis(i as u64 * 10))
                .unwrap();
        }
        assert!(c.len() <= 2);
        assert!(c.entries.contains_key(&paths[2]));
        for p in &paths {
            std::fs::remove_file(p).ok();
        }
    }
}
