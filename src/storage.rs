use crate::sysinfo::patterns::{Pattern, Sample};
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

pub struct Storage {
    conn: Mutex<Connection>,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("falha ao abrir SQLite em {}", path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA busy_timeout = 5000;",
        )?;

        let s = Self {
            conn: Mutex::new(conn),
        };
        s.init_schema()?;
        log::info!("Banco de dados aberto: {}", path.display());
        Ok(s)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS samples (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms    INTEGER NOT NULL,
                cpu_percent     REAL NOT NULL,
                mem_percent     REAL NOT NULL,
                disk_percent    REAL NOT NULL,
                disk_used       INTEGER NOT NULL,
                net_rx          INTEGER NOT NULL,
                net_tx          INTEGER NOT NULL,
                proc_count      INTEGER NOT NULL,
                swap_percent    REAL NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(timestamp_ms);

             CREATE TABLE IF NOT EXISTS patterns (
                id                TEXT PRIMARY KEY,
                kind              TEXT NOT NULL,
                level             TEXT NOT NULL,
                title             TEXT NOT NULL,
                detail            TEXT NOT NULL,
                value             REAL NOT NULL,
                threshold         REAL NOT NULL,
                first_detected_ms INTEGER NOT NULL,
                last_detected_ms  INTEGER NOT NULL,
                occurrences       INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_patterns_last ON patterns(last_detected_ms);",
        )?;
        Ok(())
    }

    pub fn insert_sample(&self, s: &Sample) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO samples (timestamp_ms, cpu_percent, mem_percent, disk_percent,
                                  disk_used, net_rx, net_tx, proc_count, swap_percent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                s.timestamp_ms as i64,
                s.cpu_percent as f64,
                s.mem_percent as f64,
                s.disk_percent as f64,
                s.disk_used as i64,
                s.net_rx as i64,
                s.net_tx as i64,
                s.proc_count as i64,
                s.swap_percent as f64,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_pattern(&self, p: &Pattern) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO patterns (id, kind, level, title, detail, value, threshold,
                                    first_detected_ms, last_detected_ms, occurrences)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                last_detected_ms = excluded.last_detected_ms,
                occurrences      = excluded.occurrences,
                value            = excluded.value,
                detail           = excluded.detail,
                level            = excluded.level",
            params![
                p.id,
                p.kind,
                p.level,
                p.title,
                p.detail,
                p.value,
                p.threshold,
                p.first_detected_ms as i64,
                p.last_detected_ms as i64,
                p.occurrences as i64,
            ],
        )?;
        Ok(())
    }

    pub fn prune_older_than(&self, cutoff_ms: u64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM samples WHERE timestamp_ms < ?1",
            params![cutoff_ms as i64],
        )?;
        Ok(deleted)
    }

    pub fn stats(&self) -> Result<(usize, usize)> {
        let conn = self.conn.lock().unwrap();
        let samples: i64 = conn
            .query_row("SELECT COUNT(*) FROM samples", [], |r| r.get(0))
            .unwrap_or(0);
        let patterns: i64 = conn
            .query_row("SELECT COUNT(*) FROM patterns", [], |r| r.get(0))
            .unwrap_or(0);
        Ok((samples as usize, patterns as usize))
    }
}
