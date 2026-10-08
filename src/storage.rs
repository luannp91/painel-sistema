use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

use crate::security::baseline::{BaselineEntry, BaselineSnapshot};
use crate::sysinfo::patterns::{Pattern, Sample};

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
             CREATE INDEX IF NOT EXISTS idx_patterns_last ON patterns(last_detected_ms);

             CREATE TABLE IF NOT EXISTS baseline_meta (
                key   TEXT PRIMARY KEY,
                value INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS baseline_entries (
                key                TEXT PRIMARY KEY,
                first_seen_ms      INTEGER NOT NULL,
                last_seen_ms       INTEGER NOT NULL,
                observations       INTEGER NOT NULL,
                max_score_seen     INTEGER NOT NULL,
                total_findings     INTEGER NOT NULL,
                high_severity_seen INTEGER NOT NULL
             );",
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

    // -----------------------------------------------------------------------
    // Baseline
    // -----------------------------------------------------------------------

    /// Salva o baseline inteiro numa transação. Substitui o conteúdo
    /// anterior.
    pub fn save_baseline(&self, snap: &BaselineSnapshot) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO baseline_meta (key, value) VALUES ('started_at_ms', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![snap.started_at_ms as i64],
        )?;

        tx.execute("DELETE FROM baseline_entries", [])?;

        {
            let mut stmt = tx.prepare(
                "INSERT INTO baseline_entries
                    (key, first_seen_ms, last_seen_ms, observations,
                     max_score_seen, total_findings, high_severity_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for (key, entry) in &snap.entries {
                stmt.execute(params![
                    key,
                    entry.first_seen_ms as i64,
                    entry.last_seen_ms as i64,
                    entry.observations as i64,
                    entry.max_score_seen as i64,
                    entry.total_findings as i64,
                    entry.high_severity_seen as i64,
                ])?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Carrega o baseline persistido. `None` se nunca foi salvo.
    pub fn load_baseline(&self) -> Result<Option<BaselineSnapshot>> {
        let conn = self.conn.lock().unwrap();

        let started_at_ms: Option<i64> = conn
            .query_row(
                "SELECT value FROM baseline_meta WHERE key = 'started_at_ms'",
                [],
                |r| r.get(0),
            )
            .ok();

        let Some(started_at_ms) = started_at_ms else {
            return Ok(None);
        };

        let mut stmt = conn.prepare(
            "SELECT key, first_seen_ms, last_seen_ms, observations,
                    max_score_seen, total_findings, high_severity_seen
             FROM baseline_entries",
        )?;

        let rows = stmt.query_map([], |row| {
            let key: String = row.get(0)?;
            let entry = BaselineEntry {
                first_seen_ms: row.get::<_, i64>(1)? as u64,
                last_seen_ms: row.get::<_, i64>(2)? as u64,
                observations: row.get::<_, i64>(3)? as u32,
                max_score_seen: row.get::<_, i64>(4)? as u8,
                total_findings: row.get::<_, i64>(5)? as u32,
                high_severity_seen: row.get::<_, i64>(6)? != 0,
            };
            Ok((key, entry))
        })?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r?);
        }

        Ok(Some(BaselineSnapshot {
            started_at_ms: started_at_ms as u64,
            entries,
        }))
    }
}
