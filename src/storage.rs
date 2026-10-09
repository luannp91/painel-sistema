use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

use crate::security::baseline::{BaselineEntry, BaselineSnapshot};
use crate::security::engine::SecuritySnapshot;
use crate::security::lineage::ChainFindingKind;
use crate::security::network::SocketSnapshot;
use crate::security::types::{FindingKind, Severity};
use crate::sysinfo::patterns::{Pattern, Sample};

pub struct Storage {
    conn: Mutex<Connection>,
}

/// Resultado de um prune, por tabela.
#[derive(Debug, Clone, Copy, Default)]
pub struct PruneStats {
    pub samples: usize,
    pub network_listening: usize,
    pub network_connections: usize,
    pub security_findings: usize,
    pub patterns: usize,
}

impl PruneStats {
    pub fn total(&self) -> usize {
        self.samples
            + self.network_listening
            + self.network_connections
            + self.security_findings
            + self.patterns
    }
}

/// Linha de `security_findings` exposta pela API.
#[derive(Debug, Clone, Serialize)]
pub struct FindingRow {
    pub id: i64,
    pub kind: String,
    pub detail: String,
    pub exe_path: String,
    pub name: String,
    pub weight: u8,
    pub max_score_seen: u8,
    pub max_severity: String,
    pub technique_id: Option<String>,
    pub technique_name: Option<String>,
    pub tactic: Option<String>,
    pub integrity_hash: Option<String>,
    pub seen_outside_learning: bool,
    pub last_pid: u32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub occurrences: u32,
}

/// Linha de `patterns` exposta pela API de histórico.
#[derive(Debug, Clone, Serialize)]
pub struct PatternRow {
    pub id: String,
    pub kind: String,
    pub level: String,
    pub title: String,
    pub detail: String,
    pub value: f64,
    pub threshold: f64,
    pub first_detected_ms: u64,
    pub last_detected_ms: u64,
    pub occurrences: u32,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("falha ao abrir SQLite em {}", path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )?;

        let s = Self {
            conn: Mutex::new(conn),
        };
        s.init_schema()?;
        log::info!("Banco de dados aberto: {}", path.display());
        Ok(s)
    }

    /// Construtor para testes (SQLite em memória, sem tocar disco).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.init_schema()?;
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
             CREATE INDEX IF NOT EXISTS idx_patterns_kind ON patterns(kind);

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
             );

             CREATE TABLE IF NOT EXISTS network_listening (
                pid           INTEGER NOT NULL,
                protocol      TEXT    NOT NULL,
                bind_addr     TEXT    NOT NULL,
                port          INTEGER NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms  INTEGER NOT NULL,
                PRIMARY KEY (pid, protocol, bind_addr, port)
             );
             CREATE INDEX IF NOT EXISTS idx_net_listen_last
                ON network_listening(last_seen_ms);

             CREATE TABLE IF NOT EXISTS network_connections (
                pid           INTEGER NOT NULL,
                protocol      TEXT    NOT NULL,
                local_addr    TEXT    NOT NULL,
                local_port    INTEGER NOT NULL,
                remote_addr   TEXT    NOT NULL,
                remote_port   INTEGER NOT NULL,
                state         TEXT    NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms  INTEGER NOT NULL,
                PRIMARY KEY (pid, protocol, local_addr, local_port, remote_addr, remote_port)
             );
             CREATE INDEX IF NOT EXISTS idx_net_conn_last
                ON network_connections(last_seen_ms);

             CREATE TABLE IF NOT EXISTS security_findings (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                kind                  TEXT    NOT NULL,
                detail                TEXT    NOT NULL,
                exe_path              TEXT    NOT NULL,
                name                  TEXT    NOT NULL,
                weight                INTEGER NOT NULL,
                max_score_seen        INTEGER NOT NULL,
                max_severity_rank     INTEGER NOT NULL,
                technique_id          TEXT,
                technique_name        TEXT,
                tactic                TEXT,
                integrity_hash        TEXT,
                seen_outside_learning INTEGER NOT NULL DEFAULT 0,
                last_pid              INTEGER NOT NULL,
                first_seen_ms         INTEGER NOT NULL,
                last_seen_ms          INTEGER NOT NULL,
                occurrences           INTEGER NOT NULL DEFAULT 1,
                UNIQUE(kind, detail, exe_path)
             );
             CREATE INDEX IF NOT EXISTS idx_sec_findings_last
                ON security_findings(last_seen_ms);
             CREATE INDEX IF NOT EXISTS idx_sec_findings_kind
                ON security_findings(kind);
             CREATE INDEX IF NOT EXISTS idx_sec_findings_sev
                ON security_findings(max_severity_rank);

             CREATE TABLE IF NOT EXISTS security_response_audit (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms INTEGER NOT NULL,
                action       TEXT    NOT NULL,
                target_pid   INTEGER,
                target_path  TEXT,
                target_hash  TEXT,
                detail       TEXT,
                success      INTEGER NOT NULL,
                actor        TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_response_audit_ts
                ON security_response_audit(timestamp_ms);",
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

    /// UPSERT de todos os sockets observados no ciclo.
    pub fn upsert_sockets(&self, sockets: &SocketSnapshot, now_ms: u64) -> Result<()> {
        if sockets.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = now_ms as i64;

        if !sockets.listening.is_empty() {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO network_listening
                    (pid, protocol, bind_addr, port, first_seen_ms, last_seen_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(pid, protocol, bind_addr, port) DO UPDATE SET
                    last_seen_ms = excluded.last_seen_ms",
            )?;
            for p in &sockets.listening {
                stmt.execute(params![
                    p.pid as i64,
                    protocol_str(p.protocol),
                    p.bind_addr.to_string(),
                    p.port as i64,
                    now,
                ])?;
            }
        }

        if !sockets.connections.is_empty() {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO network_connections
                    (pid, protocol, local_addr, local_port,
                     remote_addr, remote_port, state, first_seen_ms, last_seen_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                 ON CONFLICT(pid, protocol, local_addr, local_port,
                             remote_addr, remote_port) DO UPDATE SET
                    state        = excluded.state,
                    last_seen_ms = excluded.last_seen_ms",
            )?;
            for c in &sockets.connections {
                let (Some(remote_addr), Some(remote_port)) = (c.remote_addr, c.remote_port) else {
                    continue;
                };
                stmt.execute(params![
                    c.pid as i64,
                    protocol_str(c.protocol),
                    c.local_addr.to_string(),
                    c.local_port as i64,
                    remote_addr.to_string(),
                    remote_port as i64,
                    state_str(c.state),
                    now,
                ])?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// UPSERT de todos os findings (heurísticas, rede e cadeia) do ciclo.
    pub fn upsert_findings(&self, snapshot: &SecuritySnapshot, now_ms: u64) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = now_ms as i64;
        let outside: i64 = if snapshot.learning { 0 } else { 1 };

        let mut touched = 0usize;

        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO security_findings
                    (kind, detail, exe_path, name, weight, max_score_seen,
                     max_severity_rank, technique_id, technique_name, tactic,
                     integrity_hash, seen_outside_learning, last_pid,
                     first_seen_ms, last_seen_ms, occurrences)
                 VALUES
                    (?1, ?2, ?3, ?4, ?5, ?6,
                     ?7, ?8, ?9, ?10,
                     ?11, ?12, ?13,
                     ?14, ?14, 1)
                 ON CONFLICT(kind, detail, exe_path) DO UPDATE SET
                    occurrences           = occurrences + 1,
                    last_seen_ms          = excluded.last_seen_ms,
                    max_score_seen        = MAX(max_score_seen, excluded.max_score_seen),
                    max_severity_rank     = MAX(max_severity_rank, excluded.max_severity_rank),
                    name                  = excluded.name,
                    last_pid              = excluded.last_pid,
                    integrity_hash        = COALESCE(excluded.integrity_hash, integrity_hash),
                    seen_outside_learning = MAX(seen_outside_learning, excluded.seen_outside_learning)",
            )?;

            for p in &snapshot.processes {
                let has_findings = !p.findings.is_empty() || !p.chain.findings.is_empty();
                if !has_findings {
                    continue;
                }

                let exe_path = p.exe_path.as_deref().unwrap_or("");
                let severity_rank = severity_rank(p.severity) as i64;
                let final_score = p.final_score as i64;
                let hash = p.integrity_hash.as_deref();

                for f in &p.findings {
                    let kind = finding_kind_str(f.kind);
                    let (tid, tname, tact) = technique_parts(&f.technique);
                    stmt.execute(params![
                        kind,
                        f.detail,
                        exe_path,
                        p.name,
                        f.weight as i64,
                        final_score,
                        severity_rank,
                        tid,
                        tname,
                        tact,
                        hash,
                        outside,
                        p.pid as i64,
                        now,
                    ])?;
                    touched += 1;
                }

                for cf in &p.chain.findings {
                    let kind = format!("chain_{}", chain_kind_str(cf.kind));
                    let (tid, tname, tact) = technique_parts(&cf.technique);
                    stmt.execute(params![
                        kind,
                        cf.detail,
                        exe_path,
                        p.name,
                        cf.weight as i64,
                        final_score,
                        severity_rank,
                        tid,
                        tname,
                        tact,
                        hash,
                        outside,
                        p.pid as i64,
                        now,
                    ])?;
                    touched += 1;
                }
            }
        }

        tx.commit()?;
        Ok(touched)
    }

    /// Consulta paginada de findings históricos.
    pub fn query_findings(
        &self,
        limit: usize,
        kind: Option<&str>,
        min_severity: Option<Severity>,
        search: Option<&str>,
    ) -> Result<Vec<FindingRow>> {
        let conn = self.conn.lock().unwrap();
        let limit = limit.clamp(1, 1000) as i64;
        let min_rank: Option<i64> = min_severity.map(|s| severity_rank(s) as i64);
        let pattern: Option<String> = search.map(|s| format!("%{s}%"));

        let mut stmt = conn.prepare(
            "SELECT id, kind, detail, exe_path, name, weight, max_score_seen,
                    max_severity_rank, technique_id, technique_name, tactic,
                    integrity_hash, seen_outside_learning, last_pid,
                    first_seen_ms, last_seen_ms, occurrences
             FROM security_findings
             WHERE (?1 IS NULL OR kind = ?1)
               AND (?2 IS NULL OR max_severity_rank >= ?2)
               AND (?3 IS NULL OR name LIKE ?3 OR exe_path LIKE ?3 OR detail LIKE ?3)
             ORDER BY last_seen_ms DESC
             LIMIT ?4",
        )?;

        let rows = stmt.query_map(params![kind, min_rank, pattern, limit], |row| {
            let rank: i64 = row.get(7)?;
            Ok(FindingRow {
                id: row.get(0)?,
                kind: row.get(1)?,
                detail: row.get(2)?,
                exe_path: row.get(3)?,
                name: row.get(4)?,
                weight: row.get::<_, i64>(5)? as u8,
                max_score_seen: row.get::<_, i64>(6)? as u8,
                max_severity: severity_from_rank(rank as u8).to_string(),
                technique_id: row.get(8)?,
                technique_name: row.get(9)?,
                tactic: row.get(10)?,
                integrity_hash: row.get(11)?,
                seen_outside_learning: row.get::<_, i64>(12)? != 0,
                last_pid: row.get::<_, i64>(13)? as u32,
                first_seen_ms: row.get::<_, i64>(14)? as u64,
                last_seen_ms: row.get::<_, i64>(15)? as u64,
                occurrences: row.get::<_, i64>(16)? as u32,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Consulta paginada de padrões históricos (tabela `patterns`).
    ///
    /// - `limit`: cap duro em 1000.
    /// - `kind`: filtro exato (`cpu_spike`, `disk_pressure`, ...).
    /// - `level`: filtro exato (`Error`, `Warning`, `Information`).
    /// - `search`: LIKE em `title`, `detail` e `kind`.
    ///
    /// Ordenado por `last_detected_ms DESC`.
    pub fn query_patterns(
        &self,
        limit: usize,
        kind: Option<&str>,
        level: Option<&str>,
        search: Option<&str>,
    ) -> Result<Vec<PatternRow>> {
        let conn = self.conn.lock().unwrap();
        let limit = limit.clamp(1, 1000) as i64;
        let pattern: Option<String> = search.map(|s| format!("%{s}%"));

        let mut stmt = conn.prepare(
            "SELECT id, kind, level, title, detail, value, threshold,
                    first_detected_ms, last_detected_ms, occurrences
             FROM patterns
             WHERE (?1 IS NULL OR kind = ?1)
               AND (?2 IS NULL OR level = ?2)
               AND (?3 IS NULL OR title LIKE ?3 OR detail LIKE ?3 OR kind LIKE ?3)
             ORDER BY last_detected_ms DESC
             LIMIT ?4",
        )?;

        let rows = stmt.query_map(params![kind, level, pattern, limit], |row| {
            Ok(PatternRow {
                id: row.get(0)?,
                kind: row.get(1)?,
                level: row.get(2)?,
                title: row.get(3)?,
                detail: row.get(4)?,
                value: row.get(5)?,
                threshold: row.get(6)?,
                first_detected_ms: row.get::<_, i64>(7)? as u64,
                last_detected_ms: row.get::<_, i64>(8)? as u64,
                occurrences: row.get::<_, i64>(9)? as u32,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Apaga linhas antigas. Duas janelas:
    /// - `op_cutoff_ms`: samples + network_*
    /// - `forensic_cutoff_ms`: security_findings + patterns
    pub fn prune_older_than(
        &self,
        op_cutoff_ms: u64,
        forensic_cutoff_ms: u64,
    ) -> Result<PruneStats> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let op = op_cutoff_ms as i64;
        let forensic = forensic_cutoff_ms as i64;

        let stats = PruneStats {
            samples: tx.execute("DELETE FROM samples WHERE timestamp_ms < ?1", params![op])?,
            network_listening: tx.execute(
                "DELETE FROM network_listening WHERE last_seen_ms < ?1",
                params![op],
            )?,
            network_connections: tx.execute(
                "DELETE FROM network_connections WHERE last_seen_ms < ?1",
                params![op],
            )?,
            security_findings: tx.execute(
                "DELETE FROM security_findings WHERE last_seen_ms < ?1",
                params![forensic],
            )?,
            patterns: tx.execute(
                "DELETE FROM patterns WHERE last_detected_ms < ?1",
                params![forensic],
            )?,
        };
        tx.commit()?;

        if stats.patterns > 0 {
            log::debug!("Prune: {} patterns removidos", stats.patterns);
        }
        Ok(stats)
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

    pub fn network_stats(&self) -> Result<(usize, usize)> {
        let conn = self.conn.lock().unwrap();
        let listening: i64 = conn
            .query_row("SELECT COUNT(*) FROM network_listening", [], |r| r.get(0))
            .unwrap_or(0);
        let connections: i64 = conn
            .query_row("SELECT COUNT(*) FROM network_connections", [], |r| r.get(0))
            .unwrap_or(0);
        Ok((listening as usize, connections as usize))
    }

    pub fn findings_stats(&self) -> Result<(usize, Option<u64>)> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_findings", [], |r| r.get(0))
            .unwrap_or(0);
        let oldest: Option<i64> = conn
            .query_row(
                "SELECT MIN(first_seen_ms) FROM security_findings",
                [],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        Ok((count as usize, oldest.map(|v| v as u64)))
    }

    /// Contagem de padrões + primeiro `last_detected_ms` mais antigo.
    pub fn patterns_stats(&self) -> Result<(usize, Option<u64>)> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM patterns", [], |r| r.get(0))
            .unwrap_or(0);
        let oldest: Option<i64> = conn
            .query_row("SELECT MIN(last_detected_ms) FROM patterns", [], |r| {
                r.get(0)
            })
            .ok()
            .flatten();
        Ok((count as usize, oldest.map(|v| v as u64)))
    }

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

// ---------------------------------------------------------------------------
// Serialização de enums → TEXT
// ---------------------------------------------------------------------------

fn protocol_str(p: crate::security::network::Protocol) -> &'static str {
    use crate::security::network::Protocol;
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn state_str(s: crate::security::network::ConnectionState) -> &'static str {
    use crate::security::network::ConnectionState;
    match s {
        ConnectionState::Listen => "listen",
        ConnectionState::Established => "established",
        ConnectionState::TimeWait => "time_wait",
        ConnectionState::CloseWait => "close_wait",
        ConnectionState::SynSent => "syn_sent",
        ConnectionState::SynRecv => "syn_recv",
        ConnectionState::Other => "other",
    }
}

fn finding_kind_str(k: FindingKind) -> String {
    serde_json::to_string(&k)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| format!("{k:?}").to_lowercase())
}

fn chain_kind_str(k: ChainFindingKind) -> String {
    serde_json::to_string(&k)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| format!("{k:?}").to_lowercase())
}

fn technique_parts(
    t: &Option<crate::security::mitre::Technique>,
) -> (Option<String>, Option<String>, Option<String>) {
    match t {
        Some(t) => (
            Some(t.id.to_string()),
            Some(t.name.to_string()),
            Some(
                serde_json::to_string(&t.tactic)
                    .map(|s| s.trim_matches('"').to_string())
                    .unwrap_or_else(|_| format!("{:?}", t.tactic).to_lowercase()),
            ),
        ),
        None => (None, None, None),
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Clean => 0,
        Severity::Attention => 1,
        Severity::Suspicious => 2,
        Severity::Critical => 3,
    }
}

fn severity_from_rank(r: u8) -> &'static str {
    match r {
        0 => "clean",
        1 => "attention",
        2 => "suspicious",
        _ => "critical",
    }
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::engine::{AnalyzedProcess, ChainSummary, SeverityCounts};
    use crate::security::types::{Finding, FindingKind};

    fn snap_with_findings(findings: Vec<Finding>, learning: bool, score: u8) -> SecuritySnapshot {
        let severity = Severity::from_score(score);
        SecuritySnapshot {
            processes: vec![AnalyzedProcess {
                pid: 1234,
                name: "scvhost.exe".to_string(),
                exe_path: Some("/tmp/scvhost.exe".to_string()),
                original_score: score,
                baseline_score: score,
                final_score: score,
                severity,
                findings,
                chain: ChainSummary {
                    depth: 1,
                    has_orphan_root: false,
                    aggregate_score: 0,
                    findings: vec![],
                    node_pids: vec![1234],
                },
                attenuated: false,
                integrity_hash: Some("deadbeef".to_string()),
            }],
            counts: SeverityCounts::default(),
            learning,
            learning_remaining_secs: 0,
            elapsed_ms: 0,
            sockets: SocketSnapshot::default(),
        }
    }

    fn pattern(id: &str, kind: &str, level: &str, first_ms: u64, last_ms: u64) -> Pattern {
        Pattern {
            id: id.to_string(),
            kind: kind.to_string(),
            level: level.to_string(),
            title: format!("{kind} title"),
            detail: format!("{kind} detail"),
            value: 42.0,
            threshold: 40.0,
            first_detected_ms: first_ms,
            last_detected_ms: last_ms,
            occurrences: 3,
        }
    }

    #[test]
    fn upsert_findings_inserts_new_row() {
        let s = Storage::open_in_memory().unwrap();
        let f = Finding::new(FindingKind::MasqueradeLocation, "svchost fora de System32");
        let snap = snap_with_findings(vec![f], false, 45);

        let n = s.upsert_findings(&snap, 1_000).unwrap();
        assert_eq!(n, 1);

        let rows = s.query_findings(10, None, None, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "masquerade_location");
        assert_eq!(rows[0].occurrences, 1);
    }

    #[test]
    fn upsert_findings_aggregates_same_key() {
        let s = Storage::open_in_memory().unwrap();
        let f = Finding::new(FindingKind::MasqueradeLocation, "svchost fora de System32");

        let snap1 = snap_with_findings(vec![f.clone()], false, 45);
        let snap2 = snap_with_findings(vec![f], false, 60);

        s.upsert_findings(&snap1, 1_000).unwrap();
        s.upsert_findings(&snap2, 2_000).unwrap();

        let rows = s.query_findings(10, None, None, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].occurrences, 2);
        assert_eq!(rows[0].max_score_seen, 60);
    }

    #[test]
    fn upsert_pattern_and_query() {
        let s = Storage::open_in_memory().unwrap();
        let p = pattern("cpu_spike_1", "cpu_spike", "Error", 1_000, 2_000);
        s.upsert_pattern(&p).unwrap();

        let rows = s.query_patterns(10, None, None, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "cpu_spike");
        assert_eq!(rows[0].level, "Error");
        assert_eq!(rows[0].occurrences, 3);
        assert_eq!(rows[0].first_detected_ms, 1_000);
        assert_eq!(rows[0].last_detected_ms, 2_000);
    }

    #[test]
    fn query_patterns_filters_by_kind() {
        let s = Storage::open_in_memory().unwrap();
        s.upsert_pattern(&pattern("p1", "cpu_spike", "Error", 1_000, 1_000))
            .unwrap();
        s.upsert_pattern(&pattern("p2", "disk_pressure", "Error", 1_000, 1_000))
            .unwrap();
        s.upsert_pattern(&pattern("p3", "memory_pressure", "Warning", 1_000, 1_000))
            .unwrap();

        let cpu = s.query_patterns(10, Some("cpu_spike"), None, None).unwrap();
        assert_eq!(cpu.len(), 1);
        assert_eq!(cpu[0].kind, "cpu_spike");
    }

    #[test]
    fn query_patterns_filters_by_level() {
        let s = Storage::open_in_memory().unwrap();
        s.upsert_pattern(&pattern("p1", "cpu_spike", "Error", 1_000, 1_000))
            .unwrap();
        s.upsert_pattern(&pattern("p2", "memory_pressure", "Warning", 1_000, 1_000))
            .unwrap();

        let errors = s.query_patterns(10, None, Some("Error"), None).unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].level, "Error");
    }

    #[test]
    fn query_patterns_search_matches_title() {
        let s = Storage::open_in_memory().unwrap();
        s.upsert_pattern(&pattern("p1", "cpu_spike", "Error", 1_000, 1_000))
            .unwrap();

        let hit = s.query_patterns(10, None, None, Some("cpu_spike")).unwrap();
        assert_eq!(hit.len(), 1);

        let miss = s.query_patterns(10, None, None, Some("nothing")).unwrap();
        assert_eq!(miss.len(), 0);
    }

    #[test]
    fn query_patterns_sorted_by_last_desc() {
        let s = Storage::open_in_memory().unwrap();
        s.upsert_pattern(&pattern("p1", "a", "Error", 1_000, 1_000))
            .unwrap();
        s.upsert_pattern(&pattern("p2", "b", "Error", 2_000, 2_000))
            .unwrap();
        s.upsert_pattern(&pattern("p3", "c", "Error", 3_000, 3_000))
            .unwrap();

        let rows = s.query_patterns(10, None, None, None).unwrap();
        assert_eq!(rows[0].last_detected_ms, 3_000);
        assert_eq!(rows[1].last_detected_ms, 2_000);
        assert_eq!(rows[2].last_detected_ms, 1_000);
    }

    #[test]
    fn prune_older_than_removes_stale_patterns() {
        let s = Storage::open_in_memory().unwrap();
        s.upsert_pattern(&pattern("p1", "cpu_spike", "Error", 1_000, 1_000))
            .unwrap();

        let stats = s.prune_older_than(0, 2_000).unwrap();
        assert_eq!(stats.patterns, 1);

        let rows = s.query_patterns(10, None, None, None).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn patterns_stats_reports_count_and_oldest() {
        let s = Storage::open_in_memory().unwrap();
        s.upsert_pattern(&pattern("p1", "cpu_spike", "Error", 1_000, 7_000))
            .unwrap();
        s.upsert_pattern(&pattern("p2", "disk_pressure", "Error", 2_000, 9_000))
            .unwrap();

        let (count, oldest) = s.patterns_stats().unwrap();
        assert_eq!(count, 2);
        assert_eq!(oldest, Some(7_000));
    }
}
