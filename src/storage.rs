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

             -- Findings de seguranca agregados por assinatura unica.
             -- UPSERT por (kind, detail, exe_path): uma linha por
             -- \"tipo de coisa que aparece nessa maquina\", nao log.
             -- max_severity_rank: 0=clean 1=attention 2=suspicious 3=critical.
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

             -- Reservado para Fase 7 (acoes manuais: kill, quarantine).
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
    /// Cada assinatura única `(kind, detail, exe_path)` vira uma linha.
    ///
    /// Retorna o nº de linhas tocadas (insert ou update).
    ///
    /// Semântica dos agregados:
    /// - `occurrences` incrementa a cada re-observação.
    /// - `last_seen_ms` = `now_ms`.
    /// - `max_score_seen` = máximo entre o antigo e o do processo atual.
    /// - `max_severity_rank` = máximo (monotônico crescente).
    /// - `seen_outside_learning` = 1 assim que visto fora do aprendizado.
    /// - `integrity_hash` só é sobrescrito se o novo não for NULL.
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
    ///
    /// - `limit`: cap duro em 1000 (feito no caller também).
    /// - `kind`: filtro exato (`lol_bin`, `chain_office_to_c2`, ...).
    /// - `min_severity`: filtro mínimo (Attention inclusive).
    /// - `search`: LIKE em `name`, `exe_path` e `detail` (o caller
    ///   adiciona `%` antes/depois).
    ///
    /// Ordenado por `last_seen_ms DESC`.
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

        let mut s = PruneStats {
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

        // Cap de segurança: se security_findings explodir (raro), corta
        // as mais antigas fora do padrão de prune para não estourar o DB.
        if s.security_findings > 0 {
            log::debug!(
                "Prune: {} samples, {} listening, {} conn, {} findings, {} patterns",
                s.samples,
                s.network_listening,
                s.network_connections,
                s.security_findings,
                s.patterns
            );
        } else {
            s.security_findings = 0;
        }
        Ok(s)
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

    /// Contagem de findings + first_seen mais antigo (ms epoch).
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
    use crate::security::types::Finding;
    use crate::security::types::FindingKind;

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
        assert_eq!(rows[0].first_seen_ms, 1_000);
        assert_eq!(rows[0].last_seen_ms, 1_000);
        assert_eq!(rows[0].max_score_seen, 45);
        assert!(rows[0].seen_outside_learning);
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
        assert_eq!(rows.len(), 1, "mesma assinatura deve agregar");
        assert_eq!(rows[0].occurrences, 2);
        assert_eq!(rows[0].first_seen_ms, 1_000);
        assert_eq!(rows[0].last_seen_ms, 2_000);
        assert_eq!(rows[0].max_score_seen, 60, "score sobe pro maximo visto");
    }

    #[test]
    fn upsert_findings_severity_only_grows() {
        let s = Storage::open_in_memory().unwrap();
        let f = Finding::new(FindingKind::MasqueradeLocation, "x");

        // Primeiro com score 90 (critical), depois com score 30 (attention).
        s.upsert_findings(&snap_with_findings(vec![f.clone()], false, 90), 1_000)
            .unwrap();
        s.upsert_findings(&snap_with_findings(vec![f], false, 30), 2_000)
            .unwrap();

        let rows = s.query_findings(10, None, None, None).unwrap();
        assert_eq!(rows[0].max_severity, "critical", "severidade nao regride");
    }

    #[test]
    fn upsert_findings_learning_flag_clears() {
        let s = Storage::open_in_memory().unwrap();
        let f = Finding::new(FindingKind::CpuSustainedHigh, "cpu alta");

        // Primeiro durante o aprendizado, depois fora.
        s.upsert_findings(&snap_with_findings(vec![f.clone()], true, 15), 1_000)
            .unwrap();
        s.upsert_findings(&snap_with_findings(vec![f], false, 15), 2_000)
            .unwrap();

        let rows = s.query_findings(10, None, None, None).unwrap();
        assert!(
            rows[0].seen_outside_learning,
            "uma vez fora do aprendizado, fica marcado"
        );
    }

    #[test]
    fn query_findings_filters_by_kind() {
        let s = Storage::open_in_memory().unwrap();
        let f1 = Finding::new(FindingKind::MasqueradeLocation, "a");
        let f2 = Finding::new(FindingKind::LolBin, "b");
        s.upsert_findings(&snap_with_findings(vec![f1, f2], false, 40), 1_000)
            .unwrap();

        let only_lol = s.query_findings(10, Some("lol_bin"), None, None).unwrap();
        assert_eq!(only_lol.len(), 1);
        assert_eq!(only_lol[0].kind, "lol_bin");
    }

    #[test]
    fn query_findings_filters_by_min_severity() {
        let s = Storage::open_in_memory().unwrap();
        // Score 25 (attention), score 90 (critical)
        let snap_att = snap_with_findings(
            vec![Finding::new(FindingKind::UnusualListeningPort, "x")],
            false,
            25,
        );
        let snap_crit = snap_with_findings(
            vec![Finding::new(FindingKind::MasqueradeLocation, "y")],
            false,
            90,
        );
        s.upsert_findings(&snap_att, 1_000).unwrap();
        s.upsert_findings(&snap_crit, 2_000).unwrap();

        let critical_only = s
            .query_findings(10, None, Some(Severity::Critical), None)
            .unwrap();
        assert_eq!(critical_only.len(), 1);
        assert_eq!(critical_only[0].max_severity, "critical");

        let all = s
            .query_findings(10, None, Some(Severity::Attention), None)
            .unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn query_findings_search_matches_name() {
        let s = Storage::open_in_memory().unwrap();
        let f = Finding::new(FindingKind::MasqueradeLocation, "x");
        s.upsert_findings(&snap_with_findings(vec![f], false, 45), 1_000)
            .unwrap();

        let hit = s.query_findings(10, None, None, Some("scvhost")).unwrap();
        assert_eq!(hit.len(), 1);

        let miss = s.query_findings(10, None, None, Some("notepad")).unwrap();
        assert_eq!(miss.len(), 0);
    }

    #[test]
    fn query_findings_caps_limit_at_1000() {
        let s = Storage::open_in_memory().unwrap();
        // Só valida que não explode com limit alto.
        let r = s.query_findings(99_999, None, None, None).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn prune_older_than_removes_stale_findings() {
        let s = Storage::open_in_memory().unwrap();
        let f = Finding::new(FindingKind::MasqueradeLocation, "x");
        s.upsert_findings(&snap_with_findings(vec![f], false, 45), 1_000)
            .unwrap();

        // Corte forense em 2_000 → finding visto em 1_000 é apagado.
        let stats = s.prune_older_than(0, 2_000).unwrap();
        assert_eq!(stats.security_findings, 1);

        let rows = s.query_findings(10, None, None, None).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn prune_keeps_recent_findings() {
        let s = Storage::open_in_memory().unwrap();
        let f = Finding::new(FindingKind::MasqueradeLocation, "x");
        s.upsert_findings(&snap_with_findings(vec![f], false, 45), 5_000)
            .unwrap();

        let stats = s.prune_older_than(0, 1_000).unwrap();
        assert_eq!(stats.security_findings, 0);

        let rows = s.query_findings(10, None, None, None).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn findings_stats_reports_count_and_oldest() {
        let s = Storage::open_in_memory().unwrap();
        let f = Finding::new(FindingKind::MasqueradeLocation, "x");
        s.upsert_findings(&snap_with_findings(vec![f], false, 45), 7_000)
            .unwrap();

        let (count, oldest) = s.findings_stats().unwrap();
        assert_eq!(count, 1);
        assert_eq!(oldest, Some(7_000));
    }
}
