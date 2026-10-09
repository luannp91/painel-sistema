//! Orquestrador do motor de detecção.
//!
//! Recebe um lote de [`ProcessFacts`] (do coletor) + um [`SocketSnapshot`]
//! (do `sysinfo::sockets`) e roda o pipeline:
//!
//! 1. `heuristics::analyze`  → report original por processo
//! 2. `baseline.apply`       → atenua findings contextuais conhecidos
//! 3. `lineage.observe`      → mantém árvore para correlação
//! 4. `lineage.find_chain`   → bônus de cadeia por processo
//! 5. `network::check_*`     → findings de porta/conexão somados ao PID
//!
//! **Semântica de scores:**
//! - `original_score` — só heurísticas, sem atenuação, sem cadeia, sem rede.
//! - `baseline_score` — após atenuação do baseline (`original_score` atenuado).
//! - `final_score`    — `max(baseline_score, chain) + network` (cap [`MAX_SCORE`]).
//!
//! **Wall clock no baseline:** o baseline usa `u64` (ms desde epoch)
//! para sobreviver a reboot e ser persistível. O lineage continua com
//! `Instant` — é estado transitório, reinicia a cada boot.
//!
//! **Network não é atenuado:** assim como o bônus de cadeia, findings
//! de porta/conexão usam o peso original. Um atacante não deve poder
//! "amolecer" o baseline de portas abertas para escapar detecção.
//!
//! **`flagged` por socket:** o `SocketSnapshot` devolvido no
//! [`SecuritySnapshot`] tem `flagged: bool` + `alert: Option<String>`
//! em cada porta/conexão. A UI lê direto — sem parsing.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::baseline::{Baseline, BaselineConfig};
use super::heuristics;
use super::lineage::{ChainFinding, Lineage, ProcessChain};
use super::network::{self, SocketSnapshot};
use super::types::{Finding, MAX_SCORE, ProcessFacts, Severity};

/// Intervalo padrão entre prunes automáticos.
pub const DEFAULT_PRUNE_INTERVAL_SECONDS: u64 = 30;

/// Configuração do engine.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub baseline: BaselineConfig,
    pub lineage_window: Duration,
    pub lineage_max_nodes: usize,
    pub prune_interval: Duration,
}

impl EngineConfig {
    pub fn with_defaults() -> Self {
        Self {
            baseline: BaselineConfig::with_defaults(),
            lineage_window: Duration::from_secs(super::lineage::DEFAULT_WINDOW_SECONDS),
            lineage_max_nodes: super::lineage::DEFAULT_MAX_NODES,
            prune_interval: Duration::from_secs(DEFAULT_PRUNE_INTERVAL_SECONDS),
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Resumo serializável de uma [`ProcessChain`].
#[derive(Debug, Clone, Serialize)]
pub struct ChainSummary {
    pub depth: usize,
    pub has_orphan_root: bool,
    pub aggregate_score: u8,
    pub findings: Vec<ChainFinding>,
    pub node_pids: Vec<u32>,
}

impl From<ProcessChain> for ChainSummary {
    fn from(c: ProcessChain) -> Self {
        Self {
            depth: c.depth(),
            has_orphan_root: c.has_orphan_root,
            aggregate_score: c.aggregate_score,
            findings: c.chain_findings,
            node_pids: c.nodes.iter().map(|n| n.pid).collect(),
        }
    }
}

/// Um processo já processado pelo pipeline completo.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzedProcess {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub original_score: u8,
    pub baseline_score: u8,
    pub final_score: u8,
    pub severity: Severity,
    pub findings: Vec<Finding>,
    pub chain: ChainSummary,
    pub attenuated: bool,
    pub integrity_hash: Option<String>,
}

/// Contadores agregados do lote.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SeverityCounts {
    pub clean: usize,
    pub attention: usize,
    pub suspicious: usize,
    pub critical: usize,
}

impl SeverityCounts {
    fn add(&mut self, sev: Severity) {
        match sev {
            Severity::Clean => self.clean += 1,
            Severity::Attention => self.attention += 1,
            Severity::Suspicious => self.suspicious += 1,
            Severity::Critical => self.critical += 1,
        }
    }
}

/// Resultado de um ciclo de análise.
#[derive(Debug, Clone, Serialize)]
pub struct SecuritySnapshot {
    pub processes: Vec<AnalyzedProcess>,
    pub counts: SeverityCounts,
    pub learning: bool,
    /// Segundos restantes do período de aprendizado. `0` quando terminou.
    pub learning_remaining_secs: u64,
    pub elapsed_ms: u128,
    /// Sockets observados no ciclo (portas escutando + conexões).
    /// Cada item traz `flagged` + `alert` preenchidos pelo engine.
    pub sockets: SocketSnapshot,
}

impl SecuritySnapshot {
    pub fn above(&self, threshold: u8) -> impl Iterator<Item = &AnalyzedProcess> {
        self.processes
            .iter()
            .filter(move |p| p.final_score >= threshold)
    }
}

/// Engine.
pub struct Engine {
    baseline: Baseline,
    lineage: Lineage,
    config: EngineConfig,
    last_prune_ms: u64,
}

impl Engine {
    pub fn new(config: EngineConfig, now_ms: u64) -> Self {
        let baseline = Baseline::new(config.baseline.clone(), now_ms);
        let lineage = Lineage::new(config.lineage_window, config.lineage_max_nodes);
        Self {
            baseline,
            lineage,
            config,
            last_prune_ms: now_ms,
        }
    }

    pub fn with_defaults(now_ms: u64) -> Self {
        Self::new(EngineConfig::with_defaults(), now_ms)
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    pub fn lineage(&self) -> &Lineage {
        &self.lineage
    }

    pub fn is_learning(&self, now_ms: u64) -> bool {
        self.baseline.is_learning(now_ms)
    }

    /// Substitui o baseline por um restaurado do disco.
    pub fn replace_baseline(&mut self, baseline: Baseline) {
        self.baseline = baseline;
    }

    /// Roda o pipeline sem sockets. Conveniência para testes e para
    /// chamadas que ainda não coletam rede.
    pub fn analyze_batch(&mut self, facts: &[ProcessFacts<'_>], now_ms: u64) -> SecuritySnapshot {
        self.analyze_batch_with_sockets_at(
            facts,
            &SocketSnapshot::default(),
            now_ms,
            Instant::now(),
        )
    }

    /// Como [`Self::analyze_batch`], com `now_inst` explícito.
    pub fn analyze_batch_at(
        &mut self,
        facts: &[ProcessFacts<'_>],
        now_ms: u64,
        now_inst: Instant,
    ) -> SecuritySnapshot {
        self.analyze_batch_with_sockets_at(facts, &SocketSnapshot::default(), now_ms, now_inst)
    }

    /// Caminho de produção: lote + sockets + wall clock.
    pub fn analyze_batch_with_sockets(
        &mut self,
        facts: &[ProcessFacts<'_>],
        sockets: &SocketSnapshot,
        now_ms: u64,
    ) -> SecuritySnapshot {
        self.analyze_batch_with_sockets_at(facts, sockets, now_ms, Instant::now())
    }

    /// Como [`Self::analyze_batch_with_sockets`], com `now_inst` explícito.
    pub fn analyze_batch_with_sockets_at(
        &mut self,
        facts: &[ProcessFacts<'_>],
        sockets: &SocketSnapshot,
        now_ms: u64,
        now_inst: Instant,
    ) -> SecuritySnapshot {
        let start = Instant::now();
        let learning = self.baseline.is_learning(now_ms);

        // -- Pass 1: heurísticas + baseline + lineage ----------------------
        struct Pass1 {
            pid: u32,
            exe_path: Option<String>,
            original_score: u8,
            baseline_score: u8,
            findings: Vec<Finding>,
            attenuated: bool,
        }

        let mut pass1: Vec<Pass1> = Vec::with_capacity(facts.len());
        for f in facts {
            let original = heuristics::analyze(f);
            let original_score = original.score;
            let findings = original.findings.clone();

            let attenuated_report = self.baseline.apply(f, original.clone(), now_ms);
            let baseline_score = attenuated_report.score;
            let attenuated = baseline_score != original_score;

            self.lineage.observe_at(f, original, now_inst);

            pass1.push(Pass1 {
                pid: f.pid,
                exe_path: f.exe_path.map(str::to_string),
                original_score,
                baseline_score,
                findings,
                attenuated,
            });
        }

        // -- Pass 2: chain bonus -------------------------------------------
        let mut processes: Vec<AnalyzedProcess> = Vec::with_capacity(pass1.len());
        for p in pass1 {
            let chain = self.lineage.find_chain(p.pid);
            let final_score = p.baseline_score.max(chain.aggregate_score);
            let name = chain
                .nodes
                .last()
                .map(|n| n.name.clone())
                .unwrap_or_default();
            processes.push(AnalyzedProcess {
                pid: p.pid,
                name,
                exe_path: p.exe_path,
                original_score: p.original_score,
                baseline_score: p.baseline_score,
                final_score,
                severity: Severity::from_score(final_score),
                findings: p.findings,
                chain: chain.into(),
                attenuated: p.attenuated,
                integrity_hash: None,
            });
        }

        // -- Pass 3: network bonus + flagging por socket -------------------
        let marked_sockets = merge_network_findings(&mut processes, sockets);

        // -- Ordenação + contagem ------------------------------------------
        processes.sort_by(|a, b| {
            b.final_score
                .cmp(&a.final_score)
                .then_with(|| a.pid.cmp(&b.pid))
        });

        let mut counts = SeverityCounts::default();
        for p in &processes {
            counts.add(p.severity);
        }

        // -- Manutenção periódica ------------------------------------------
        let prune_ms = self.config.prune_interval.as_millis() as u64;
        if now_ms.saturating_sub(self.last_prune_ms) >= prune_ms {
            self.lineage.prune(now_inst);
            self.baseline.prune(now_ms);
            self.last_prune_ms = now_ms;
        }

        let learning_remaining_secs = self.baseline.learning_remaining(now_ms).as_secs();

        SecuritySnapshot {
            processes,
            counts,
            learning,
            learning_remaining_secs,
            elapsed_ms: start.elapsed().as_millis(),
            sockets: marked_sockets,
        }
    }
}

// ---------------------------------------------------------------------------
// Merge de findings de rede + flagging por socket
// ---------------------------------------------------------------------------

/// Clona o `SocketSnapshot` de entrada, marca cada socket que disparou
/// finding (`flagged: true` + `alert` preenchido), agrupa por PID e soma
/// o peso ao `final_score` do processo correspondente.
///
/// Findings de rede **não** passam pelo baseline (evita "amolecimento"
/// de portas abertas). Sockets cujo PID não está no batch (processo
/// morreu entre as coletas, ou é kernel/idle) ainda são marcados — o
/// finding é real; só o processo é que não está sendo exibido.
///
/// **Devolve o snapshot marcado** para ser embutido no
/// `SecuritySnapshot`. Preserva a assinatura `&SocketSnapshot` dos
/// callers (`collector.rs` continua igual).
fn merge_network_findings(
    processes: &mut [AnalyzedProcess],
    sockets: &SocketSnapshot,
) -> SocketSnapshot {
    let mut marked = sockets.clone();

    if sockets.is_empty() {
        return marked;
    }

    let mut by_pid: HashMap<u32, Vec<Finding>> = HashMap::new();

    for port in marked.listening.iter_mut() {
        if let Some(f) = network::check_listening(port) {
            port.flagged = true;
            port.alert = Some(f.detail.clone());
            by_pid.entry(port.pid).or_default().push(f);
        }
    }
    for conn in marked.connections.iter_mut() {
        if let Some(f) = network::check_connection(conn) {
            conn.flagged = true;
            conn.alert = Some(f.detail.clone());
            by_pid.entry(conn.pid).or_default().push(f);
        }
    }

    if by_pid.is_empty() {
        return marked;
    }

    for p in processes.iter_mut() {
        let Some(extra) = by_pid.remove(&p.pid) else {
            continue;
        };

        let extra_weight: u8 = extra.iter().map(|f| f.weight).fold(0, u8::saturating_add);

        p.findings.extend(extra);
        p.final_score = p.final_score.saturating_add(extra_weight).min(MAX_SCORE);
        p.severity = Severity::from_score(p.final_score);
    }

    if !by_pid.is_empty() {
        log::debug!(
            "{} PID(s) com findings de rede fora do batch de processos",
            by_pid.len()
        );
    }

    marked
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::network::{ConnectionState, ListeningPort, Protocol};
    use crate::security::types::FindingKind;
    use std::net::{IpAddr, Ipv4Addr};

    const T0: u64 = 1_000_000;

    fn facts<'a>(
        pid: u32,
        parent: Option<u32>,
        name: &'a str,
        cmd: &'a str,
        exe: Option<&'a str>,
    ) -> ProcessFacts<'a> {
        ProcessFacts {
            pid,
            parent_pid: parent,
            name,
            exe_path: exe,
            cmdline: cmd,
            parent_name: None,
            user: None,
            cpu_sustained_high: false,
        }
    }

    fn cfg_short_learning() -> EngineConfig {
        let mut c = EngineConfig::with_defaults();
        c.baseline.learning_period = Duration::from_secs(60);
        c.baseline.min_observations = 3;
        c
    }

    fn listening(pid: u32, port: u16) -> ListeningPort {
        ListeningPort {
            pid,
            protocol: Protocol::Tcp,
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
            flagged: false,
            alert: None,
        }
    }

    fn public_conn(pid: u32, rport: u16) -> crate::security::network::NetworkConnection {
        crate::security::network::NetworkConnection {
            pid,
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            local_port: 55555,
            remote_addr: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            remote_port: Some(rport),
            state: ConnectionState::Established,
            flagged: false,
            alert: None,
        }
    }

    #[test]
    fn empty_batch_yields_empty_snapshot() {
        let mut e = Engine::with_defaults(T0);
        let snap = e.analyze_batch(&[], T0);
        assert!(snap.processes.is_empty());
        assert_eq!(snap.counts.clean, 0);
        assert!(snap.sockets.is_empty());
    }

    #[test]
    fn clean_process_is_clean() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(
            1,
            None,
            "explorer.exe",
            "",
            Some(r"C:\Windows\explorer.exe"),
        );
        let snap = e.analyze_batch(&[f], T0);
        assert_eq!(snap.processes.len(), 1);
        assert_eq!(snap.processes[0].final_score, 0);
        assert_eq!(snap.counts.clean, 1);
        assert_eq!(
            snap.processes[0].exe_path.as_deref(),
            Some(r"C:\Windows\explorer.exe")
        );
        assert!(snap.processes[0].integrity_hash.is_none());
    }

    #[test]
    fn chain_bonus_increases_final_score() {
        let mut e = Engine::with_defaults(T0);
        let inst = Instant::now();
        let office = facts(10, None, "winword.exe", "", None);
        let cmd = facts(11, Some(10), "cmd.exe", "", None);
        let ps = facts(12, Some(11), "powershell.exe", "powershell -enc AAAA", None);

        let snap = e.analyze_batch_at(&[office, cmd, ps], T0, inst);

        let ps_entry = snap.processes.iter().find(|p| p.pid == 12).unwrap();
        assert_eq!(ps_entry.baseline_score, 30);
        assert!(ps_entry.final_score >= 70);
        assert_eq!(ps_entry.severity, Severity::Suspicious);
        assert_eq!(ps_entry.chain.depth, 3);
        assert_eq!(ps_entry.chain.node_pids, vec![10, 11, 12]);
    }

    #[test]
    fn ordering_is_by_final_score_desc() {
        let mut e = Engine::with_defaults(T0);
        let clean = facts(1, None, "explorer.exe", "", None);
        let bad = facts(
            2,
            None,
            "scvhost.exe",
            "powershell -enc AAAA",
            Some("/tmp/scvhost.exe"),
        );

        let snap = e.analyze_batch(&[clean, bad], T0);
        assert_eq!(snap.processes[0].pid, 2);
        assert!(snap.processes[0].final_score > snap.processes[1].final_score);
    }

    #[test]
    fn learning_flag_propagates() {
        let mut e = Engine::with_defaults(T0);
        let snap = e.analyze_batch(&[], T0);
        assert!(snap.learning);
        assert!(snap.learning_remaining_secs > 0);
    }

    #[test]
    fn severity_counts_match_processes() {
        let mut e = Engine::with_defaults(T0);
        let clean = facts(1, None, "explorer.exe", "", None);
        let bad = facts(
            2,
            None,
            "scvhost.exe",
            "powershell -enc AAAA",
            Some("/tmp/scvhost.exe"),
        );
        let snap = e.analyze_batch(&[clean, bad], T0);
        let total = snap.counts.clean
            + snap.counts.attention
            + snap.counts.suspicious
            + snap.counts.critical;
        assert_eq!(total, snap.processes.len());
    }

    #[test]
    fn baseline_attenuates_after_learning() {
        let mut e = Engine::new(cfg_short_learning(), T0);
        let inst = Instant::now();

        let f = facts(1, None, "updater.exe", "", Some("/tmp/updater.exe"));

        for _ in 0..5 {
            e.analyze_batch_at(std::slice::from_ref(&f), T0, inst);
        }

        let after = T0 + 120_000;
        let snap = e.analyze_batch_at(std::slice::from_ref(&f), after, inst);
        let p = &snap.processes[0];

        assert_eq!(p.original_score, 30);
        assert_eq!(p.baseline_score, 9);
        assert!(p.attenuated);
        assert_eq!(p.final_score, 30);
    }

    #[test]
    fn learning_remaining_countdown() {
        let mut e = Engine::with_defaults(T0);
        let snap = e.analyze_batch(&[], T0 + 12 * 3600 * 1000);
        assert!(snap.learning);
        assert!(snap.learning_remaining_secs >= 12 * 3600 - 1);
        assert!(snap.learning_remaining_secs <= 12 * 3600 + 1);
    }

    #[test]
    fn learning_finishes_at_24h() {
        let mut e = Engine::with_defaults(T0);
        let snap = e.analyze_batch(&[], T0 + 24 * 3600 * 1000);
        assert!(!snap.learning);
        assert_eq!(snap.learning_remaining_secs, 0);
    }

    #[test]
    fn above_filters_by_threshold() {
        let mut e = Engine::with_defaults(T0);
        let clean = facts(1, None, "explorer.exe", "", None);
        let bad = facts(
            2,
            None,
            "scvhost.exe",
            "powershell -enc AAAA",
            Some("/tmp/scvhost.exe"),
        );
        let snap = e.analyze_batch(&[clean, bad], T0);

        let high: Vec<_> = snap.above(50).collect();
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].pid, 2);
    }

    // --- Rede (score) -----------------------------------------------------

    #[test]
    fn network_finding_raises_score_and_severity() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "svc.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.listening.push(listening(1, 44444));

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        let p = &snap.processes[0];

        assert_eq!(p.baseline_score, 0);
        assert_eq!(p.final_score, 20);
        assert_eq!(p.severity, Severity::Attention);
        assert_eq!(snap.counts.attention, 1);
        assert_eq!(snap.counts.clean, 0);
        assert!(
            p.findings
                .iter()
                .any(|f| f.kind == FindingKind::UnusualListeningPort)
        );
    }

    #[test]
    fn network_finding_accumulates_with_heuristics() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "updater.exe", "", Some("/tmp/updater.exe"));

        let mut sockets = SocketSnapshot::default();
        sockets.listening.push(listening(1, 44444));

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        let p = &snap.processes[0];

        assert_eq!(p.baseline_score, 30);
        assert_eq!(p.final_score, 50);
        assert_eq!(p.severity, Severity::Suspicious);
    }

    #[test]
    fn network_score_is_capped_at_max() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(
            1,
            None,
            "scvhost.exe",
            "powershell -enc AAAA",
            Some("/tmp/scvhost.exe"),
        );

        let mut sockets = SocketSnapshot::default();
        for p in 0..10 {
            sockets.listening.push(listening(1, 40_000 + p));
        }

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        assert_eq!(snap.processes[0].final_score, MAX_SCORE);
        assert_eq!(snap.processes[0].severity, Severity::Critical);
    }

    #[test]
    fn socket_for_unknown_pid_is_ignored_but_kept_in_snapshot() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "explorer.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.listening.push(listening(9999, 44444));

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        assert_eq!(snap.processes.len(), 1);
        assert_eq!(snap.processes[0].final_score, 0);
        assert_eq!(snap.sockets.listening.len(), 1);
        assert_eq!(snap.sockets.listening[0].pid, 9999);
    }

    #[test]
    fn network_finding_not_attenuated_by_baseline() {
        let mut e = Engine::new(cfg_short_learning(), T0);
        let inst = Instant::now();

        let f = facts(1, None, "svc.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.listening.push(listening(1, 44444));

        for _ in 0..5 {
            e.analyze_batch_with_sockets_at(std::slice::from_ref(&f), &sockets, T0, inst);
        }

        let after = T0 + 120_000;
        let snap = e.analyze_batch_with_sockets_at(std::slice::from_ref(&f), &sockets, after, inst);
        let p = &snap.processes[0];

        assert_eq!(p.baseline_score, 0);
        assert_eq!(p.final_score, 20);
        assert_eq!(p.severity, Severity::Attention);
    }

    #[test]
    fn external_connection_finding() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "svc.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.connections.push(public_conn(1, 4444));

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        let p = &snap.processes[0];

        assert_eq!(p.final_score, 15);
        assert_eq!(p.severity, Severity::Clean);
        assert!(
            p.findings
                .iter()
                .any(|f| f.kind == FindingKind::ExternalConnection)
        );
    }

    // --- Flagging por socket (Fase 5.1) -----------------------------------

    #[test]
    fn socket_gets_flagged_when_finding_fires() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "svc.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.listening.push(listening(1, 44444));

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        let port = &snap.sockets.listening[0];

        assert!(port.flagged);
        assert!(port.alert.as_deref().unwrap().contains("44444"));
    }

    #[test]
    fn socket_not_flagged_when_no_finding() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "svc.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.listening.push(listening(1, 443)); // well-known, sem finding

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        let port = &snap.sockets.listening[0];

        assert!(!port.flagged);
        assert!(port.alert.is_none());
    }

    /// Regressão da precisão: se um PID tem 3 portas e só uma é incomum,
    /// só ela deve ficar flaggada — as outras não.
    #[test]
    fn only_flagged_socket_marked_not_siblings() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "svc.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.listening.push(listening(1, 443)); // well-known → sem flag
        sockets.listening.push(listening(1, 44444)); // alta → flag
        sockets.listening.push(listening(1, 8080)); // baixa → sem flag

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);

        let flagged: Vec<_> = snap
            .sockets
            .listening
            .iter()
            .filter(|p| p.flagged)
            .collect();
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].port, 44444);
    }

    #[test]
    fn connection_gets_flagged_when_finding_fires() {
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "svc.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.connections.push(public_conn(1, 4444));

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        let conn = &snap.sockets.connections[0];

        assert!(conn.flagged);
        assert!(conn.alert.as_deref().unwrap().contains("1.1.1.1:4444"));
    }

    #[test]
    fn socket_for_unknown_pid_still_flagged() {
        // Finding é real; só o processo não está mais no batch. A porta
        // continua marcada, pra UI mostrar ⚠️ mesmo sem processo dono.
        let mut e = Engine::with_defaults(T0);
        let f = facts(1, None, "explorer.exe", "", None);

        let mut sockets = SocketSnapshot::default();
        sockets.listening.push(listening(9999, 44444));

        let snap = e.analyze_batch_with_sockets(&[f], &sockets, T0);
        assert_eq!(snap.processes[0].final_score, 0);
        assert!(snap.sockets.listening[0].flagged);
        assert!(snap.sockets.listening[0].alert.is_some());
    }
}
