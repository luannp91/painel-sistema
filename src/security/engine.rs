//! Orquestrador do motor de detecção.
//!
//! Recebe um lote de [`ProcessFacts`] (do coletor) e roda o pipeline:
//!
//! 1. `heuristics::analyze` → report original por processo
//! 2. `baseline.apply` → atenua findings contextuais conhecidos
//! 3. `lineage.observe` → mantém árvore para correlação
//! 4. `lineage.find_chain` → bônus de cadeia por processo
//!
//! Devolve [`SecuritySnapshot`] ordenado por score final — pronto
//! para serializar na API (Fase 5) ou gravar no SQLite (Fase 4).
//!
//! [`AnalyzedProcess`] expõe a cadeia como [`ChainSummary`] (não
//! [`ProcessChain`]) porque `ProcessNode` contém `Instant`, que não é
//! serializável — e o frontend não precisa dos timestamps internos.

use std::time::{Duration, Instant};

use serde::Serialize;

use super::baseline::{Baseline, BaselineConfig};
use super::heuristics;
use super::lineage::{ChainFinding, Lineage, ProcessChain};
use super::types::{Finding, ProcessFacts, Severity};

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

/// Resumo serializável de uma [`ProcessChain`] — o que a UI e o
/// storage precisam, sem os `Instant` internos.
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
    pub original_score: u8,
    pub baseline_score: u8,
    pub final_score: u8,
    pub severity: Severity,
    pub findings: Vec<Finding>,
    pub chain: ChainSummary,
    pub attenuated: bool,
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
    /// Segundos restantes do período de aprendizado do baseline.
    /// `0` quando já terminou (ou quando `learning == false`).
    pub learning_remaining_secs: u64,
    pub elapsed_ms: u128,
}

impl SecuritySnapshot {
    /// Processos com `final_score >= threshold`, em ordem decrescente.
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
    last_prune: Instant,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        let now = Instant::now();
        let baseline = Baseline::new(config.baseline.clone());
        let lineage = Lineage::new(config.lineage_window, config.lineage_max_nodes);
        Self {
            baseline,
            lineage,
            config,
            last_prune: now,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(EngineConfig::with_defaults())
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

    pub fn is_learning(&self) -> bool {
        self.baseline.is_learning(Instant::now())
    }

    /// Roda o pipeline completo sobre um lote de processos.
    ///
    /// Duas passadas obrigatórias: a primeira registra todos os nós
    /// (para que `find_chain` veja a árvore inteira), a segunda monta
    /// as cadeias.
    pub fn analyze_batch(&mut self, facts: &[ProcessFacts<'_>]) -> SecuritySnapshot {
        self.analyze_batch_at(facts, Instant::now())
    }

    pub fn analyze_batch_at(
        &mut self,
        facts: &[ProcessFacts<'_>],
        now: Instant,
    ) -> SecuritySnapshot {
        let start = Instant::now();
        let learning = self.baseline.is_learning(now);

        struct Pass1 {
            pid: u32,
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

            let attenuated_report = self.baseline.apply_at(f, original.clone(), now);
            let baseline_score = attenuated_report.score;
            let attenuated = baseline_score != original_score;

            self.lineage.observe_at(f, original, now);

            pass1.push(Pass1 {
                pid: f.pid,
                original_score,
                baseline_score,
                findings,
                attenuated,
            });
        }

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
                original_score: p.original_score,
                baseline_score: p.baseline_score,
                final_score,
                severity: Severity::from_score(final_score),
                findings: p.findings,
                chain: chain.into(),
                attenuated: p.attenuated,
            });
        }

        processes.sort_by(|a, b| {
            b.final_score
                .cmp(&a.final_score)
                .then_with(|| a.pid.cmp(&b.pid))
        });

        let mut counts = SeverityCounts::default();
        for p in &processes {
            counts.add(p.severity);
        }

        if now.saturating_duration_since(self.last_prune) >= self.config.prune_interval {
            self.lineage.prune(now);
            self.baseline.prune(now);
            self.last_prune = now;
        }

        let learning_remaining_secs = self.baseline.learning_remaining(now).as_secs();

        SecuritySnapshot {
            processes,
            counts,
            learning,
            learning_remaining_secs,
            elapsed_ms: start.elapsed().as_millis(),
        }
    }
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn empty_batch_yields_empty_snapshot() {
        let mut e = Engine::with_defaults();
        let snap = e.analyze_batch(&[]);
        assert!(snap.processes.is_empty());
        assert_eq!(snap.counts.clean, 0);
    }

    #[test]
    fn clean_process_is_clean() {
        let mut e = Engine::with_defaults();
        let f = facts(
            1,
            None,
            "explorer.exe",
            "",
            Some(r"C:\Windows\explorer.exe"),
        );
        let snap = e.analyze_batch(&[f]);
        assert_eq!(snap.processes.len(), 1);
        assert_eq!(snap.processes[0].final_score, 0);
        assert_eq!(snap.counts.clean, 1);
    }

    #[test]
    fn chain_bonus_increases_final_score() {
        let mut e = Engine::with_defaults();
        let t0 = Instant::now();
        let office = facts(10, None, "winword.exe", "", None);
        let cmd = facts(11, Some(10), "cmd.exe", "", None);
        let ps = facts(12, Some(11), "powershell.exe", "powershell -enc AAAA", None);

        let snap = e.analyze_batch_at(&[office, cmd, ps], t0);

        let ps_entry = snap.processes.iter().find(|p| p.pid == 12).unwrap();
        assert_eq!(ps_entry.baseline_score, 30);
        assert!(ps_entry.final_score >= 70);
        assert_eq!(ps_entry.severity, Severity::Suspicious);
        assert_eq!(ps_entry.chain.depth, 3);
        assert_eq!(ps_entry.chain.node_pids, vec![10, 11, 12]);
    }

    #[test]
    fn ordering_is_by_final_score_desc() {
        let mut e = Engine::with_defaults();
        let clean = facts(1, None, "explorer.exe", "", None);
        let bad = facts(
            2,
            None,
            "scvhost.exe",
            "powershell -enc AAAA",
            Some("/tmp/scvhost.exe"),
        );

        let snap = e.analyze_batch(&[clean, bad]);
        assert_eq!(snap.processes[0].pid, 2);
        assert!(snap.processes[0].final_score > snap.processes[1].final_score);
    }

    #[test]
    fn learning_flag_propagates() {
        let mut e = Engine::with_defaults();
        let snap = e.analyze_batch(&[]);
        assert!(snap.learning);
    }

    #[test]
    fn severity_counts_match_processes() {
        let mut e = Engine::with_defaults();
        let clean = facts(1, None, "explorer.exe", "", None);
        let bad = facts(
            2,
            None,
            "scvhost.exe",
            "powershell -enc AAAA",
            Some("/tmp/scvhost.exe"),
        );
        let snap = e.analyze_batch(&[clean, bad]);
        let total = snap.counts.clean
            + snap.counts.attention
            + snap.counts.suspicious
            + snap.counts.critical;
        assert_eq!(total, snap.processes.len());
    }

    #[test]
    fn baseline_attenuates_after_learning() {
        let mut e = Engine::new(cfg_short_learning());
        let t0 = Instant::now();

        let f = facts(1, None, "updater.exe", "", Some("/tmp/updater.exe"));

        // 5 ciclos de aprendizado (learning_period = 60s).
        for _ in 0..5 {
            e.analyze_batch_at(std::slice::from_ref(&f), t0);
        }

        // 120s depois — fora do aprendizado.
        let after = t0 + Duration::from_secs(120);
        let snap = e.analyze_batch_at(std::slice::from_ref(&f), after);
        let p = &snap.processes[0];

        // Score bruto: apenas TempDir (+30).
        assert_eq!(p.original_score, 30, "original_score deveria ser 30");

        // Score após atenuação do baseline: 30 * 30% = 9.
        assert_eq!(
            p.baseline_score, 9,
            "baseline_score deveria ser 9 (30 atenuado por 30%)"
        );
        assert!(p.attenuated, "flag attenuated deveria ser true");

        // final_score = max(baseline_score, chain.aggregate_score).
        // A cadeia usa o report ORIGINAL (não atenuado) do último nó —
        // decisão intencional: baseline reflete "conhecido limpo" por
        // processo, enquanto correlação de cadeia sempre avalia
        // heurísticas brutas. Por isso final_score = 30, não 9.
        assert_eq!(
            p.final_score, 30,
            "final_score é dominado pela cadeia (score bruto)"
        );
    }

    #[test]
    fn above_filters_by_threshold() {
        let mut e = Engine::with_defaults();
        let clean = facts(1, None, "explorer.exe", "", None);
        let bad = facts(
            2,
            None,
            "scvhost.exe",
            "powershell -enc AAAA",
            Some("/tmp/scvhost.exe"),
        );
        let snap = e.analyze_batch(&[clean, bad]);

        let high: Vec<_> = snap.above(50).collect();
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].pid, 2);
    }
}
