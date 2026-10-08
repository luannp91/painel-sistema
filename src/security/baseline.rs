//! Baseline por máquina — aprende o que é normal e atenua findings
//! contextuais em processos conhecidos como limpos.
//!
//! **Persistência:** `started_at_ms` e cada `BaselineEntry` podem ser
//! serializados (via [`BaselineSnapshot`]) e restaurados no próximo
//! boot. Sem isso, o período de aprendizado reinicia a cada execução.
//!
//! **Wall clock:** todos os tempos internos são `u64` (ms desde epoch).
//! `Instant` não é serializável nem sobrevive a reboot.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::heuristics::strip_ext;
use super::types::{Finding, FindingKind, MAX_SCORE, ProcessFacts, Severity, SuspicionReport};

/// Período de aprendizado padrão (24h).
pub const DEFAULT_LEARNING_SECONDS: u64 = 24 * 3600;

/// Observações mínimas para uma chave virar "conhecida limpa".
pub const DEFAULT_MIN_OBSERVATIONS: u32 = 3;

/// Percentual do peso original preservado após atenuação (30%).
pub const DEFAULT_ATTENUATION_PERCENT: u8 = 30;

/// Idade máxima de uma entrada sem ser observada (30 dias).
pub const DEFAULT_MAX_ENTRY_AGE_SECONDS: u64 = 30 * 24 * 3600;

/// Findings que nunca são atenuados, independente do baseline.
pub const DEFAULT_EXEMPT_KINDS: &[FindingKind] = &[
    FindingKind::Typosquatting,
    FindingKind::SuspiciousParent,
    FindingKind::SuspiciousCmdline,
];

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------

/// Parâmetros do baseline. Vira `[security.baseline]` em Fase 8.
#[derive(Debug, Clone)]
pub struct BaselineConfig {
    pub learning_period: Duration,
    pub min_observations: u32,
    /// 0 = zera o peso; 100 = não atenua. Default 30.
    pub attenuation_percent: u8,
    pub max_entry_age: Duration,
    pub exempt_kinds: Vec<FindingKind>,
}

impl BaselineConfig {
    pub fn with_defaults() -> Self {
        Self {
            learning_period: Duration::from_secs(DEFAULT_LEARNING_SECONDS),
            min_observations: DEFAULT_MIN_OBSERVATIONS,
            attenuation_percent: DEFAULT_ATTENUATION_PERCENT,
            max_entry_age: Duration::from_secs(DEFAULT_MAX_ENTRY_AGE_SECONDS),
            exempt_kinds: DEFAULT_EXEMPT_KINDS.to_vec(),
        }
    }

    pub fn is_exempt(&self, kind: FindingKind) -> bool {
        self.exempt_kinds.contains(&kind)
    }
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------------
// Entrada
// ---------------------------------------------------------------------------

/// Estado aprendido de uma chave `(nome, path)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub observations: u32,
    pub max_score_seen: u8,
    pub total_findings: u32,
    /// Marcado para sempre quando um finding exempt dispara. Uma vez
    /// `true`, a chave nunca mais é elegível à atenuação.
    pub high_severity_seen: bool,
}

impl BaselineEntry {
    fn new(now_ms: u64) -> Self {
        Self {
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            observations: 0,
            max_score_seen: 0,
            total_findings: 0,
            high_severity_seen: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot (persistível)
// ---------------------------------------------------------------------------

/// Estado completo do baseline, pronto para gravar no SQLite e
/// restaurar no próximo boot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    /// Momento (wall clock, ms desde epoch) em que o aprendizado começou.
    /// Zero indica "primeira vez" — o caller decide usar `now`.
    pub started_at_ms: u64,
    pub entries: Vec<(String, BaselineEntry)>,
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

/// Baseline em memória. Não thread-safe — quem usa serializa.
pub struct Baseline {
    entries: HashMap<String, BaselineEntry>,
    /// Instante (wall clock) em que o período de aprendizado começou.
    started_at_ms: u64,
    config: BaselineConfig,
}

impl Baseline {
    /// Cria com `started_at_ms` = agora.
    pub fn new(config: BaselineConfig, now_ms: u64) -> Self {
        Self::started_at(config, now_ms)
    }

    /// Cria com `started_at_ms` explícito (testável).
    pub fn started_at(config: BaselineConfig, now_ms: u64) -> Self {
        Self {
            entries: HashMap::new(),
            started_at_ms: now_ms,
            config,
        }
    }

    pub fn with_defaults(now_ms: u64) -> Self {
        Self::new(BaselineConfig::with_defaults(), now_ms)
    }

    /// Reconstrói a partir de um snapshot persistido.
    ///
    /// Se `snapshot.started_at_ms == 0`, cai no comportamento de
    /// "primeira vez" — usa `now_ms` como início do aprendizado.
    pub fn restore(config: BaselineConfig, snapshot: BaselineSnapshot, now_ms: u64) -> Self {
        let started_at_ms = if snapshot.started_at_ms == 0 {
            now_ms
        } else {
            snapshot.started_at_ms
        };
        Self {
            entries: snapshot.entries.into_iter().collect(),
            started_at_ms,
            config,
        }
    }

    /// Gera snapshot do estado atual para persistir.
    pub fn snapshot(&self) -> BaselineSnapshot {
        let mut entries: Vec<(String, BaselineEntry)> = self
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0)); // determinismo
        BaselineSnapshot {
            started_at_ms: self.started_at_ms,
            entries,
        }
    }

    pub fn config(&self) -> &BaselineConfig {
        &self.config
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    /// `true` enquanto o agente está na fase de aprendizado.
    pub fn is_learning(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.started_at_ms) < self.config.learning_period.as_millis() as u64
    }

    /// Quanto falta pro período de aprendizado terminar. Zero se já
    /// terminou.
    pub fn learning_remaining(&self, now_ms: u64) -> Duration {
        let elapsed = now_ms.saturating_sub(self.started_at_ms);
        let total = self.config.learning_period.as_millis() as u64;
        Duration::from_millis(total.saturating_sub(elapsed))
    }

    /// Quantas chaves são hoje "conhecidas limpas".
    pub fn known_clean_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| self.is_entry_clean(e))
            .count()
    }

    /// Consulta se a chave de `facts` é conhecida limpa (não considera
    /// fase de aprendizado — isso é decisão do caller).
    pub fn is_known_clean(&self, facts: &ProcessFacts<'_>) -> bool {
        match self.entries.get(&key_of(facts)) {
            Some(e) => self.is_entry_clean(e),
            None => false,
        }
    }

    /// Aplica o pipeline completo: consulta o baseline, registra a
    /// observação e devolve o report (possivelmente atenuado).
    pub fn apply(
        &mut self,
        facts: &ProcessFacts<'_>,
        report: SuspicionReport,
        now_ms: u64,
    ) -> SuspicionReport {
        let learning = self.is_learning(now_ms);
        let was_clean = self.is_known_clean(facts);

        self.observe_at(facts, &report, now_ms);

        if learning || !was_clean {
            return report;
        }

        attenuate(report, &self.config)
    }

    /// Só registra a observação (sem devolver report).
    pub fn observe_at(&mut self, facts: &ProcessFacts<'_>, report: &SuspicionReport, now_ms: u64) {
        let key = key_of(facts);
        let has_exempt = report
            .findings
            .iter()
            .any(|f| self.config.is_exempt(f.kind));

        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| BaselineEntry::new(now_ms));
        entry.observations = entry.observations.saturating_add(1);
        entry.last_seen_ms = now_ms;
        entry.max_score_seen = entry.max_score_seen.max(report.score);
        entry.total_findings = entry
            .total_findings
            .saturating_add(report.findings.len() as u32);
        if has_exempt {
            entry.high_severity_seen = true;
        }
    }

    /// Remove entradas sem observação há mais de `max_entry_age`.
    pub fn prune(&mut self, now_ms: u64) {
        let max_age_ms = self.config.max_entry_age.as_millis() as u64;
        let cutoff = now_ms.saturating_sub(max_age_ms);
        self.entries.retain(|_, e| e.last_seen_ms >= cutoff);
    }

    // -- internos ----------------------------------------------------------

    fn is_entry_clean(&self, entry: &BaselineEntry) -> bool {
        entry.observations >= self.config.min_observations && !entry.high_severity_seen
    }
}

// ---------------------------------------------------------------------------
// Atenuação
// ---------------------------------------------------------------------------

fn attenuate(report: SuspicionReport, config: &BaselineConfig) -> SuspicionReport {
    let factor = config.attenuation_percent as u32;

    let findings: Vec<Finding> = report
        .findings
        .into_iter()
        .map(|f| {
            if config.is_exempt(f.kind) {
                return f;
            }
            let new_weight = ((f.weight as u32) * factor / 100) as u8;
            Finding {
                weight: new_weight,
                ..f
            }
        })
        .collect();

    let raw: u32 = findings.iter().map(|f| f.weight as u32).sum();
    let score = raw.min(MAX_SCORE as u32) as u8;

    SuspicionReport {
        score,
        severity: Severity::from_score(score),
        findings,
    }
}

// ---------------------------------------------------------------------------
// Chave
// ---------------------------------------------------------------------------

fn key_of(facts: &ProcessFacts<'_>) -> String {
    let stem = strip_ext(facts.name).to_ascii_lowercase();
    match facts.exe_path {
        Some(path) => {
            let p = path.replace('\\', "/").to_ascii_lowercase();
            format!("{stem}|{p}")
        }
        None => stem,
    }
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::heuristics::analyze;

    const T0: u64 = 1_000_000;

    fn facts<'a>(
        name: &'a str,
        exe: Option<&'a str>,
        cmd: &'a str,
        parent: Option<&'a str>,
    ) -> ProcessFacts<'a> {
        ProcessFacts {
            pid: 1234,
            parent_pid: None,
            name,
            exe_path: exe,
            cmdline: cmd,
            parent_name: parent,
            user: None,
            cpu_sustained_high: false,
        }
    }

    fn cfg() -> BaselineConfig {
        BaselineConfig {
            learning_period: Duration::from_secs(60),
            min_observations: 3,
            attenuation_percent: 30,
            max_entry_age: Duration::from_secs(3600),
            exempt_kinds: DEFAULT_EXEMPT_KINDS.to_vec(),
        }
    }

    #[test]
    fn learning_phase_does_not_attenuate() {
        let mut b = Baseline::started_at(cfg(), T0);
        let f = facts("app.exe", Some("/tmp/app.exe"), "", None);
        assert_eq!(analyze(&f).score, 30);

        for _ in 0..5 {
            let out = b.apply(&f, analyze(&f), T0);
            assert_eq!(out.score, 30);
        }
    }

    #[test]
    fn known_clean_attenuates_after_learning() {
        let mut b = Baseline::started_at(cfg(), T0);
        let f = facts("updater.exe", Some("/tmp/updater.exe"), "", None);

        for _ in 0..5 {
            b.apply(&f, analyze(&f), T0);
        }

        let after = T0 + 120_000;
        let out = b.apply(&f, analyze(&f), after);
        assert_eq!(out.score, 9);
        assert_eq!(out.severity, Severity::Clean);
    }

    #[test]
    fn below_min_observations_no_attenuation() {
        let mut b = Baseline::started_at(cfg(), T0);
        let f = facts("app.exe", Some("/tmp/app.exe"), "", None);
        b.apply(&f, analyze(&f), T0);

        let after = T0 + 120_000;
        let out = b.apply(&f, analyze(&f), after);
        assert_eq!(out.score, 30);
    }

    #[test]
    fn exempt_finding_blocks_attenuation_forever() {
        let mut b = Baseline::started_at(cfg(), T0);
        let benign = facts("app.exe", Some("/opt/app.exe"), "", None);
        for _ in 0..5 {
            b.apply(&benign, analyze(&benign), T0);
        }
        assert!(b.is_known_clean(&benign));

        let suspect = facts(
            "app.exe",
            Some("/opt/app.exe"),
            "powershell -enc AAAA",
            None,
        );
        b.apply(&suspect, analyze(&suspect), T0 + 1000);
        assert!(!b.is_known_clean(&suspect));
        assert!(b.entries.get(&key_of(&benign)).unwrap().high_severity_seen);
    }

    #[test]
    fn learning_boundary() {
        let b = Baseline::started_at(cfg(), T0);
        assert!(b.is_learning(T0));
        assert!(b.is_learning(T0 + 59_999));
        assert!(!b.is_learning(T0 + 60_000));
        assert!(!b.is_learning(T0 + 60_001));
    }

    #[test]
    fn learning_remaining_counts_down() {
        let b = Baseline::started_at(cfg(), T0);
        assert_eq!(b.learning_remaining(T0).as_secs(), 60);
        assert_eq!(b.learning_remaining(T0 + 30_000).as_secs(), 30);
        assert_eq!(b.learning_remaining(T0 + 90_000).as_secs(), 0);
    }

    #[test]
    fn prune_removes_stale() {
        let mut b = Baseline::started_at(cfg(), T0);
        let f = facts("app.exe", Some("/opt/app.exe"), "", None);
        b.apply(&f, analyze(&f), T0);
        assert_eq!(b.len(), 1);

        b.prune(T0 + 7_200_000); // 2h > max_entry_age (1h)
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn snapshot_roundtrip_preserves_state() {
        let mut original = Baseline::started_at(cfg(), T0);
        let f = facts("updater.exe", Some("/tmp/updater.exe"), "", None);
        for _ in 0..5 {
            original.apply(&f, analyze(&f), T0);
        }

        let snap = original.snapshot();
        assert_eq!(snap.started_at_ms, T0);
        assert_eq!(snap.entries.len(), 1);
        assert_eq!(snap.entries[0].0, "updater|/tmp/updater.exe");
        assert_eq!(snap.entries[0].1.observations, 5);

        let restored = Baseline::restore(cfg(), snap, T0 + 999_999);
        assert_eq!(restored.started_at_ms(), T0);
        assert!(restored.is_known_clean(&f));
    }

    #[test]
    fn restore_with_zero_started_at_uses_now() {
        let snap = BaselineSnapshot {
            started_at_ms: 0,
            entries: Vec::new(),
        };
        let b = Baseline::restore(cfg(), snap, T0);
        assert_eq!(b.started_at_ms(), T0);
        assert!(b.is_learning(T0 + 1000));
    }

    #[test]
    fn persist_learning_survives_restart() {
        // Simula: rodou por 40s, salvou, reiniciou 30s depois, ainda
        // em aprendizado? Não — passaram 70s totais.
        let mut original = Baseline::started_at(cfg(), T0);
        let f = facts("x.exe", None, "", None);
        original.apply(&f, analyze(&f), T0 + 40_000);

        let snap = original.snapshot();
        let restored = Baseline::restore(cfg(), snap, T0 + 70_000);
        assert!(!restored.is_learning(T0 + 70_000));
        assert_eq!(restored.started_at_ms(), T0);
    }
}
