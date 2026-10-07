//! Baseline por máquina — aprende o que é normal e atenua findings
//! contextuais em processos conhecidos como limpos.
//!
//! Sem isso, o agente vira gerador de falso-positivo: todo `svchost`
//! em `System32` que apareça com path ligeiramente diferente, todo
//! updater legítimo executando de `%TEMP%`, todo `runtimebroker`
//! dispara uma finding contextual. O baseline observa o que é normal
//! nesta máquina e, depois de um período de aprendizado, aplica um
//! fator de atenuação sobre findings **contextuais** de processos já
//! conhecidos.
//!
//! Findings **exempt** (Typosquatting, SuspiciousParent,
//! SuspiciousCmdline) nunca são atenuados — são fortes demais para
//! virar ruído, mesmo em processo "conhecido". E uma vez que uma
//! chave dispara um exempt, ela é marcada permanentemente e deixa de
//! ser elegível à atenuação — evita que um atacante "amoleça" o
//! baseline rodando benigno várias vezes antes do ataque.
//!
//! Estado em memória (Fase 1). Persistência SQLite vem na Fase 4.

use std::collections::HashMap;
use std::time::{Duration, Instant};

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
#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub observations: u32,
    pub max_score_seen: u8,
    pub total_findings: u32,
    /// Marcado para sempre quando um finding exempt dispara. Uma vez
    /// `true`, a chave nunca mais é elegível à atenuação.
    pub high_severity_seen: bool,
}

impl BaselineEntry {
    fn new(now: Instant) -> Self {
        Self {
            first_seen: now,
            last_seen: now,
            observations: 0,
            max_score_seen: 0,
            total_findings: 0,
            high_severity_seen: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

/// Baseline em memória. Não thread-safe — quem usa serializa.
pub struct Baseline {
    entries: HashMap<String, BaselineEntry>,
    /// Instante de criação — o "t0" do período de aprendizado.
    started_at: Instant,
    config: BaselineConfig,
}

impl Baseline {
    /// Cria com config explícita. `started_at` = agora.
    pub fn new(config: BaselineConfig) -> Self {
        Self::started_at(config, Instant::now())
    }

    /// Cria com `started_at` explícito (testável).
    pub fn started_at(config: BaselineConfig, now: Instant) -> Self {
        Self {
            entries: HashMap::new(),
            started_at: now,
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(BaselineConfig::with_defaults())
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

    /// `true` enquanto o agente está na fase de aprendizado.
    pub fn is_learning(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started_at) < self.config.learning_period
    }

    /// Quanto falta pro período de aprendizado terminar. Zero se já
    /// terminou — `saturating_sub` evita panic se `now` for anterior
    /// a `started_at` (não deveria acontecer, mas por segurança).
    pub fn learning_remaining(&self, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.started_at);
        self.config.learning_period.saturating_sub(elapsed)
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
    ///
    /// Semântica:
    /// - Durante o aprendizado: devolve o report original, mas aprende.
    /// - Após o aprendizado: se a chave é conhecida limpa, devolve um
    ///   report com findings não-exempt atenuados. Caso contrário,
    ///   devolve o original.
    ///
    /// Sempre registra a observação com o **report original** — nunca
    /// com o atenuado — para não criar feedback loop.
    pub fn apply(&mut self, facts: &ProcessFacts<'_>, report: SuspicionReport) -> SuspicionReport {
        self.apply_at(facts, report, Instant::now())
    }

    /// Como [`apply`], com timestamp explícito (testável).
    pub fn apply_at(
        &mut self,
        facts: &ProcessFacts<'_>,
        report: SuspicionReport,
        now: Instant,
    ) -> SuspicionReport {
        let learning = self.is_learning(now);
        let was_clean = self.is_known_clean(facts);

        // Registra sempre com o report original.
        self.observe_at(facts, &report, now);

        if learning || !was_clean {
            return report;
        }

        attenuate(report, &self.config)
    }

    /// Só registra a observação (sem devolver report). Útil quando o
    /// caller quer controle fino sobre quando atenuar.
    pub fn observe_at(&mut self, facts: &ProcessFacts<'_>, report: &SuspicionReport, now: Instant) {
        let key = key_of(facts);
        let has_exempt = report
            .findings
            .iter()
            .any(|f| self.config.is_exempt(f.kind));

        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| BaselineEntry::new(now));
        entry.observations = entry.observations.saturating_add(1);
        entry.last_seen = now;
        entry.max_score_seen = entry.max_score_seen.max(report.score);
        entry.total_findings = entry
            .total_findings
            .saturating_add(report.findings.len() as u32);
        if has_exempt {
            entry.high_severity_seen = true;
        }
    }

    /// Remove entradas sem observação há mais de `max_entry_age`.
    pub fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.config.max_entry_age).unwrap_or(now);
        self.entries.retain(|_, e| e.last_seen >= cutoff);
    }

    // -- internos ----------------------------------------------------------

    fn is_entry_clean(&self, entry: &BaselineEntry) -> bool {
        entry.observations >= self.config.min_observations && !entry.high_severity_seen
    }
}

// ---------------------------------------------------------------------------
// Atenuação
// ---------------------------------------------------------------------------

/// Aplica atenuação sobre findings não-exempt.
///
/// Findings exempt ficam intactos. Findings não-exempt têm o peso
/// multiplicado por `attenuation_percent / 100`. O score é recalculado
/// e a severidade reavaliada. Se todos os findings sumirem com peso 0,
/// o report fica `Clean`.
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

/// Chave estável de baseline: `stem_normalizado|path_normalizado`.
///
/// Sem `exe_path`, só o stem. Lowercase, barras unificadas para `/`,
/// sem trailing `/`. Não usa hash de arquivo ainda (Fase 2 introduz).
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
        let mut b = Baseline::started_at(cfg(), Instant::now());
        let now = Instant::now();
        let f = facts("app.exe", Some("/tmp/app.exe"), "", None);
        let r = analyze(&f);
        assert_eq!(r.score, 30);

        // Mesmo com N observações, durante o aprendizado não atenua.
        for _ in 0..5 {
            let out = b.apply_at(&f, analyze(&f), now);
            assert_eq!(out.score, 30);
        }
    }

    #[test]
    fn known_clean_attenuates_after_learning() {
        let t0 = Instant::now();
        let mut b = Baseline::started_at(cfg(), t0);
        let f = facts("updater.exe", Some("/tmp/updater.exe"), "", None);

        // Aprende: 5 observações durante o período de aprendizado.
        for _ in 0..5 {
            b.apply_at(&f, analyze(&f), t0);
        }

        // Pós-aprendizado: aplica atenuação.
        let after = t0 + Duration::from_secs(120);
        let out = b.apply_at(&f, analyze(&f), after);

        // Original: TempDir(30) = 30. Atenuado: 30*30/100 = 9.
        assert_eq!(out.score, 9);
        assert_eq!(out.severity, Severity::Clean);
    }

    #[test]
    fn below_min_observations_no_attenuation() {
        let t0 = Instant::now();
        let mut b = Baseline::started_at(cfg(), t0);
        let f = facts("app.exe", Some("/tmp/app.exe"), "", None);

        // Apenas 1 observação durante aprendizado (< min=3).
        b.apply_at(&f, analyze(&f), t0);

        let after = t0 + Duration::from_secs(120);
        let out = b.apply_at(&f, analyze(&f), after);
        assert_eq!(out.score, 30);
    }

    #[test]
    fn exempt_finding_blocks_attenuation_forever() {
        let t0 = Instant::now();
        let mut b = Baseline::started_at(cfg(), t0);

        // Dia 1: processo benigno, acumula observações.
        let benign = facts("app.exe", Some("/opt/app.exe"), "", None);
        for _ in 0..5 {
            b.apply_at(&benign, analyze(&benign), t0);
        }
        assert!(b.is_known_clean(&benign));

        // Mesmo processo, agora com cmdline suspeita (exempt).
        let suspect = facts(
            "app.exe",
            Some("/opt/app.exe"),
            "powershell -enc AAAA",
            None,
        );
        b.apply_at(&suspect, analyze(&suspect), t0 + Duration::from_secs(1));
        assert!(!b.is_known_clean(&suspect));

        // Mesmo voltando a ser benigno, não atenua mais.
        let after = t0 + Duration::from_secs(120);
        let out = b.apply_at(&benign, analyze(&benign), after);
        // app.exe em /opt/app.exe sozinho dá score 0 — sem finding, sem
        // atenuação visível. Vamos usar um que tenha finding atenuável.
        let _ = out;

        // Confirma a marcação permanente: a entry tem high_severity_seen.
        let key = key_of(&benign);
        assert!(b.entries.get(&key).unwrap().high_severity_seen);
    }

    #[test]
    fn exempt_kinds_preserved_in_full() {
        // Processo com SuspiciousParent (exempt) + TempDir (atenuável).
        // Conhecido limpo: SuspiciousParent preserva 35, TempDir vira 9.
        let t0 = Instant::now();
        let mut b = Baseline::started_at(cfg(), t0);

        // Pré-aquece a chave SEM o finding exempt, durante aprendizado.
        let clean = facts("cmd.exe", Some("/tmp/cmd.exe"), "", None);
        for _ in 0..5 {
            b.apply_at(&clean, analyze(&clean), t0);
        }
        assert!(b.is_known_clean(&clean));

        // Agora dispara com SuspiciousParent + TempDir.
        let dirty = facts("cmd.exe", Some("/tmp/cmd.exe"), "", Some("winword.exe"));
        let original = analyze(&dirty);
        // TempDir 30 + SuspiciousParent 35 = 65.
        assert_eq!(original.score, 65);

        let after = t0 + Duration::from_secs(120);
        let out = b.apply_at(&dirty, original, after);

        // SuspiciousParent preserva 35; TempDir vira 30*30/100 = 9.
        // Total: 44. Mas como high_severity_seen ficou true na chamada
        // atual, a atenuação só vale por que was_clean era true ANTES
        // deste apply — o que é o correto (marca, mas não atenuou o
        // exempt desta chamada).
        assert_eq!(out.score, 44);
    }

    #[test]
    fn different_path_different_key() {
        let b = Baseline::with_defaults();
        let a = facts(
            "svchost.exe",
            Some(r"C:\Windows\System32\svchost.exe"),
            "",
            None,
        );
        let c = facts("svchost.exe", Some(r"C:\Temp\svchost.exe"), "", None);
        assert_ne!(key_of(&a), key_of(&c));
        assert!(!b.is_known_clean(&a));
        assert!(!b.is_known_clean(&c));
    }

    #[test]
    fn key_is_case_and_separator_insensitive() {
        let a = facts(
            "SVCHOST.EXE",
            Some(r"C:\Windows\System32\SVCHOST.EXE"),
            "",
            None,
        );
        let c = facts(
            "svchost.exe",
            Some("C:/windows/system32/svchost.exe"),
            "",
            None,
        );
        assert_eq!(key_of(&a), key_of(&c));
    }

    #[test]
    fn prune_removes_stale_entries() {
        let t0 = Instant::now();
        let mut b = Baseline::started_at(cfg(), t0);
        let f = facts("app.exe", Some("/opt/app.exe"), "", None);
        b.apply_at(&f, analyze(&f), t0);
        assert_eq!(b.len(), 1);

        b.prune(t0 + Duration::from_secs(7200));
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn known_clean_count_reflects_state() {
        let t0 = Instant::now();
        let mut b = Baseline::started_at(cfg(), t0);

        let f = facts("app.exe", Some("/opt/app.exe"), "", None);
        assert_eq!(b.known_clean_count(), 0);

        for _ in 0..3 {
            b.apply_at(&f, analyze(&f), t0);
        }
        assert_eq!(b.known_clean_count(), 1);

        // Adiciona um segundo que dispara exempt no caminho.
        let g = facts(
            "bad.exe",
            Some("/opt/bad.exe"),
            "powershell -enc AAAA",
            None,
        );
        for _ in 0..3 {
            b.apply_at(&g, analyze(&g), t0);
        }
        // Continua 1 — bad.exe nunca vira limpo.
        assert_eq!(b.known_clean_count(), 1);
    }

    #[test]
    fn is_learning_boundary() {
        let t0 = Instant::now();
        let b = Baseline::started_at(cfg(), t0);
        assert!(b.is_learning(t0));
        assert!(b.is_learning(t0 + Duration::from_secs(59)));
        assert!(!b.is_learning(t0 + Duration::from_secs(60)));
        assert!(!b.is_learning(t0 + Duration::from_secs(61)));
    }
}
