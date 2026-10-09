//! Tipos fundamentais do motor de detecção.

use serde::Serialize;

use super::mitre::{self, Technique};

/// Teto do score agregado. A soma dos pesos é truncada aqui.
pub const MAX_SCORE: u8 = 100;

/// Fatos observados de um processo, prontos para análise.
///
/// Coletados pelo `sysinfo::collector` (Fase 2) e entregues a
/// [`super::heuristics::analyze`]. Emprestado — nada é clonado aqui.
#[derive(Debug, Clone)]
pub struct ProcessFacts<'a> {
    /// PID do processo.
    pub pid: u32,
    /// PID do processo pai, se conhecido.
    pub parent_pid: Option<u32>,
    /// Nome do processo (com ou sem extensão). Ex.: `svchost.exe`.
    pub name: &'a str,
    /// Caminho absoluto do executável, se disponível.
    pub exe_path: Option<&'a str>,
    /// Linha de comando completa (vazia se desconhecida).
    pub cmdline: &'a str,
    /// Nome do processo pai, se disponível.
    pub parent_name: Option<&'a str>,
    /// Usuário dono (`SYSTEM`, `root`, `luann`, ...).
    pub user: Option<&'a str>,
    /// Sinalizado pelo chamador quando o CPU ficou alto por N leituras.
    /// O módulo é stateless — quem tem histórico marca esta flag.
    pub cpu_sustained_high: bool,
}

/// Categoria de heurística que disparou.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    TempDir,
    Typosquatting,
    SuspiciousParent,
    SuspiciousCmdline,
    HiddenExecutable,
    UserWritableLocation,
    CpuSustainedHigh,
    /// Porta alta escutando em processo de user (não sistema).
    UnusualListeningPort,
    /// Conexão estabelecida com IP público não correlacionada ao processo.
    ExternalConnection,
    /// Nome canônico de processo do sistema rodando fora de dir canônico.
    /// Padrão #1 de malware Windows (`svchost.exe` em `%TEMP%`, etc.).
    MasqueradeLocation,
    /// Binário nativo do Windows usado como proxy (LOLBin).
    /// Ex.: `certutil -urlcache`, `mshta http`, `regsvr32 /i:http`.
    LolBin,
    /// Combo de flags de obfuscação em PowerShell.
    /// Ex.: `-w hidden -nop -ep bypass` sem `-EncodedCommand`.
    ObfuscatedCommand,
    /// Conexão estabelecida para porta de serviço sensível em IP público.
    /// Ex.: 3389 (RDP), 445 (SMB), 1433 (MSSQL).
    SuspiciousRemotePort,
}

impl FindingKind {
    /// Peso somado ao score quando este finding dispara.
    ///
    /// Valores iniciais calibrados para workstation; virarão config em
    /// Fase 8 (`[security.weights.*]`).
    pub fn weight(self) -> u8 {
        match self {
            FindingKind::Typosquatting => 40,
            FindingKind::MasqueradeLocation => 45,
            FindingKind::SuspiciousParent => 35,
            FindingKind::LolBin => 35,
            FindingKind::TempDir => 30,
            FindingKind::SuspiciousCmdline => 30,
            FindingKind::ObfuscatedCommand => 25,
            FindingKind::HiddenExecutable => 25,
            FindingKind::SuspiciousRemotePort => 25,
            FindingKind::UnusualListeningPort => 20,
            FindingKind::UserWritableLocation => 15,
            FindingKind::CpuSustainedHigh => 15,
            FindingKind::ExternalConnection => 15,
        }
    }

    /// Técnica ATT&CK padrão associada a este tipo de finding.
    ///
    /// Alguns findings apontam para técnicas mais específicas dependendo
    /// do contexto (ex.: `SuspiciousCmdline` vira `T1059.001` para
    /// PowerShell, `T1105` para download-cradle). Nesses casos o
    /// heurístico sobrescreve via [`Finding::with_technique`].
    pub fn default_technique(self) -> Option<Technique> {
        match self {
            FindingKind::Typosquatting => Some(mitre::MASQUERADING_NAME_OR_LOCATION),
            FindingKind::MasqueradeLocation => Some(mitre::MASQUERADING_NAME_OR_LOCATION),
            FindingKind::LolBin => Some(mitre::SYSTEM_BINARY_PROXY),
            FindingKind::SuspiciousParent => Some(mitre::COMMAND_AND_SCRIPTING),
            FindingKind::SuspiciousCmdline => Some(mitre::COMMAND_AND_SCRIPTING),
            FindingKind::ObfuscatedCommand => Some(mitre::OBFUSCATED_FILES),
            FindingKind::HiddenExecutable => Some(mitre::MASQUERADING),
            FindingKind::TempDir | FindingKind::UserWritableLocation => Some(mitre::USER_EXECUTION),
            FindingKind::CpuSustainedHigh => None,
            FindingKind::UnusualListeningPort => Some(mitre::NON_STANDARD_PORT),
            FindingKind::ExternalConnection => Some(mitre::APPLICATION_LAYER_PROTOCOL),
            FindingKind::SuspiciousRemotePort => Some(mitre::REMOTE_SERVICES),
        }
    }
}

/// Um finding individual — categoria, peso, explicação e técnica MITRE.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub weight: u8,
    pub detail: String,
    /// Técnica ATT&CK, quando aplicável.
    pub technique: Option<Technique>,
}

impl Finding {
    /// Constrói um finding preenchendo peso e técnica padrão a partir
    /// de `kind`.
    pub fn new(kind: FindingKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            weight: kind.weight(),
            detail: detail.into(),
            technique: kind.default_technique(),
        }
    }

    /// Como [`Finding::new`], mas sobrescreve a técnica (útil quando o
    /// contexto do match indica uma técnica mais específica).
    pub fn with_technique(
        kind: FindingKind,
        detail: impl Into<String>,
        technique: Technique,
    ) -> Self {
        Self {
            kind,
            weight: kind.weight(),
            detail: detail.into(),
            technique: Some(technique),
        }
    }
}

/// Nível agregado do score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Clean,
    Attention,
    Suspicious,
    Critical,
}

impl Severity {
    /// Converte score 0-100 em nível discreto.
    ///
    /// - `0..=19` → Clean
    /// - `20..=49` → Attention
    /// - `50..=79` → Suspicious
    /// - `80..=100` → Critical
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Severity::Clean,
            20..=49 => Severity::Attention,
            50..=79 => Severity::Suspicious,
            _ => Severity::Critical,
        }
    }
}

/// Resultado completo da análise de um processo.
#[derive(Debug, Clone, Serialize)]
pub struct SuspicionReport {
    pub score: u8,
    pub severity: Severity,
    pub findings: Vec<Finding>,
}

impl SuspicionReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}
