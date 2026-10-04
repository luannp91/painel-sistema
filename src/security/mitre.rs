//! Mapeamento para MITRE ATT&CK.
//!
//! Referência: <https://attack.mitre.org/>.
//!
//! Cada [`Technique`] carrega id, nome e tática. As constantes abaixo
//! cobrem as técnicas que as heurísticas atuais podem produzir. Novas
//! técnicas entram conforme os heurísticos evoluem.

use serde::Serialize;

/// Tática ATT&CK (coluna do framework).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

/// Técnica ATT&CK. `id` usa a notação oficial (`T1059.001`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Technique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactic: Tactic,
}

// ---- Execution -----------------------------------------------------------

pub const COMMAND_AND_SCRIPTING: Technique = Technique {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: Tactic::Execution,
};

pub const POWERSHELL: Technique = Technique {
    id: "T1059.001",
    name: "PowerShell",
    tactic: Tactic::Execution,
};

pub const WINDOWS_COMMAND_SHELL: Technique = Technique {
    id: "T1059.003",
    name: "Windows Command Shell",
    tactic: Tactic::Execution,
};

pub const UNIX_SHELL: Technique = Technique {
    id: "T1059.004",
    name: "Unix Shell",
    tactic: Tactic::Execution,
};

pub const USER_EXECUTION: Technique = Technique {
    id: "T1204",
    name: "User Execution",
    tactic: Tactic::Execution,
};

// ---- Defense Evasion -----------------------------------------------------

pub const MASQUERADING: Technique = Technique {
    id: "T1036",
    name: "Masquerading",
    tactic: Tactic::DefenseEvasion,
};

pub const MASQUERADING_NAME_OR_LOCATION: Technique = Technique {
    id: "T1036.005",
    name: "Match Legitimate Name or Location",
    tactic: Tactic::DefenseEvasion,
};

pub const OBFUSCATED_FILES: Technique = Technique {
    id: "T1027",
    name: "Obfuscated Files or Information",
    tactic: Tactic::DefenseEvasion,
};

pub const DEOBFUSCATE_DECODE: Technique = Technique {
    id: "T1140",
    name: "Deobfuscate/Decode Files or Information",
    tactic: Tactic::DefenseEvasion,
};

// ---- Command and Control -------------------------------------------------

pub const INGRESS_TOOL_TRANSFER: Technique = Technique {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tactic: Tactic::CommandAndControl,
};

pub const NON_APP_LAYER_PROTOCOL: Technique = Technique {
    id: "T1095",
    name: "Non-Application Layer Protocol",
    tactic: Tactic::CommandAndControl,
};
