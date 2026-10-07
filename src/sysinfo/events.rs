use std::process::Command;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SystemEvent {
    pub time: String,
    pub level: String,
    pub source: String,
    pub id: u32,
    pub message: String,
}

/// TTL default do cache de eventos (segundos). Eventos do SO mudam
/// devagar — não faz sentido ir ao PowerShell a cada fetch do frontend.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 15;

/// Flag do Windows pra não abrir janela do processo filho.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

// ===========================================================================
// EventCollector — camada de cache sobre `collect_events`
// ===========================================================================

/// Envolve `collect_events` com um cache com TTL. Chamar `collect` várias
/// vezes dentro da janela devolve o mesmo `Vec` (clonado) sem tocar no SO.
///
/// Não é thread-safe — quem usa serializa (a rota `/api/events` recebe
/// um `Arc<Mutex<EventCollector>>`).
pub struct EventCollector {
    cached: Option<CachedBatch>,
    ttl: Duration,
}

struct CachedBatch {
    events: Vec<SystemEvent>,
    at: Instant,
    /// Maior limit já requisitado (define o tamanho útil do cache).
    max_limit: usize,
}

impl EventCollector {
    pub fn new(ttl: Duration) -> Self {
        Self { cached: None, ttl }
    }

    pub fn with_default_ttl() -> Self {
        Self::new(Duration::from_secs(DEFAULT_CACHE_TTL_SECS))
    }

    /// Devolve até `limit` eventos. Usa cache se ainda estiver fresco
    /// **e** tiver eventos suficientes. Caso contrário, rebusca.
    pub fn collect(&mut self, limit: usize) -> Vec<SystemEvent> {
        if let Some(batch) = &self.cached {
            let fresh = batch.at.elapsed() < self.ttl;
            let has_enough = batch.max_limit >= limit;
            if fresh && has_enough {
                return batch.events.iter().take(limit).cloned().collect();
            }
        }

        let events = collect_events(limit);
        self.cached = Some(CachedBatch {
            events: events.clone(),
            at: Instant::now(),
            max_limit: limit,
        });
        events
    }

    /// Limpa o cache forçando próxima chamada a ir ao SO.
    #[allow(dead_code)]
    pub fn invalidate(&mut self) {
        self.cached = None;
    }
}

// ===========================================================================
// Windows — PowerShell Get-WinEvent (com CREATE_NO_WINDOW)
// ===========================================================================

#[cfg(windows)]
pub fn collect_events(limit: usize) -> Vec<SystemEvent> {
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
         $OutputEncoding = [System.Text.Encoding]::UTF8; \
         $ProgressPreference = 'SilentlyContinue'; \
         Get-WinEvent -LogName System -MaxEvents {} | \
         Select-Object @{{N='time';E={{$_.TimeCreated.ToString('o')}}}}, \
                       @{{N='level';E={{$_.LevelDisplayName}}}}, \
                       @{{N='source';E={{$_.ProviderName}}}}, \
                       @{{N='id';E={{$_.Id}}}}, \
                       @{{N='message';E={{$_.Message}}}} | \
         ConvertTo-Json -Compress -Depth 3",
        limit
    );

    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-Command",
        &script,
    ]);
    // Dupla proteção contra o flash de janela: CREATE_NO_WINDOW no
    // CreateProcess + -WindowStyle Hidden no PowerShell.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    match cmd.output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_json_events(&text)
        }
        Ok(out) => {
            log::warn!(
                "Get-WinEvent falhou: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            Vec::new()
        }
        Err(e) => {
            log::warn!("powershell não disponível: {}", e);
            Vec::new()
        }
    }
}

// ===========================================================================
// Linux — journalctl
// ===========================================================================

#[cfg(target_os = "linux")]
pub fn collect_events(limit: usize) -> Vec<SystemEvent> {
    let output = Command::new("journalctl")
        .args(["-n", &limit.to_string(), "-o", "json", "--no-pager"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_journal_events(&text)
        }
        Ok(out) => {
            log::warn!(
                "journalctl falhou: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            Vec::new()
        }
        Err(e) => {
            log::warn!("journalctl não disponível: {}", e);
            Vec::new()
        }
    }
}

// ===========================================================================
// macOS — unified log
// ===========================================================================

#[cfg(target_os = "macos")]
pub fn collect_events(limit: usize) -> Vec<SystemEvent> {
    let output = Command::new("log")
        .args([
            "show",
            "--last",
            "30m",
            "--style",
            "json",
            "--predicate",
            "eventType == logEvent OR eventType == traceEvent",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut events = parse_macos_log_events(&text);
            events.truncate(limit);
            events
        }
        Ok(out) => {
            log::warn!("log show falhou: {}", String::from_utf8_lossy(&out.stderr));
            Vec::new()
        }
        Err(e) => {
            log::warn!("comando log não disponível: {}", e);
            Vec::new()
        }
    }
}

// ===========================================================================
// Fallback
// ===========================================================================

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn collect_events(_limit: usize) -> Vec<SystemEvent> {
    log::warn!("Coleta de eventos do SO não implementada nesta plataforma");
    Vec::new()
}

// ===========================================================================
// Normalização de nível
// ===========================================================================

fn normalize_level(raw: &str) -> String {
    match raw.trim().to_lowercase().as_str() {
        "error" | "critical" | "critical error" | "erro" | "crítico" | "critico"
        | "erro crítico" | "erro critico" | "fehler" | "kritisch" | "erreur" | "critique"
        | "fallo" | "fault" => "Error".into(),

        "warning" | "warnung" | "aviso" | "alerta" | "avertissement" | "advertencia" | "warn" => {
            "Warning".into()
        }

        "information" | "informations" | "info" | "informação" | "informacao" | "informativo"
        | "información" | "informacion" | "notice" => "Information".into(),

        "verbose" | "detalhado" | "detalhe" | "debug" | "trace" => "Verbose".into(),

        _ => "Information".into(),
    }
}

// ===========================================================================
// Parsing — Windows (JSON de PowerShell)
// ===========================================================================

#[cfg(windows)]
fn parse_json_events(text: &str) -> Vec<SystemEvent> {
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("JSON de eventos inválido: {}", e);
            return Vec::new();
        }
    };

    let arr = match value {
        serde_json::Value::Array(a) => a,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Vec::new(),
    };

    arr.into_iter()
        .filter_map(|v| {
            let obj = v.as_object()?;
            Some(SystemEvent {
                time: obj
                    .get("time")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                level: normalize_level(
                    obj.get("level")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Information"),
                ),
                source: obj
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                id: obj.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                message: obj
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            })
        })
        .collect()
}

// ===========================================================================
// Parsing — Linux
// ===========================================================================

#[cfg(target_os = "linux")]
fn parse_journal_events(text: &str) -> Vec<SystemEvent> {
    text.lines()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let obj = v.as_object()?;

            let priority = obj
                .get("PRIORITY")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(6);

            let level = match priority {
                0..=3 => "Error",
                4 => "Warning",
                5 => "Information",
                _ => "Information",
            };

            Some(SystemEvent {
                time: obj
                    .get("__REALTIME_TIMESTAMP")
                    .and_then(|v| v.as_str())
                    .and_then(|us| us.parse::<u64>().ok())
                    .map(|us| chrono_from_unix(us / 1_000_000))
                    .unwrap_or_default(),
                level: normalize_level(level),
                source: obj
                    .get("SYSLOG_IDENTIFIER")
                    .or_else(|| obj.get("_COMM"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                id: 0,
                message: obj
                    .get("MESSAGE")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn chrono_from_unix(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days as i64);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

#[cfg(target_os = "linux")]
fn days_to_ymd(mut days: i64) -> (i32, u32, u32) {
    let mut year = 1970i32;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let dy = if leap { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let months = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u32;
    for md in months {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, (days + 1) as u32)
}

// ===========================================================================
// Parsing — macOS
// ===========================================================================

#[cfg(target_os = "macos")]
fn parse_macos_log_events(text: &str) -> Vec<SystemEvent> {
    let value: serde_json::Value = match serde_json::from_str(text.trim()) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let arr = match value {
        serde_json::Value::Array(a) => a,
        _ => return Vec::new(),
    };

    arr.into_iter()
        .filter_map(|v| {
            let obj = v.as_object()?;

            let message = obj
                .get("eventMessage")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let level_raw = obj
                .get("messageType")
                .and_then(|v| v.as_str())
                .unwrap_or("Info");

            let level = normalize_level(level_raw);

            Some(SystemEvent {
                time: obj
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                level,
                source: obj
                    .get("process")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                id: obj.get("eventType").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                message: message.to_string(),
            })
        })
        .collect()
}

// ===========================================================================
// Testes
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_level_handles_pt_en() {
        assert_eq!(normalize_level("Error"), "Error");
        assert_eq!(normalize_level("erro"), "Error");
        assert_eq!(normalize_level("Crítico"), "Error");
        assert_eq!(normalize_level("Warning"), "Warning");
        assert_eq!(normalize_level("Information"), "Information");
        assert_eq!(normalize_level("info"), "Information");
        assert_eq!(normalize_level("Verbose"), "Verbose");
        assert_eq!(normalize_level("algo-aleatorio"), "Information");
    }

    #[test]
    fn event_collector_invalidate_clears() {
        let mut c = EventCollector::new(Duration::from_secs(60));
        // Não chamamos collect() — só testamos que invalidate zera o Option.
        assert!(c.cached.is_none());
        c.cached = Some(CachedBatch {
            events: Vec::new(),
            at: Instant::now(),
            max_limit: 1,
        });
        assert!(c.cached.is_some());
        c.invalidate();
        assert!(c.cached.is_none());
    }
}
