use serde::Serialize;
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct SystemEvent {
    pub time: String,
    pub level: String,
    pub source: String,
    pub id: u32,
    pub message: String,
}

/* =========================================================
Windows — PowerShell Get-WinEvent
========================================================= */

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

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output();

    match output {
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

/* =========================================================
Linux — journalctl
========================================================= */

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

/* =========================================================
macOS — unified log via `log show`
========================================================= */

#[cfg(target_os = "macos")]
pub fn collect_events(limit: usize) -> Vec<SystemEvent> {
    // `log show` retorna JSON quando --style json é usado.
    // Filtra últimos 30 min (o log show é pesado — limitar a janela).
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

/* =========================================================
Fallback — SOs sem suporte explícito
========================================================= */

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn collect_events(_limit: usize) -> Vec<SystemEvent> {
    log::warn!("Coleta de eventos do SO não implementada nesta plataforma");
    Vec::new()
}

/* =========================================================
Normalização de nível
========================================================= */

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

/* =========================================================
Parsing — Windows (JSON de PowerShell)
========================================================= */

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

/* =========================================================
Parsing — Linux (journalctl)
========================================================= */

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

/* =========================================================
Parsing — macOS (`log show` com --style json)
========================================================= */

#[cfg(target_os = "macos")]
fn parse_macos_log_events(text: &str) -> Vec<SystemEvent> {
    // `log show --style json` retorna um array de objetos.
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

            // macOS messageType: "Info", "Debug", "Error", "Fault", "Default"
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
