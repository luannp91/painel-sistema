use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct Settings {
    pub server: ServerSettings,
    pub auth: AuthSettings,
    pub thresholds: ThresholdSettings,
    pub patterns: PatternSettings,
    pub events: EventSettings,
    pub database: DatabaseSettings,
}

/* ---------------------- Server ---------------------- */

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerSettings {
    pub port: u16,
    pub bind_all: bool,
    pub interval_seconds: u64,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            port: 8080,
            bind_all: false,
            interval_seconds: 2,
        }
    }
}

/* ---------------------- Auth ---------------------- */

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct AuthSettings {
    pub enabled: bool,
    pub token: String,
}

/* ---------------------- Thresholds ---------------------- */

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct ThresholdSettings {
    pub cpu: CpuThresholds,
    pub memory: MemoryThresholds,
    pub disk: DiskThresholds,
    pub swap: SwapThresholds,
    pub network: NetworkThresholds,
    pub processes: ProcessThresholds,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CpuThresholds {
    pub spike_percent: f32,
    pub spike_readings: usize,
    pub sustained_percent: f32,
    pub sustained_readings: usize,
}

impl Default for CpuThresholds {
    fn default() -> Self {
        Self {
            spike_percent: 85.0,
            spike_readings: 5,
            sustained_percent: 60.0,
            sustained_readings: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MemoryThresholds {
    pub critical_percent: f32,
    pub growth_percent_per_min: f64,
    pub growth_readings: usize,
}

impl Default for MemoryThresholds {
    fn default() -> Self {
        Self {
            critical_percent: 90.0,
            growth_percent_per_min: 0.3,
            growth_readings: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DiskThresholds {
    pub critical_percent: f32,
    pub filling_mb_per_5min: u64,
}

impl Default for DiskThresholds {
    fn default() -> Self {
        Self {
            critical_percent: 90.0,
            filling_mb_per_5min: 500,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SwapThresholds {
    pub active_percent: f32,
}

impl Default for SwapThresholds {
    fn default() -> Self {
        Self {
            active_percent: 20.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct NetworkThresholds {
    pub burst_multiplier: f64,
    pub min_baseline_bytes: u64,
}

impl Default for NetworkThresholds {
    fn default() -> Self {
        Self {
            burst_multiplier: 10.0,
            min_baseline_bytes: 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ProcessThresholds {
    pub churn_max_delta: usize,
    pub high_count: usize,
}

impl Default for ProcessThresholds {
    fn default() -> Self {
        Self {
            churn_max_delta: 20,
            high_count: 300,
        }
    }
}

/* ---------------------- Patterns ---------------------- */

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PatternSettings {
    pub history_capacity: usize,
    pub active_window_seconds: u64,
    pub max_age_seconds: u64,
    pub max_patterns: usize,
}

impl Default for PatternSettings {
    fn default() -> Self {
        Self {
            history_capacity: 180,
            active_window_seconds: 60,
            max_age_seconds: 3600,
            max_patterns: 200,
        }
    }
}

/* ---------------------- Events ---------------------- */

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct EventSettings {
    pub default_limit: usize,
    pub max_limit: usize,
}

impl Default for EventSettings {
    fn default() -> Self {
        Self {
            default_limit: 100,
            max_limit: 500,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DatabaseSettings {
    pub enabled: bool,
    pub path: String,
    pub retention_days: u64,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "painel.db".into(),
            retention_days: 7,
        }
    }
}

/* ---------------------- Load/Create ---------------------- */

impl Settings {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let text = fs::read_to_string(path)
                .with_context(|| format!("não foi possível ler {}", path.display()))?;
            let settings: Settings = toml::from_str(&text)
                .with_context(|| format!("TOML inválido em {}", path.display()))?;
            log::info!("Configuração carregada de {}", path.display());
            Ok(settings)
        } else {
            let default = Settings::default();
            let text = toml::to_string_pretty(&default)?;
            fs::write(path, text)
                .with_context(|| format!("não foi possível criar {}", path.display()))?;
            log::info!("Configuração padrão criada em {}", path.display());
            Ok(default)
        }
    }

    pub fn auth_active(&self) -> bool {
        self.auth.enabled && self.auth.token.len() >= 16
    }
}
