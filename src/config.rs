use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::Cli;
use crate::settings::Settings;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub web_root: Option<PathBuf>,
    pub interval: Duration,
    pub bind_all: bool,
    pub auth_enabled: bool,
    pub auth_token: String,
    pub settings: Settings,
    pub config_dir: PathBuf,
}

impl Config {
    pub fn build(cli: &Cli, settings: Settings) -> Self {
        let port = cli.port.unwrap_or(settings.server.port);
        let interval_secs = cli
            .interval
            .unwrap_or(settings.server.interval_seconds)
            .max(1);
        let bind_all = cli.bind_all || settings.server.bind_all;
        let auth_enabled = settings.auth_active();

        let config_dir = cli
            .config
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        Self {
            port,
            web_root: cli.web.clone(),
            interval: Duration::from_secs(interval_secs),
            bind_all,
            auth_enabled,
            auth_token: settings.auth.token.clone(),
            settings,
            config_dir,
        }
    }

    pub fn bind_addr(&self) -> String {
        if self.bind_all {
            format!("0.0.0.0:{}", self.port)
        } else {
            format!("127.0.0.1:{}", self.port)
        }
    }

    pub fn db_path(&self) -> Option<PathBuf> {
        if !self.settings.database.enabled {
            return None;
        }
        Some(self.config_dir.join(&self.settings.database.path))
    }
}
