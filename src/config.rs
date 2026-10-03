use std::path::PathBuf;
use std::time::Duration;

use crate::cli::Cli;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub web_root: Option<PathBuf>,
    pub interval: Duration,
    pub bind_all: bool,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            port: cli.port,
            web_root: cli.web.clone(), // já é Option<PathBuf>
            interval: Duration::from_secs(cli.interval.max(1)),
            bind_all: cli.bind_all,
        }
    }

    pub fn bind_addr(&self) -> String {
        if self.bind_all {
            format!("0.0.0.0:{}", self.port)
        } else {
            format!("127.0.0.1:{}", self.port)
        }
    }
}
