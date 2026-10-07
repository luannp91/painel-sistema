#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod auth;
mod broadcaster;
mod cli;
mod config;
mod embedded;
mod routes;
mod security;
mod server;
mod settings;
mod storage;
mod sysinfo;
#[cfg(windows)]
mod tray;
mod update;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use cli::Cli;
use config::Config;
use routes::security::SecurityCache;
use settings::Settings;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(&cli);

    let settings = Settings::load_or_create(&cli.config)?;
    let config = Config::build(&cli, settings);

    let use_tray = should_use_tray(&cli);

    if !use_tray {
        print_banner(&config);
    }

    if let Some(ref root) = config.web_root {
        if !root.exists() {
            anyhow::bail!("Diretório --web não encontrado: {}", root.display());
        }
    } else if !embedded::WebAssets::has_index() {
        anyhow::bail!(
            "Nenhum asset embutido. Rode o build a partir da raiz do projeto \
             (a pasta `web/` precisa existir)."
        );
    }

    let security_cache: SecurityCache = Arc::new(Mutex::new(None));

    #[cfg(windows)]
    if use_tray {
        return run_tray_mode(config, security_cache, cli.no_open);
    }

    let _ = security_cache;
    server::run(config, security_cache)
}

// ---------------------------------------------------------------------------
// Modo tray (Windows)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_tray_mode(config: Config, cache: SecurityCache, no_open: bool) -> anyhow::Result<()> {
    let port = config.port;
    let state_dir = user_state_dir();
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("painel-sistema.exe"));

    // Registrar o AppID do toast antes de qualquer notificação — sem
    // isso o Windows nega a ativação COM e dispara Event ID 10016.

    // Token vai na URL da abertura inicial pra evitar prompt manual.
    let token = if config.auth_enabled {
        Some(config.auth_token.clone())
    } else {
        None
    };

    // Servidor HTTP sobe em thread separada.
    {
        let config = config.clone();
        let cache = cache.clone();
        std::thread::spawn(move || {
            if let Err(e) = server::run(config, cache) {
                log::error!("servidor encerrou: {:#}", e);
            }
        });
    }

    // Margem pro bind completar (heurística: 800ms é folgado).
    std::thread::sleep(Duration::from_millis(800));

    // Primeira execução? Marca e agenda abertura + toast.
    let marker = state_dir.join(".first-run-done");
    let first_run = !marker.exists();
    if first_run {
        let _ = std::fs::write(&marker, b"1");
    }

    if first_run && !no_open {
        let _ = tray::open_browser(port, token.as_deref());
        std::thread::spawn(move || {
            // pequena espera pro toast aparecer depois da janela abrir
            std::thread::sleep(Duration::from_millis(500));
            tray::notify(
                "Painel do Sistema",
                "Rodando em segundo plano. Clique no ícone na bandeja para abrir.",
            );
        });
    }

    // Bloqueia no message loop do tray.
    tray::run(
        tray::TrayConfig {
            port,
            state_dir,
            exe_path,
            token,
        },
        cache,
    )
}

/// Decide se roda com tray: release Windows = sim, debug = não (preserva
/// workflow de `cargo run` com banner). Flags sobrescrevem.
fn should_use_tray(cli: &Cli) -> bool {
    if cli.no_tray {
        return false;
    }
    if cli.tray {
        return true;
    }
    cfg!(all(windows, not(debug_assertions)))
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

fn init_logger(_cli: &Cli) {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

    // Em release+tray não há console: escreve em arquivo.
    #[cfg(all(windows, not(debug_assertions)))]
    if !_cli.no_tray {
        let dir = user_state_dir();
        let log_path = dir.join("painel.log");
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(file) => {
                builder.target(env_logger::Target::Pipe(Box::new(file)));
            }
            Err(e) => eprintln!("aviso: não foi possível abrir {}: {e}", log_path.display()),
        }
    }

    let _ = builder.try_init();
}

/// Diretório gravável por usuário pra logs e marker de primeira execução.
fn user_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(local).join("painel-sistema");
            let _ = std::fs::create_dir_all(&p);
            return p;
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home).join(".local/state/painel-sistema");
            let _ = std::fs::create_dir_all(&p);
            return p;
        }
    }
    std::env::temp_dir().join("painel-sistema")
}

// ---------------------------------------------------------------------------
// Banner (modo console)
// ---------------------------------------------------------------------------

fn print_banner(config: &Config) {
    let fonte = match &config.web_root {
        Some(p) => format!("disco ({})", p.display()),
        None => "embutido no executável".into(),
    };

    let auth_info = if config.auth_enabled {
        "🔒 ATIVADA (token obrigatório em /api/*)".to_string()
    } else {
        "🔓 Desativada (uso local)".to_string()
    };

    println!("═══════════════════════════════════════════════");
    println!("  Painel do Sistema — Agente Rust");
    println!("═══════════════════════════════════════════════");
    println!("  Porta:         {}", config.port);
    println!("  Frontend:      {}", fonte);
    println!("  Intervalo SSE: {:?}", config.interval);
    println!("  Bind:          {}", config.bind_addr());
    println!("  Autenticação:  {}", auth_info);
    println!("═══════════════════════════════════════════════");
    println!("  Abra: http://localhost:{}", config.port);
    println!("═══════════════════════════════════════════════\n");
}
