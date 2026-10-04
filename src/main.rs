mod auth;
mod broadcaster;
mod cli;
mod config;
mod embedded;
mod routes;
mod server;
mod settings;
mod storage;
mod sysinfo;
mod update;

use clap::Parser;
use cli::Cli;
use config::Config;
use settings::Settings;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let settings = Settings::load_or_create(&cli.config)?;
    let config = Config::build(&cli, settings);

    print_banner(&config);

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

    server::run(config)
}

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
