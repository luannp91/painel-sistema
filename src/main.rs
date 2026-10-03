mod broadcaster;
mod cli;
mod config;
mod embedded;
mod routes;
mod server;
mod sysinfo;

use clap::Parser;
use cli::Cli;
use config::Config;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let config = Config::from_cli(&cli);

    print_banner(&config);

    // Se --web foi passado, valida; senão, usa embed.
    if let Some(ref root) = config.web_root {
        if !root.exists() {
            anyhow::bail!(
                "Diretório --web não encontrado: {}\n\
                 Omita --web para usar os arquivos embutidos no executável.",
                root.display()
            );
        }
    } else if !embedded::WebAssets::has_index() {
        anyhow::bail!(
            "Nenhum asset embutido encontrado. Rode o build a partir da raiz do projeto \
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

    println!("═══════════════════════════════════════════════");
    println!("  Painel do Sistema — Agente Rust");
    println!("═══════════════════════════════════════════════");
    println!("  Porta:         {}", config.port);
    println!("  Frontend:      {}", fonte);
    println!("  Intervalo SSE: {:?}", config.interval);
    println!("  Bind:          {}", config.bind_addr());
    println!("═══════════════════════════════════════════════");
    println!("  Abra: http://localhost:{}", config.port);
    println!("═══════════════════════════════════════════════\n");
}
