use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "painel-sistema",
    version,
    about = "Agente nativo do Painel do Sistema",
    long_about = "Serve a interface web e expõe dados do SO via REST + SSE.\n\
                  Acesse http://localhost:<porta> no navegador.\n\n\
                  Sem --web, usa os assets embutidos no executável.\n\
                  Sem --port/--interval/--bind-all, usa config.toml."
)]
pub struct Cli {
    /// Porta HTTP (sobrepõe config.toml)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Diretório web opcional. Se omitido, usa os embutidos.
    #[arg(short, long)]
    pub web: Option<PathBuf>,

    /// Caminho do arquivo de configuração
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    /// Intervalo entre coletas em segundos (sobrepõe config.toml)
    #[arg(short, long)]
    pub interval: Option<u64>,

    /// Binda em 0.0.0.0 em vez de localhost (sobrepõe config.toml)
    #[arg(long)]
    pub bind_all: bool,

    /// Roda com ícone na bandeja do sistema (padrão em release no Windows).
    #[arg(long)]
    pub tray: bool,

    /// Força modo console mesmo em release (útil pra ver os logs no terminal).
    #[arg(long, conflicts_with = "tray")]
    pub no_tray: bool,

    /// Não abre o browser automaticamente na primeira execução.
    #[arg(long)]
    pub no_open: bool,
}
