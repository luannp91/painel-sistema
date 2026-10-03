use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "painel-sistema",
    version,
    about = "Agente nativo do Painel do Sistema",
    long_about = "Serve a interface web e expõe dados do SO via REST + SSE.\n\
                  Acesse http://localhost:<porta> no navegador.\n\n\
                  Sem --web, usa os assets embutidos no executável."
)]
pub struct Cli {
    /// Porta HTTP do agente
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,

    /// Diretório com os arquivos web (opcional).
    /// Se omitido, usa os assets embutidos no executável.
    #[arg(short, long)]
    pub web: Option<PathBuf>,

    /// Intervalo entre atualizações SSE, em segundos
    #[arg(short, long, default_value_t = 2)]
    pub interval: u64,

    /// Binda em todas as interfaces (0.0.0.0) em vez de localhost
    #[arg(long, default_value_t = false)]
    pub bind_all: bool,
}
