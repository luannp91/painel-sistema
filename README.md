# 🦀 Painel do Sistema

Agente nativo em Rust que coleta informações do sistema operacional, detecta
padrões de uso anormais e serve um painel web em tempo real — tudo em um único
executável, sem dependências externas.

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## ✨ Recursos

- **Coleta nativa** — CPU, memória, swap, disco, rede, processos e eventos do SO
- **Padrões** — detecção automática de anomalias (CPU spike, memory leak, disco crítico, etc.)
- **Eventos do SO** — leitura do Windows Event Log / `journalctl` com filtros por nível
- **Processos** — lista completa com ação de kill (protegido por token)
- **Histórico** — persistência em SQLite com gráficos interativos (uPlot, zoom/pan)
- **Notificações** — toast nativo do Windows para padrões críticos
- **Auto-update** — verifica GitHub Releases e avisa sobre novas versões
- **Autenticação** — token Bearer opcional para expor em LAN
- **Config externo** — `config.toml` com todos os thresholds ajustáveis
- **Um binário** — frontend embutido via `rust-embed`

---

## 📋 Requisitos

| Item                      | Versão mínima |
| ------------------------- | ------------- |
| Rust                      | 1.75          |
| (Windows) C++ Build Tools | VS 2019+      |
| (Linux) build-essential   | —             |

---

## 🚀 Como rodar

### Opção 1 — Instalador `.msi` (Windows, recomendado)

Baixe o instalador na página de [Releases](https://github.com/luannp91/painel-sistema/releases):

Duplo clique → próximo, próximo, instalar. O painel fica em
`http://localhost:8080` e é registrado como serviço do Windows
(opcional, escolha durante a instalação).

### Opção 2 — Compilar do código

```bash
git clone https://github.com/luannp91/painel-sistema
cd painel-sistema
cargo build --release
```

# Linux / macOS

./target/release/painel-sistema

# Windows

.\target\release\painel-sistema.exe

[server]
port = 8080
bind_all = false
interval_seconds = 2

[auth]
enabled = false
token = ""

[thresholds.cpu]
spike_percent = 85.0
spike_readings = 5

# ... (veja o arquivo completo)

Flags da CLI (sobrepõem o config.toml)
text

--port <N> Porta HTTP
--web <PATH> Diretório com assets (default: embutidos)
--interval <N> Intervalo SSE em segundos
--bind-all Escuta em 0.0.0.0 (LAN)
--config <PATH> Caminho do config.toml

📡 API
Método Endpoint Descrição
GET /api/snapshot Snapshot completo (CPU, memória, disco, rede, processos)
GET /api/stream SSE (event stream) atualizado a cada N segundos
GET /api/events?limit=N Eventos do SO (Windows Event Log / journalctl)
GET /api/patterns?limit=N Padrões detectados + histórico recente
GET /api/processes Lista completa de processos
POST /api/processes/{pid}/kill Encerra processo
GET /api/history?minutes=N&limit=M Série temporal de amostras
GET /api/db-stats Contagens do banco
GET /api/update-check Verifica nova versão no GitHub
GET /api/health Health check

Quando auth.enabled = true, todas as rotas /api/\* exigem:
text

Authorization: Bearer <token>

Para SSE (EventSource não suporta headers), use ?token=<token> na URL.
🎨 Interface
Página URL Descrição
Painel / Cards em tempo real + dados do navegador
Processos /processes.html Lista com sort, filtro e kill
Eventos /events.html Log do SO com filtros
Padrões /patterns.html Anomalias detectadas + gráfico
Histórico /history.html Séries temporais com zoom
🏗️ Arquitetura
text

┌────────────────────────────────────────────────────┐
│ Navegador │
│ ├── /api/snapshot (JSON, fetch) │
│ ├── /api/stream (SSE, 2s) │
│ ├── /api/events (logs do SO) │
│ ├── /api/patterns (anomalias) │
│ ├── /api/processes (lista + kill) │
│ └── /api/history (SQLite) │
└────────────────────┬───────────────────────────────┘
│ HTTP (localhost:8080)
┌────────────────────▼───────────────────────────────┐
│ painel-sistema (Rust) │
│ ├── tiny_http HTTP server │
│ ├── sysinfo Coleta nativa │
│ ├── rusqlite Persistência │
│ ├── crossbeam-channel Broadcast SSE │
│ └── rust-embed Assets embutidos │
└────────────────────┬───────────────────────────────┘
│
┌──────────────┼──────────────┐
│ │ │
/proc, WMI /var/log, EvtLog SQLite

🔧 Desenvolvimento
Rodar testes
bash

cargo test

Lint
bash

cargo clippy --all-targets -- -D warnings
cargo fmt --check

Estrutura
text

painel-sistema/
├── Cargo.toml
├── build.rs # Metadados do .exe no Windows
├── config.toml # Config externo
├── src/
│ ├── main.rs
│ ├── cli.rs, config.rs, settings.rs
│ ├── auth.rs # Token Bearer
│ ├── storage.rs # SQLite
│ ├── update.rs # Auto-update
│ ├── broadcaster.rs # SSE broadcast
│ ├── server.rs # HTTP loop
│ ├── embedded.rs # rust-embed wrapper
│ ├── routes/ # Handlers REST
│ └── sysinfo/ # Coletores
└── web/
├── index.html, events.html, patterns.html,
│ processes.html, history.html
├── css/, js/
└── vendor/uplot/

📦 Empacotamento
Gerar .exe com ícone e metadados
bash

cargo build --release

O .exe em target/release/ já inclui:

    Ícone (via winresource + build.rs)

    Versão, autor, descrição

    Assinatura de build

Gerar instalador .msi

Requer WiX Toolset v3.
powershell

.\wix\build.ps1

Gera wix/target/PainelSistema-<versão>.msi com:

    Menu Iniciar e atalho na área de trabalho

    Registro no "Adicionar ou remover programas"

    Custom action para criar/iniciar serviço do Windows

🐛 Diagnóstico
Sintoma Solução
bind: address already in use Outra instância rodando, ou mude --port
Página em branco no Firefox Ctrl+Shift+R (limpa cache)
401 Unauthorized Defina auth.token no config.toml e faça login
Sem notificações Verifique permissões do navegador (cadeado na URL)
Histórico vazio Aguarde ~1 min ou verifique database.enabled
📄 Licença

MIT — veja LICENSE para detalhes.
🤝 Contribuindo

Pull requests são bem-vindos. Para mudanças grandes, abra uma issue antes
para discutirmos o que você pretende alterar.
🙏 Agradecimentos

    sysinfo — coleta cross-platform

    tiny_http — HTTP sem async

    rusqlite — SQLite bundled

    uPlot — gráficos rápidos e leves

text

---

## 🔨 Compilar e testar

```powershell
cd $HOME\projetos\painel-sistema

cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```
