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

### Windows

**Opção 1 — Instalador `.msi`**

Baixe o `PainelSistema-<versão>.msi` na página de [Releases](https://github.com/luannp91/painel-sistema/releases)
e execute. O instalador:

- Adiciona ao menu Iniciar e cria atalho na área de trabalho
- Registra no "Adicionar ou remover programas"
- Opcionalmente instala como serviço do Windows

**Opção 2 — Executável direto**

Baixe `painel-sistema-x86_64-pc-windows-msvc.exe` dos Releases e execute.
Sem dependências — Rust com `crt-static` para rodar em qualquer Windows 10/11.

**Opção 3 — Compilar**

```powershell
git clone https://github.com/luannp91/painel-sistema
cd painel-sistema
cargo build --release
.\target\release\painel-sistema.exe
```

### Linux

**Opção 1 — `.deb` (Debian/Ubuntu)**

```bash
wget https://github.com/luannp91/painel-sistema/releases/latest/download/painel-sistema_0.2.0_amd64.deb
sudo dpkg -i painel-sistema_0.2.0_amd64.deb
sudo systemctl start painel-sistema
```

Acesse `http://localhost:8080`. Config em `/etc/painel-sistema/config.toml`.

**Opção 2 — `.rpm` (Fedora/RHEL/openSUSE)**

```bash
wget https://github.com/luannp91/painel-sistema/releases/latest/download/painel-sistema-0.2.0.x86_64.rpm
sudo rpm -i painel-sistema-0.2.0.x86_64.rpm
sudo systemctl start painel-sistema
```

**Opção 3 — Binário estático**

```bash
wget https://github.com/luannp91/painel-sistema/releases/latest/download/painel-sistema-x86_64-unknown-linux-gnu
chmod +x painel-sistema-x86_64-unknown-linux-gnu
./painel-sistema-x86_64-unknown-linux-gnu
```

**Opção 4 — Compilar**

```bash
git clone https://github.com/luannp91/painel-sistema
cd painel-sistema
cargo build --release
./target/release/painel-sistema
```

### macOS

**Opção 1 — DMG**

Baixe `PainelSistema-0.2.0.dmg` dos Releases, abra e arraste o app para `Applications`.

**Opção 2 — Binário direto**

```bash
# Intel
curl -L -o painel-sistema https://github.com/luannp91/painel-sistema/releases/latest/download/painel-sistema-x86_64-apple-darwin
chmod +x painel-sistema
./painel-sistema

# Apple Silicon (M1/M2/M3)
curl -L -o painel-sistema https://github.com/luannp91/painel-sistema/releases/latest/download/painel-sistema-aarch64-apple-darwin
chmod +x painel-sistema
./painel-sistema
```

**Opção 3 — Homebrew (via tap)**

```bash
brew tap luannp91/painel
brew install painel-sistema
brew services start painel-sistema
```

**Opção 4 — Compilar**

```bash
git clone https://github.com/luannp91/painel-sistema
cd painel-sistema
cargo build --release
./target/release/painel-sistema
```

### Docker (todas as plataformas)

```bash
docker run -d \
  --name painel-sistema \
  -p 8080:8080 \
  -v painel-data:/data \
  -v /etc/painel-sistema:/config \
  ghcr.io/luannp91/painel-sistema:latest
```

### Modo desenvolvimento (qualquer SO)

```bash
cargo run -- --web ./web
```

## 📦 Empacotamento

### Gerar todos os pacotes localmente

**Linux:**

```bash
./packaging/build-linux.sh
# Gera .deb e .rpm em packaging/dist/
```

**macOS:**

```bash
./packaging/macos/build-app.sh
# Gera PainelSistema.app e PainelSistema-0.2.0.dmg
```

**Windows:**

```powershell
.\wix\build.ps1
# Gera PainelSistema-0.2.0.msi
```

### Gerar via CI (recomendado)

1. Faça um commit com as mudanças
2. Crie uma tag: `git tag -a v0.2.0 -m "Release 0.2.0"`
3. Envie: `git push origin v0.2.0`
4. O GitHub Actions compila para **Windows + Linux + macOS (Intel + ARM)** e publica a Release automaticamente com todos os artefatos.

### Targets suportados

| Plataforma         | Target Rust                 | Artefato                |
| ------------------ | --------------------------- | ----------------------- |
| Windows x64        | `x86_64-pc-windows-msvc`    | `.exe`, `.msi`          |
| Linux x64 (glibc)  | `x86_64-unknown-linux-gnu`  | binário, `.deb`, `.rpm` |
| Linux x64 (static) | `x86_64-unknown-linux-musl` | binário estático        |
| macOS Intel        | `x86_64-apple-darwin`       | binário, `.dmg`         |
| macOS ARM          | `aarch64-apple-darwin`      | binário, `.dmg`         |

### Compilar para musl (Linux estático)

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

Binário resultante roda em qualquer distro Linux sem dependências.

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
