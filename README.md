# 🦀 Painel do Sistema

Agente nativo em Rust que detecta processos suspeitos, correlaciona cadeias
pai→filho, aprende o baseline da máquina e serve um painel web em tempo
real — tudo em um único executável, sem dependências externas de runtime.
Em release Windows roda como app residente na bandeja do sistema.

![Rust](https://img.shields.io/badge/Rust-1.95%2B-orange?logo=rust)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Version](https://img.shields.io/badge/version-1.5.7-green)

---

## ⚠️ Escopo: EDR-lite em userspace

Isto **não** é um EDR comercial. Um EDR de verdade usa driver de kernel
(Windows), eBPF (Linux) ou EndpointSecurity framework (macOS) e bloqueia
execução em tempo real. Este agente roda em **userspace**, **por polling**
(2s), e faz **detecção + análise**, não prevenção.

O que isso significa na prática:

- ✅ Inventário de processos com cadeia pai→filho completa
- ✅ Hash SHA256 de executáveis + cache de integridade
- ✅ Heurísticas de comportamento suspeito + mapeamento MITRE ATT&CK
- ✅ Correlação de cadeias (Office → shell → download-cradle, etc.)
- ✅ Baseline por máquina — aprende o normal e atenua falsos positivos
- ✅ Persistência SQLite de findings, sockets e samples
- ❌ **Não** bloqueia execução antes do dano
- ❌ **Não** monitora arquivo/registry em tempo real
- ❌ **Não** varre memória de outros processos

É o mesmo território de Wazuh, Velociraptor e Sysmon+SOAR — útil para
visibilidade e triagem, não substituto de antivírus.

---

## ✨ Recursos

### Detecção de segurança

- **Heurísticas por processo** — `Typosquatting`, `MasqueradeLocation`,
  `SuspiciousParent`, `LolBin`, `TempDir`, `SuspiciousCmdline`,
  `ObfuscatedCommand`, `HiddenExecutable`, `UserWritableLocation`,
  `CpuSustainedHigh`
- **Correlação de cadeia** — `MultiShellSpawn`, `OfficeToC2`,
  `DownloadAndExecute`, `RapidChain`, `OrphanHighScore` (score alto com
  pai fora da árvore = possível injeção/parent spoofing)
- **Regras de rede** — `UnusualListeningPort`, `ExternalConnection`,
  `SuspiciousRemotePort` (RDP/SMB/MSSQL públicos)
- **Baseline adaptativo** — aprende o que é normal nesta máquina (24h por
  padrão) e aplica atenuação sobre findings contextuais de processos
  conhecidos como limpos. Findings fortes (typosquatting, cmdline suspeita,
  parent suspeito) **nunca** são atenuados
- **Mapeamento MITRE ATT&CK** — cada finding carrega técnica
  (`T1059.001` PowerShell, `T1036.005` Masquerading, `T1218` System Binary
  Proxy, `T1021` Remote Services, etc.)
- **Hash SHA256 + cache** — `IntegrityCache` invalida por `size`/`mtime`;
  hash calculado para processos com `final_score >= 20`
- **Coletor de sockets cross-platform** — `GetExtendedTcpTable` /
  `GetExtendedUdpTable` (Windows), `/proc/net/*` + `/proc/<pid>/fd` (Linux);
  macOS stub documentado

### Painel e infraestrutura

- **Coleta nativa** — CPU, memória, swap, disco, rede, processos e eventos
  do SO via `sysinfo`
- **Padrões clássicos** — CPU spike, memory leak, disco enchendo, swap
  ativo, pico de rede, churn de processos
- **Eventos do SO** — Windows Event Log (`Get-WinEvent`) / Linux
  (`journalctl`) / macOS (`log show`) com filtros por nível
- **SSE em tempo real** — dois eventos: `data:` (SystemSnapshot) e
  `event: security` (SecuritySnapshot) no mesmo stream
- **Persistência SQLite** — samples, patterns, baseline, sockets, findings.
  Duas janelas de retenção: operacional 7d / forense 90d
- **Autenticação** — sessão por cookie `HttpOnly` derivada do token
  (`sha256(salt||token)`); `/api/health` é público por design
- **Tray no Windows** — app residente, sem console; menu com status
  dinâmico, autostart e atalho pra abrir o painel
- **Auto-update** — consulta GitHub Releases, filtra artefatos por SO/arch
- **Um binário** — frontend embutido via `rust-embed`

---

## 📋 Requisitos

| Item                      | Versão mínima       |
| ------------------------- | ------------------- |
| Rust                      | 1.95 (edition 2024) |
| (Windows) C++ Build Tools | VS 2019+            |
| (Linux) build-essential   | —                   |

---

## 🚀 Como rodar

### Modo desenvolvimento (qualquer SO)

```powershell
cargo run -- --web .\web
```

Com `--web .\web`, o servidor lê HTML/CSS/JS do disco — edita e recarrega o
browser sem rebuild. Sem `--web`, os assets vêm embutidos no binário
(`rust-embed`) e exigem `cargo build` a cada mudança no frontend.

Em debug o console fica aberto e o banner aparece. **O tray não sobe em
debug** — use `--tray` se quiser testá-lo sem compilar release.

### Produção (Windows — tray)

```powershell
cargo build --release
.\target\release\painel-sistema.exe
```

Na primeira execução:

1. Servidor sobe em `localhost:8080` (sem console)
2. Browser abre automaticamente em `http://localhost:8080/`, já autenticado
   quando `auth.enabled = true`
3. Notificação do sistema avisa que o app está rodando em segundo plano
4. Ícone 🦀 aparece na bandeja

Nas execuções seguintes: só tray, silencioso. Use o menu do ícone pra
abrir o painel, ver status, ativar autostart ou encerrar.

### Produção (Linux / macOS)

```bash
./target/release/painel-sistema
```

Console fica aberto, banner aparece. Sem tray nessas plataformas — rode
como serviço systemd (Linux) ou launchd (macOS) se quiser residente.

### Menu do tray (Windows)

```
┌─────────────────────────────────┐
│ Abrir painel                    │
│ ─────────────────────────────── │
│ 201 processos · 2 alertas       │  ← dinâmico, mostra o SecuritySnapshot
│ ─────────────────────────────── │
│ ☑ Iniciar com o Windows         │  ← toggle via HKCU\...\Run
│ ─────────────────────────────── │
│ Abrir pasta de logs             │  ← %LOCALAPPDATA%\painel-sistema
│ Sair                            │
└─────────────────────────────────┘
```

### Flags da CLI

| Flag              | Descrição                                   |
| ----------------- | ------------------------------------------- |
| `--port <N>`      | Porta HTTP (default: `8080`)                |
| `--web <PATH>`    | Diretório com assets (default: embutidos)   |
| `--interval <N>`  | Intervalo SSE em segundos (default: `2`)    |
| `--bind-all`      | Escuta em `0.0.0.0` (LAN)                   |
| `--config <PATH>` | Caminho do `config.toml`                    |
| `--tray`          | Força modo tray (Windows)                   |
| `--no-tray`       | Força modo console mesmo em release Windows |
| `--no-open`       | Não abre o browser na primeira execução     |

Todas sobrepõem o `config.toml`.

### Instaladores

- **Windows** — `.exe` direto dos Releases
- **Linux** — `.deb` e `.rpm` via `nfpm` (`./packaging/build-linux.sh`)
- **macOS** — binário universal via CI

O CI compila e publica todos automaticamente ao empurrar uma tag `v*.*.*`.

---

## ⚙️ Configuração (`config.toml`)

```toml
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
sustained_percent = 60.0
sustained_readings = 30

[thresholds.memory]
critical_percent = 90.0
growth_percent_per_min = 0.3
growth_readings = 60

[thresholds.disk]
critical_percent = 90.0
filling_mb_per_5min = 500

[thresholds.swap]
active_percent = 20.0

[thresholds.network]
burst_multiplier = 10.0
min_baseline_bytes = 1024

[thresholds.processes]
churn_max_delta = 20
high_count = 300

[patterns]
history_capacity = 180
active_window_seconds = 60
max_age_seconds = 3600
max_patterns = 200

[events]
default_limit = 100
max_limit = 500

[database]
enabled = true
path = "painel.db"
retention_days = 7            # samples + network_listening + network_connections
findings_retention_days = 90  # security_findings + patterns

[updates]
enabled = true
github_token = ""
```

---

## 📡 API

| Método | Endpoint                 | Descrição                                                                   |
| ------ | ------------------------ | --------------------------------------------------------------------------- |
| GET    | `/api/health`            | **Público** — status, versão do binário, clientes SSE                       |
| GET    | `/api/snapshot`          | Snapshot completo do sistema (CPU, memória, disco, rede, processos)         |
| GET    | `/api/security/snapshot` | Último `SecuritySnapshot` produzido pelo motor                              |
| GET    | `/api/security/findings` | Histórico persistido (limit cap 1000, filtros `kind`, `severity`, `search`) |
| GET    | `/api/stream`            | SSE — `data:` SystemSnapshot + `event: security` SecuritySnapshot           |
| GET    | `/api/events?limit=N`    | Eventos do SO (Event Log / journalctl / log show)                           |
| GET    | `/api/patterns?limit=N`  | Padrões clássicos + histórico recente                                       |
| GET    | `/api/db-stats`          | Contagens do SQLite (samples, patterns, listening, connections, findings)   |
| GET    | `/api/update-check`      | Verifica nova versão no GitHub Releases                                     |
| GET    | `/api/auth-check`        | Valida o token                                                              |
| GET    | `/api/patterns/history`  | Padrões persistidos em SQLite (retention 90d)                               |

**Autenticação** — quando `auth.enabled = true`, todas as rotas `/api/*`
(exceto `/api/health`) exigem sessão via cookie `HttpOnly` ou
`Authorization: Bearer <token>`. Para SSE e abertura inicial pelo tray,
a URL aceita `?otk=<chave-efêmera>` que o backend troca por cookie sem
passar pelo histórico do browser.

---

## 🔒 Motor de detecção

### Heurísticas por processo

| Kind                   | Peso | O que detecta                                                                                                                                               |
| ---------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MasqueradeLocation`   | 45   | Nome crítico do sistema (`svchost`, `lsass`, `services`, `csrss`, `wininit`, `winlogon`, `smss`, `spoolsv`, `ngciso`) rodando fora de `System32`/`SysWOW64` |
| `Typosquatting`        | 40   | Nome a ≤2 edições de binário do sistema (`scvhost` → `svchost`). Suprimido em diretórios canônicos                                                          |
| `SuspiciousParent`     | 35   | Office, PDF reader, mídia, chat, servidor web spawnando shell                                                                                               |
| `LolBin`               | 35   | `certutil`, `bitsadmin`, `mshta`, `rundll32`, `regsvr32`, `wmic`, `installutil`, `msbuild` com args abusivos (T1218)                                        |
| `TempDir`              | 30   | Executável em `/tmp`, `/dev/shm`, `%TEMP%`, `/var/tmp`                                                                                                      |
| `SuspiciousCmdline`    | 30   | `-EncodedCommand`, `IEX`, download-cradle, `curl \| sh`, `certutil`, `nc -e`, `/dev/tcp`                                                                    |
| `ObfuscatedCommand`    | 25   | Combo ≥1 flag forte + ≥3 total em PowerShell (sem `-Enc`) ou base64-lookalike ≥100 chars                                                                    |
| `HiddenExecutable`     | 25   | Extensão dupla (`.pdf.exe`), espaço antes da extensão, RTL override                                                                                         |
| `SuspiciousRemotePort` | 25   | Conexão pública para 21, 23, 25, 445, 1433, 3306, 3389, 5432, 5985, 5986 (T1021)                                                                            |
| `UnusualListeningPort` | 20   | Porta alta escutando fora de well-known                                                                                                                     |
| `UserWritableLocation` | 15   | Exe em `Downloads`, `Desktop`, `Documents`, `OneDrive`                                                                                                      |
| `CpuSustainedHigh`     | 15   | CPU >80% por 5 leituras consecutivas                                                                                                                        |
| `ExternalConnection`   | 15   | Conexão estabelecida com IP público em porta incomum                                                                                                        |

Score final: soma truncada em 100. Níveis: **clean** (0-19), **attention**
(20-49), **suspicious** (50-79), **critical** (80+).

### Correlação de cadeia

| Regra                | Peso | O que detecta                                                               |
| -------------------- | ---- | --------------------------------------------------------------------------- |
| `OfficeToC2`         | 40   | Cadeia contém Office → shell                                                |
| `DownloadAndExecute` | 35   | Download-cradle com filho executado de `/tmp` ou `Downloads`                |
| `RapidChain`         | 30   | ≥4 níveis em ≤5s (com warm-up de 5s para não disparar no primeiro snapshot) |
| `OrphanHighScore`    | 30   | Score ≥50 cujo pai não está mais na árvore                                  |
| `MultiShellSpawn`    | 25   | Pai spawnou ≥3 shells em ≤10s                                               |

O score final de um processo é `max(baseline_score, chain.aggregate_score)

- network_bonus`. A cadeia e o network bonus usam o score **original** (não
  atenuado) — evita que um atacante "amoleça" o baseline com execuções
  benignas antes do ataque.

### Baseline

Durante o período de aprendizado (24h por padrão), todos os processos são
observados mas nenhum é atenuado. Depois disso, um processo é "conhecido
limpo" se foi visto ≥3 vezes **sem nunca** disparar um finding exempt.
Findings exempt (`Typosquatting`, `SuspiciousParent`, `SuspiciousCmdline`)
marcam a chave permanentemente.

O estado do baseline é **persistido em SQLite** (`baseline_meta` +
`baseline_entries`) e restaurado no próximo boot — o período de 24h de
aprendizado começa uma vez só, não a cada execução. Snapshot salvo a cada
30 ciclos (~60s).

### Integridade

Para processos com `final_score >= 20`, o SHA256 do executável é calculado
e armazenado junto ao finding na tabela `security_findings`. Arquivos
acima de 64 MiB são pulados. O `IntegrityCache` em memória invalida por
`size` + `mtime` e tem TTL de 1h.

---

## 🎨 Interface

| Página        | URL              | Descrição                                                         |
| ------------- | ---------------- | ----------------------------------------------------------------- |
| **Painel**    | `/`              | Cards do sistema (CPU, memória, disco, rede) + cards do navegador |
| **Segurança** | `/security.html` | **Hub** com 4 cards de escolha                                    |
| **Eventos**   | `/events.html`   | Log do SO com filtro por nível, busca e limite                    |
| **Padrões**   | `/patterns.html` | Anomalias clássicas + mini-gráfico de histórico                   |

### Hub de Segurança

A `security.html` é um **hub** com 4 cards, cada um levando a uma página
dedicada:

| Página        | URL                        | Descrição                                                             |
| ------------- | -------------------------- | --------------------------------------------------------------------- |
| **Processos** | `/security-processes.html` | KPIs por severidade, health strip, top processos e tabela de findings |
| **Portas**    | `/security-ports.html`     | Sockets em escuta (TCP/UDP) por processo, detecção de portas altas    |
| **Rede**      | `/security-network.html`   | Conexões ativas, IPs públicos, portas sensíveis                       |
| **Histórico** | `/security-findings.html`  | Findings persistidos em SQLite (90d), agregados por assinatura única  |

Todos os cards do hub mostram contadores ao vivo (SSE) — total e alertas.
A página de histórico é REST-only, com re-fetch automático a cada 60s.

O acesso ao restante do painel se faz pelo logo 🦀 no topo (volta pra home).

---

## 🗄️ Persistência (SQLite)

Duas janelas de retenção configuráveis:

- **Operacional (7d)** — `samples`, `network_listening`, `network_connections`
- **Forense (90d)** — `security_findings`, `patterns`
- **Permanente** — `baseline_meta`, `baseline_entries`

### Estratégia por tabela

- **`samples`** — append-only, alta frequência (~43k/dia). Serve pra
  tendência semanal.
- **`patterns`** — UPSERT por `id`, occurrences incrementam.
- **`baseline_meta` / `baseline_entries`** — estado (não histórico),
  reescritos a cada 30 ciclos.
- **`network_listening`** — UPSERT por `(pid, protocol, bind_addr, port)`,
  `first_seen_ms` + `last_seen_ms`.
- **`network_connections`** — UPSERT por
  `(pid, protocol, local_addr, local_port, remote_addr, remote_port)`,
  com `state` atualizado a cada ciclo.
- **`security_findings`** — UPSERT por `(kind, detail, exe_path)`. Cada
  "tipo de coisa que aparece nessa máquina" vira uma linha, agregando
  `occurrences`, `first_seen_ms`, `last_seen_ms`, `max_score_seen`,
  `max_severity`, `integrity_hash`. NÃO é log append-only — em polling de
  2s isso viraria milhões de linhas em horas.

Prune automático a cada 1h. Baseline e entradas do aprendizado nunca são
podados.

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│ Navegador                                               │
│   ├── /api/snapshot           (JSON, fetch)             │
│   ├── /api/security/snapshot  (JSON, fetch)             │
│   ├── /api/security/findings  (JSON, REST)              │
│   ├── /api/stream             (SSE — 2 eventos)         │
│   ├── /api/events             (logs do SO)              │
│   └── /api/patterns           (anomalias clássicas)     │
└──────────────────────────┬──────────────────────────────┘
                           │ HTTP (localhost:8080)
┌──────────────────────────▼──────────────────────────────┐
│ painel-sistema (Rust)                                   │
│   ├── tray (Windows)       ícone na bandeja + menu      │
│   ├── tiny_http            HTTP síncrono                │
│   ├── sysinfo              coleta nativa cross-platform │
│   │   └── sockets          TCP/UDP por SO               │
│   ├── security/            motor EDR-lite               │
│   │   ├── heuristics       findings por processo        │
│   │   ├── lineage          árvore + cadeias             │
│   │   ├── baseline         aprendizado + atenuação      │
│   │   ├── integrity        SHA256 + cache               │
│   │   ├── network          tipos + regras de socket     │
│   │   ├── mitre            mapeamento ATT&CK            │
│   │   └── engine           orquestrador do pipeline     │
│   ├── rusqlite             persistência (6 tabelas)     │
│   ├── crossbeam-channel    broadcast SSE                │
│   └── rust-embed           assets embutidos             │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 Desenvolvimento

### Testes

```powershell
cargo test
# ~120 testes: heuristics (30), lineage (12), baseline (10),
# integrity (9), network (13), engine (15), storage (10),
# routes (5), update (5), auth_sessions (6)
```

### Lint

```powershell
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

O projeto exige clippy limpo sob `-D warnings`. Todo commit é validado
localmente antes do push.

### Estrutura

```
painel-sistema/
├── Cargo.toml, Cargo.lock, rust-toolchain.toml
├── build.rs                    # Metadados do .exe no Windows
├── config.toml                 # Config externa
├── src/
│   ├── main.rs                 # Entry point + banner + dispatch pro tray
│   ├── cli.rs, config.rs, settings.rs
│   ├── auth.rs                 # Token Bearer (constant-time)
│   ├── auth_sessions.rs        # Cookie HttpOnly derivado do token
│   ├── auth_bootstrap.rs       # Chave efêmera do tray
│   ├── storage.rs              # SQLite (6 tabelas)
│   ├── update.rs               # GitHub Releases + semver
│   ├── broadcaster.rs          # SSE broadcast
│   ├── server.rs               # HTTP loop + router + publisher
│   ├── embedded.rs             # rust-embed wrapper
│   ├── tray.rs                 # Ícone na bandeja (Windows-only)
│   ├── routes/                 # Handlers REST
│   │   ├── snapshot.rs, security.rs, stream.rs
│   │   ├── events.rs, patterns.rs, update.rs
│   │   └── static_files.rs, auth.rs
│   ├── security/               # Motor de detecção
│   │   ├── types.rs, mitre.rs, heuristics.rs
│   │   ├── lineage.rs, baseline.rs
│   │   ├── integrity.rs, network.rs
│   │   └── engine.rs
│   └── sysinfo/
│       ├── types.rs, collector.rs
│       ├── sockets.rs          # Coletor TCP/UDP por SO
│       └── patterns.rs, events.rs
├── web/
│   ├── index.html
│   ├── security.html           # Hub (4 cards)
│   ├── security-processes.html
│   ├── security-ports.html
│   ├── security-network.html
│   ├── security-findings.html
│   ├── events.html, patterns.html
│   ├── css/
│   │   ├── base.css, layout.css, components.css, themes.css
│   │   ├── events.css, patterns.css, security.css, dashboard.css
│   └── js/
│       ├── main.js, security.js, events.js, patterns.js
│       ├── api/rest.js, api/sse.js
│       ├── actions/refresh.js
│       ├── ui/, utils/
├── packaging/
│   ├── nfpm.yaml, painel-sistema.service
│   ├── build-linux.sh, postinstall.sh
│   └── macos/build-app.sh
└── .github/workflows/release.yml
```

### Convenções

- **Rust edition 2024** — usa let chains, obrigatório
- **Commits** em Conventional Commits (`feat(scope):`, `fix(scope):`, `chore:`)
- **Versão** segue `<fase>.<backend>.<frontend>`
- **Nunca** versionar `target/`, `painel.db*`, `*.exe`, `*.msi`, `*.deb`, `*.rpm`
- Scripts `.sh` marcados com `git update-index --chmod=+x` (no Windows)

---

## 📦 CI / Release

`.github/workflows/release.yml` dispara em push de tag `v*.*.*`:

1. **build** — matriz paralela para 4 targets:
   - `x86_64-pc-windows-msvc`
   - `x86_64-unknown-linux-gnu`
   - `x86_64-apple-darwin`
   - `aarch64-apple-darwin`
2. **linux-packages** — gera `.deb` e `.rpm` via `nfpm`
3. **release** — publica tudo em GitHub Releases com `draft: false`

### Fluxo de release

```powershell
# 1. Bump em Cargo.toml e README.md
# 2. Commit
git add Cargo.toml Cargo.lock README.md
git commit -m "chore: release X.Y.Z"
git push

# 3. Tag e push
git tag -a vX.Y.Z -m "Release X.Y.Z"
git push origin vX.Y.Z
```

O frontend lê a versão de `/api/health` em runtime — nenhum HTML precisa
ser editado por release.

---

## 🐛 Diagnóstico

| Sintoma                                         | Solução                                                                  |
| ----------------------------------------------- | ------------------------------------------------------------------------ |
| `bind: address already in use`                  | Outra instância rodando — `--port 8090`, ou menu do tray → Sair          |
| Página em branco no Firefox                     | `Ctrl+Shift+R` (limpa cache)                                             |
| `401 Unauthorized` em tudo exceto `/api/health` | Sessão expirada — reabra pelo tray com `?otk=` ou faça login pelo prompt |
| Prompt de token mesmo abrindo pelo tray         | `?otk=` não chegou na URL — confira `auth.enabled` e `auth.token`        |
| Sem notificações                                | Firefox exige `http://localhost` (não IP da LAN) para Notifications API  |
| Versão não aparece no rodapé                    | `curl /api/health` deve retornar `version` — se não, rebuild             |
| Tray não aparece (Windows release)              | Ver `%LOCALAPPDATA%\painel-sistema\painel.log`                           |
| Tray sem ícone (quadrado laranja)               | Falta `web/assets/icons/favicon.ico` — converta do SVG                   |
| Histórico de findings vazio                     | Confira `[database] enabled = true` no `config.toml`                     |
| Build travado no Windows                        | Smart App Control pode bloquear (os error 4551). Desligue ou use WSL2    |
| Rust edition 2024 não compila                   | let chains exigem edition 2024 — confira `Cargo.toml`                    |

**Onde ficam os arquivos do usuário (Windows):**

- `%LOCALAPPDATA%\painel-sistema\painel.log` — log do app em modo tray
- `%LOCALAPPDATA%\painel-sistema\.first-run-done` — marker da primeira execução
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PainelSistema` — autostart
- `painel.db` (no cwd) — SQLite com samples, patterns, baseline, sockets, findings

---

## 🗺️ Roadmap

- ✅ **Fase 1** — Motor de detecção (heuristics, lineage, baseline, MITRE)
- ✅ **Fase 2** — Coleta forense (integrity, network, engine, collector)
- ✅ **Fase 3** — API + SSE (`/api/security/snapshot`, evento `security`)
- ✅ **Fase 4** — UI (security.html, nav, versão auto-carregada)
- ✅ **Fase 4.5** — Tray Windows + autostart + abertura autenticada
- ✅ **Fase 5** — Monitoramento de portas e rede (coletor + hub + páginas dedicadas)
- ✅ **Fase 6** — Persistência de findings no SQLite + hash SHA256 + página de histórico
- ⏳ **Fase 7** — Persistência de SO (Run keys Windows, systemd/cron Linux, launchd macOS)
- ⏳ **Fase 8** — Regras customizáveis em `config.toml` (`[security.rules.*]`)
- ⏳ **Fase 9** — Pesos de heurística configuráveis (`[security.weights.*]`)

Ideias futuras: `/metrics` Prometheus, webhook Discord/Slack/Telegram em
finding crítico, export CSV/PDF, modo kiosk, MQTT publisher, tray em
Linux (AppIndicator) e macOS (NSStatusItem).

---

## 📄 Licença

MIT — veja [LICENSE](LICENSE).

---

## 🙏 Agradecimentos

- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) — coleta cross-platform
- [tiny_http](https://github.com/tiny-http/tiny-http) — HTTP síncrono sem async
- [rusqlite](https://github.com/rusqlite/rusqlite) — SQLite bundled
- [rust-embed](https://github.com/pyros2097/rust-embed) — assets embutidos
- [tray-icon](https://github.com/tauri-apps/tray-icon) — ícone na bandeja
- [MITRE ATT&CK®](https://attack.mitre.org/) — framework de táticas e técnicas
