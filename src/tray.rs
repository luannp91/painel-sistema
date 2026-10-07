//! Ícone na bandeja do sistema + menu de contexto (Windows).
//!
//! Roda como app residente após a primeira execução. O servidor HTTP
//! continua no ar em `localhost:<porta>`; a UI é o browser, aberto sob
//! demanda pelo item "Abrir painel".
//!
//! **Notas importantes:**
//! - `MenuItem`/`TrayIcon` não são `Send` — todo acesso no main thread.
//! - `TrayIcon` precisa ser criado **depois** que o event loop do winit
//!   está rodando — por isso `resumed()`/`about_to_wait()`.
//! - **Autostart:** se o app sobe pelo `HKCU\...\Run`, a taskbar do
//!   Windows ainda não está pronta. `Shell_NotifyIcon` retorna sucesso
//!   mas o ícone nunca aparece. `wait_for_taskbar()` antes de construir.
//! - **Abrir browser:** usar `ShellExecuteW` direto evita que o
//!   `cmd /C start` spawn via Windows Terminal (janela piscando) e
//!   ative o CLSID `ShellWindows` via COM (Event ID 10016).

#![cfg(windows)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::WindowId;

use crate::auth_bootstrap::BootstrapKey;
use crate::embedded::WebAssets;
use crate::routes::security::SecurityCache;

const MENU_OPEN: &str = "tray.open";
const MENU_AUTOSTART: &str = "tray.autostart";
const MENU_LOGS: &str = "tray.logs";
const MENU_QUIT: &str = "tray.quit";

const AUTOSTART_REG_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const AUTOSTART_REG_VALUE: &str = "PainelSistema";

/// AppID usado no toast. Usa o do PowerShell — já registrado pelo
/// sistema, com permissão de ativação COM. Sem isso, o Windows pode
/// disparar Event ID 10016 a cada toast.
///
/// Trade-off: o toast aparece com rótulo "Windows PowerShell".
const TOAST_APP_ID: &str = "Microsoft.Windows.PowerShell";

/// Intervalo do refresh do texto de status.
const STATUS_REFRESH: Duration = Duration::from_secs(2);

/// Frequência de polling do canal de eventos do menu.
const MENU_POLL: Duration = Duration::from_millis(150);

/// Timeout máximo esperando a taskbar subir (no autostart).
const TASKBAR_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Intervalo entre tentativas de encontrar a taskbar.
const TASKBAR_POLL: Duration = Duration::from_millis(500);

pub struct TrayConfig {
    pub port: u16,
    pub state_dir: PathBuf,
    pub exe_path: PathBuf,
    pub bootstrap: BootstrapKey,
}

/// Sobe o tray e entra no message loop (bloqueia a thread principal).
pub fn run(cfg: TrayConfig, cache: SecurityCache) -> Result<()> {
    let event_loop = EventLoop::new().context("falha ao criar event loop")?;
    event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + MENU_POLL));

    let mut app = TrayHost {
        state: None,
        cache,
        port: cfg.port,
        state_dir: cfg.state_dir,
        exe_path: cfg.exe_path,
        bootstrap: cfg.bootstrap,
        next_status_tick: Instant::now() + STATUS_REFRESH,
    };

    event_loop
        .run_app(&mut app)
        .context("event loop encerrou com erro")?;
    Ok(())
}

/// Toast nativo no Windows. Silencia falhas.
pub fn notify(title: &str, body: &str) {
    let result = win_toast_notify::WinToastNotify::new()
        .set_app_id(TOAST_APP_ID)
        .set_title(title)
        .set_messages(vec![body])
        .show();
    if let Err(e) = result {
        log::warn!("falha ao exibir notificação: {e}");
    }
}

/// Abre `http://localhost:<port>/` no browser padrão via `ShellExecuteW`.
///
/// Se `otk` for `Some`, anexa `?otk=...` — o frontend troca a chave
/// pelo token real via `POST /api/auth/exchange`.
///
/// **Por que não `cmd /C start`:** no Windows 11, o `cmd.exe` spawn via
/// Windows Terminal (janela pisca) e internamente ativa o CLSID
/// `ShellWindows` via COM — se o CLSID não tem permissão explícita pro
/// usuário, o Windows loga Event ID 10016 (DCOM permission denial).
pub fn open_browser(port: u16, otk: Option<&str>) -> Result<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let url = match otk {
        Some(k) if !k.is_empty() => format!("http://localhost:{port}/?otk={k}"),
        _ => format!("http://localhost:{port}/"),
    };

    // String UTF-16 nul-terminated pro ShellExecuteW
    let url_wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = "open\0".encode_utf16().collect();

    // SAFETY: os dois Vec<u16> são nul-terminated e vivem até o fim da
    // chamada. hwnd/params/dir são null, comportamento esperado pra URL.
    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(), // hwnd
            verb.as_ptr(),        // "open"
            url_wide.as_ptr(),    // file / URL
            std::ptr::null(),     // params
            std::ptr::null(),     // dir
            SW_SHOWNORMAL,        // nShowCmd
        )
    };

    // ShellExecuteW retorna um HINSTANCE; valor <= 32 é erro.
    if (ret as isize) <= 32 {
        anyhow::bail!("ShellExecuteW falhou (código {})", ret as isize);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Espera pela taskbar (autostart)
// ---------------------------------------------------------------------------

/// Bloqueia até a taskbar (`Shell_TrayWnd`) existir ou o timeout estourar.
///
/// No autostart via `HKCU\...\Run`, o app sobe junto com o login — antes
/// da taskbar estar pronta. `Shell_NotifyIcon` (chamada internamente
/// pelo `tray-icon`) retorna sucesso mesmo assim, mas o ícone nunca
/// aparece. Esperar a classe existir resolve.
fn wait_for_taskbar(timeout: Duration) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW;

    let class_name: Vec<u16> = "Shell_TrayWnd\0".encode_utf16().collect();
    let start = Instant::now();

    loop {
        // SAFETY: class_name é nul-terminated; null no segundo parâmetro
        // significa "qualquer janela da classe".
        let hwnd = unsafe { FindWindowW(class_name.as_ptr(), std::ptr::null()) };
        if !hwnd.is_null() {
            log::info!("taskbar detectada em {:?}", start.elapsed());
            return true;
        }
        if start.elapsed() >= timeout {
            log::warn!("taskbar nao apareceu em {:?}", timeout);
            return false;
        }
        std::thread::sleep(TASKBAR_POLL);
    }
}

// ---------------------------------------------------------------------------
// Host (main thread)
// ---------------------------------------------------------------------------

struct TrayState {
    _tray: TrayIcon,
    status_item: MenuItem,
}

struct TrayHost {
    state: Option<TrayState>,
    cache: SecurityCache,
    port: u16,
    state_dir: PathBuf,
    exe_path: PathBuf,
    bootstrap: BootstrapKey,
    next_status_tick: Instant,
}

impl TrayHost {
    fn build_tray(&mut self) -> Result<()> {
        if self.state.is_some() {
            return Ok(());
        }

        // Autostart: taskbar pode não estar pronta ainda.
        wait_for_taskbar(TASKBAR_WAIT_TIMEOUT);

        let menu = Menu::new();
        let open_item = MenuItem::with_id(MENU_OPEN, "Abrir painel", true, None);
        let status_item = MenuItem::with_id("tray.status", "Iniciando…", false, None);
        let autostart_item = CheckMenuItem::with_id(
            MENU_AUTOSTART,
            "Iniciar com o Windows",
            true,
            is_autostart_enabled(),
            None,
        );
        let logs_item = MenuItem::with_id(MENU_LOGS, "Abrir pasta de logs", true, None);
        let quit_item = MenuItem::with_id(MENU_QUIT, "Sair", true, None);

        menu.append_items(&[
            &open_item,
            &PredefinedMenuItem::separator(),
            &status_item,
            &PredefinedMenuItem::separator(),
            &autostart_item,
            &PredefinedMenuItem::separator(),
            &logs_item,
            &quit_item,
        ])
        .context("falha ao montar menu")?;

        let icon = load_icon();
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Painel do Sistema")
            .with_icon(icon)
            .build()
            .context("falha ao criar ícone da bandeja")?;

        self.state = Some(TrayState {
            _tray: tray,
            status_item,
        });
        log::info!("tray construido");
        Ok(())
    }

    fn handle_menu(&self, id: &str) {
        match id {
            MENU_OPEN => {
                let key = self.bootstrap.current();
                if let Err(e) = open_browser(self.port, Some(&key)) {
                    log::warn!("falha ao abrir browser: {e:#}");
                }
            }
            MENU_AUTOSTART => {
                let enabled = is_autostart_enabled();
                if let Err(e) = set_autostart(!enabled, &self.exe_path) {
                    log::warn!("falha ao alternar autostart: {e:#}");
                }
            }
            MENU_LOGS => {
                if let Err(e) = open_path(&self.state_dir) {
                    log::warn!("falha ao abrir pasta de logs: {e:#}");
                }
            }
            MENU_QUIT => {
                log::info!("Encerrando por menu");
                std::process::exit(0);
            }
            _ => {}
        }
    }

    fn update_status(&self) {
        let Some(state) = self.state.as_ref() else {
            return;
        };
        let Ok(g) = self.cache.lock() else { return };
        let Some(snap) = g.as_ref() else { return };
        let alerts = snap.counts.attention + snap.counts.suspicious + snap.counts.critical;
        let learn = if snap.learning { " · aprendendo" } else { "" };
        state.status_item.set_text(format!(
            "{} processos · {} alertas{}",
            snap.processes.len(),
            alerts,
            learn
        ));
    }
}

impl ApplicationHandler for TrayHost {
    fn resumed(&mut self, _: &ActiveEventLoop) {
        if let Err(e) = self.build_tray() {
            log::error!("falha ao construir tray: {e:#}");
        }
    }

    fn window_event(&mut self, _: &ActiveEventLoop, _: WindowId, _: WindowEvent) {}

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // Segurança: se `resumed()` não foi chamado, tenta construir aqui.
        if self.state.is_none()
            && let Err(e) = self.build_tray()
        {
            log::error!("falha ao construir tray (about_to_wait): {e:#}");
        }

        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            self.handle_menu(ev.id.0.as_str());
        }

        let now = Instant::now();
        if now >= self.next_status_tick {
            self.update_status();
            self.next_status_tick = now + STATUS_REFRESH;
        }

        let next = self.next_status_tick.min(now + MENU_POLL);
        event_loop.set_control_flow(ControlFlow::WaitUntil(next));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_icon() -> tray_icon::Icon {
    if let Some(file) = WebAssets::get("assets/icons/favicon.ico")
        && let Ok(img) = image::load_from_memory_with_format(&file.data, image::ImageFormat::Ico)
    {
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        if let Ok(icon) = tray_icon::Icon::from_rgba(rgba.into_raw(), w, h) {
            return icon;
        }
    }
    let mut buf = vec![0u8; 32 * 32 * 4];
    for px in buf.as_chunks_mut::<4>().0 {
        px.copy_from_slice(&[0xFF, 0x6B, 0x35, 0xFF]);
    }
    tray_icon::Icon::from_rgba(buf, 32, 32).expect("fallback válido")
}

fn open_path(path: &std::path::Path) -> Result<()> {
    std::process::Command::new("explorer")
        .arg(path)
        .spawn()
        .context("falha ao abrir explorer")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Registro (autostart)
// ---------------------------------------------------------------------------

fn is_autostart_enabled() -> bool {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey(AUTOSTART_REG_KEY)
        .ok()
        .and_then(|k| k.get_value::<String, _>(AUTOSTART_REG_VALUE).ok())
        .is_some()
}

fn set_autostart(enabled: bool, exe_path: &std::path::Path) -> Result<()> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(AUTOSTART_REG_KEY)?;
    if enabled {
        let cmd = format!("\"{}\" --no-open", exe_path.display());
        key.set_value(AUTOSTART_REG_VALUE, &cmd)?;
        log::info!("autostart habilitado: {cmd}");
    } else {
        let _ = key.delete_value(AUTOSTART_REG_VALUE);
        log::info!("autostart desabilitado");
    }
    Ok(())
}
