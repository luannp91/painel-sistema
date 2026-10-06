//! Ícone na bandeja do sistema + menu de contexto (Windows).
//!
//! Roda como app residente após a primeira execução. O servidor HTTP
//! continua no ar em `localhost:<porta>`; a UI é o browser, aberto sob
//! demanda pelo item "Abrir painel".
//!
//! **Nota de threading:** `MenuItem` e `TrayIcon` **não** são `Send`
//! (a `muda` usa `Rc` internamente). Por isso todo acesso a eles
//! acontece no main thread, dentro do `about_to_wait` do winit — sem
//! `std::thread::spawn` tocando nesses tipos.

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

use crate::embedded::WebAssets;
use crate::routes::security::SecurityCache;

const MENU_OPEN: &str = "tray.open";
const MENU_AUTOSTART: &str = "tray.autostart";
const MENU_LOGS: &str = "tray.logs";
const MENU_QUIT: &str = "tray.quit";

const AUTOSTART_REG_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const AUTOSTART_REG_VALUE: &str = "PainelSistema";

/// Intervalo do refresh do texto de status.
const STATUS_REFRESH: Duration = Duration::from_secs(2);

/// Frequência de polling do canal de eventos do menu (a `muda` não
/// integra com o event loop do winit, então drenamos manualmente).
const MENU_POLL: Duration = Duration::from_millis(150);

pub struct TrayConfig {
    pub port: u16,
    pub state_dir: PathBuf,
    pub exe_path: PathBuf,
}

/// Sobe o tray e entra no message loop (bloqueia a thread principal).
pub fn run(cfg: TrayConfig, cache: SecurityCache) -> Result<()> {
    // --- Menu ---------------------------------------------------------------
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

    // --- Ícone --------------------------------------------------------------
    let icon = load_icon();
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Painel do Sistema")
        .with_icon(icon)
        .build()
        .context("falha ao criar ícone da bandeja")?;

    // --- Message loop (bloqueia) -------------------------------------------
    let event_loop = EventLoop::new().context("falha ao criar event loop")?;
    event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + MENU_POLL));

    let mut app = TrayHost {
        _tray: tray,
        status_item,
        cache,
        port: cfg.port,
        state_dir: cfg.state_dir,
        exe_path: cfg.exe_path,
        next_status_tick: Instant::now() + STATUS_REFRESH,
    };

    event_loop
        .run_app(&mut app)
        .context("event loop encerrou com erro")?;
    Ok(())
}

/// Toast nativo (Windows 10+). Silencia falhas — não vale interromper
/// o fluxo se a notificação não puder ser exibida.
pub fn notify(title: &str, body: &str) {
    if let Err(e) = notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .show()
    {
        log::warn!("falha ao exibir notificação: {e}");
    }
}

/// Abre `http://localhost:<port>/` no browser padrão.
pub fn open_browser(port: u16) -> Result<()> {
    let url = format!("http://localhost:{port}/");
    std::process::Command::new("cmd")
        .args(["/C", "start", "", &url])
        .spawn()
        .context("falha ao abrir o browser")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Host (main thread)
// ---------------------------------------------------------------------------

struct TrayHost {
    /// Mantido vivo — se o `TrayIcon` for dropado, o ícone some.
    _tray: TrayIcon,
    /// Texto de status atualizado a cada [`STATUS_REFRESH`].
    status_item: MenuItem,
    cache: SecurityCache,
    port: u16,
    state_dir: PathBuf,
    exe_path: PathBuf,
    next_status_tick: Instant,
}

impl TrayHost {
    fn handle_menu(&self, id: &str) {
        match id {
            MENU_OPEN => {
                if let Err(e) = open_browser(self.port) {
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
        let Ok(g) = self.cache.lock() else { return };
        let Some(snap) = g.as_ref() else { return };
        let alerts = snap.counts.attention + snap.counts.suspicious + snap.counts.critical;
        let learn = if snap.learning { " · aprendendo" } else { "" };
        self.status_item.set_text(format!(
            "{} processos · {} alertas{}",
            snap.processes.len(),
            alerts,
            learn
        ));
    }
}

impl ApplicationHandler for TrayHost {
    fn resumed(&mut self, _: &ActiveEventLoop) {}

    fn window_event(&mut self, _: &ActiveEventLoop, _: WindowId, _: WindowEvent) {}

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // 1. Menu: drena o canal (não bloqueante)
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            self.handle_menu(ev.id.0.as_str());
        }

        // 2. Status: atualiza a cada STATUS_REFRESH
        let now = Instant::now();
        if now >= self.next_status_tick {
            self.update_status();
            self.next_status_tick = now + STATUS_REFRESH;
        }

        // 3. Acorda no próximo evento relevante (status ou poll do menu)
        let next = self.next_status_tick.min(now + MENU_POLL);
        event_loop.set_control_flow(ControlFlow::WaitUntil(next));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Carrega o ícone embutido (`assets/icons/favicon.ico`). Se não existir
/// ou não puder ser decodificado, cai num quadrado laranja 32×32.
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
    // Fallback: quadrado laranja sólido
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
