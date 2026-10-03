use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::auth;
use crate::broadcaster::Broadcaster;
use crate::config::Config;
use crate::routes;
use crate::settings::EventSettings;
use crate::sysinfo::patterns::PatternDetector;
use crate::sysinfo::{Collector, ProcessCollector};

pub fn run(config: Config) -> Result<()> {
    let addr = config.bind_addr();
    let server =
        Server::http(&addr).map_err(|e| anyhow::anyhow!("Falha ao bindar {}: {}", addr, e))?;

    log::info!("Servidor ouvindo em http://{}", addr);
    if config.auth_enabled {
        log::warn!("Autenticação por token ATIVADA");
    }
    match &config.web_root {
        Some(p) => log::info!("Servindo arquivos de: {}", p.display()),
        None => log::info!("Servindo assets embutidos"),
    }

    let collector = Arc::new(Mutex::new(Collector::new()));
    let broadcaster = Arc::new(Broadcaster::new());
    let detector = Arc::new(Mutex::new(PatternDetector::new_with_settings(
        &config.settings.patterns,
        &config.settings.thresholds,
    )));
    let process_collector = Arc::new(Mutex::new(ProcessCollector::new()));

    spawn_publisher(
        collector.clone(),
        broadcaster.clone(),
        detector.clone(),
        config.interval,
    );

    for request in server.incoming_requests() {
        let collector = collector.clone();
        let broadcaster = broadcaster.clone();
        let detector = detector.clone();
        let process_collector = process_collector.clone();
        let web_root = config.web_root.clone();
        let auth_enabled = config.auth_enabled;
        let auth_token = config.auth_token.clone();
        let event_settings = config.settings.events.clone();

        thread::spawn(move || {
            if let Err(e) = route(
                request,
                collector,
                broadcaster,
                detector,
                process_collector,
                web_root,
                auth_enabled,
                &auth_token,
                &event_settings,
            ) {
                log::error!("Erro ao processar requisição: {:#}", e);
            }
        });
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn route(
    request: Request,
    collector: Arc<Mutex<Collector>>,
    broadcaster: Arc<Broadcaster>,
    detector: Arc<Mutex<PatternDetector>>,
    process_collector: Arc<Mutex<ProcessCollector>>,
    web_root: Option<std::path::PathBuf>,
    auth_enabled: bool,
    auth_token: &str,
    event_settings: &EventSettings,
) -> Result<()> {
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("/");

    if request.method() == &Method::Options {
        let response = Response::empty(StatusCode(204))
            .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap())
            .with_header(
                Header::from_bytes("Access-Control-Allow-Methods", "GET, POST, OPTIONS").unwrap(),
            )
            .with_header(Header::from_bytes("Access-Control-Allow-Headers", "*").unwrap());
        request.respond(response)?;
        return Ok(());
    }

    if path.starts_with("/api/") && !auth::is_authorized(&request, auth_enabled, auth_token) {
        request.respond(auth::unauthorized_response())?;
        return Ok(());
    }

    // Rota dinâmica de kill: /api/processes/{pid}/kill
    if let Some(pid) = routes::processes::parse_kill_path(path) {
        return routes::processes::kill(request, process_collector, pid);
    }

    match path {
        "/api/snapshot" => routes::snapshot::handle(request, collector),
        "/api/stream" => routes::stream::handle(request, broadcaster),
        "/api/events" => routes::events::handle(request, event_settings),
        "/api/patterns" => routes::patterns::handle(request, detector),
        "/api/processes" => routes::processes::list(request, process_collector),
        "/api/auth-check" => {
            let body = r#"{"status":"ok","authenticated":true}"#;
            let header = Header::from_bytes("Content-Type", "application/json").unwrap();
            let response = Response::from_string(body).with_header(header);
            request.respond(response)?;
            Ok(())
        }
        "/api/health" => {
            let body = format!(
                "{{\"status\":\"ok\",\"clients\":{}}}",
                broadcaster.client_count()
            );
            let header =
                Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
            let response = Response::from_string(body).with_header(header);
            request.respond(response)?;
            Ok(())
        }
        _ => routes::static_files::handle(request, web_root.as_deref()),
    }
}

fn spawn_publisher(
    collector: Arc<Mutex<Collector>>,
    broadcaster: Arc<Broadcaster>,
    detector: Arc<Mutex<PatternDetector>>,
    interval: Duration,
) {
    thread::spawn(move || {
        let start = Instant::now();
        loop {
            let t0 = Instant::now();

            let snap = {
                let mut c = collector.lock().unwrap();
                c.collect()
            };

            {
                let mut pd = detector.lock().unwrap();
                let detected = pd.push(&snap);
                if !detected.is_empty() {
                    log::debug!("{} padrões detectados", detected.len());
                }
            }

            match serde_json::to_string(&snap) {
                Ok(json) => broadcaster.publish(format!("data: {}\n\n", json).into_bytes()),
                Err(e) => log::warn!("Falha ao serializar snapshot: {}", e),
            }

            let secs = start.elapsed().as_secs();
            if secs > 0 && secs.is_multiple_of(60) {
                log::debug!(
                    "Uptime: {}s | Clientes SSE: {}",
                    secs,
                    broadcaster.client_count()
                );
            }

            let elapsed = t0.elapsed();
            if elapsed < interval {
                thread::sleep(interval - elapsed);
            }
        }
    });
}
