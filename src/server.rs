use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::broadcaster::Broadcaster;
use crate::config::Config;
use crate::routes;
use crate::sysinfo::Collector;
use crate::sysinfo::patterns::PatternDetector;

pub fn run(config: Config) -> Result<()> {
    let addr = config.bind_addr();
    let server =
        Server::http(&addr).map_err(|e| anyhow::anyhow!("Falha ao bindar {}: {}", addr, e))?;

    log::info!("Servidor ouvindo em http://{}", addr);
    match &config.web_root {
        Some(p) => log::info!("Servindo arquivos de: {}", p.display()),
        None => log::info!("Servindo assets embutidos no executável"),
    }

    let collector = Arc::new(Mutex::new(Collector::new()));
    let broadcaster = Arc::new(Broadcaster::new());
    let detector = Arc::new(Mutex::new(PatternDetector::new()));

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
        let web_root = config.web_root.clone();

        thread::spawn(move || {
            if let Err(e) = route(request, collector, broadcaster, detector, web_root) {
                log::error!("Erro ao processar requisição: {:#}", e);
            }
        });
    }

    Ok(())
}

fn route(
    request: Request,
    collector: Arc<Mutex<Collector>>,
    broadcaster: Arc<Broadcaster>,
    detector: Arc<Mutex<PatternDetector>>,
    web_root: Option<std::path::PathBuf>,
) -> Result<()> {
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("/");

    if request.method() == &Method::Options {
        let response = Response::empty(StatusCode(204))
            .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap())
            .with_header(
                Header::from_bytes("Access-Control-Allow-Methods", "GET, OPTIONS").unwrap(),
            )
            .with_header(Header::from_bytes("Access-Control-Allow-Headers", "*").unwrap());
        request.respond(response)?;
        return Ok(());
    }

    match path {
        "/api/snapshot" => routes::snapshot::handle(request, collector),
        "/api/stream" => routes::stream::handle(request, broadcaster),
        "/api/events" => routes::events::handle(request),
        "/api/patterns" => routes::patterns::handle(request, detector),
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

            // Coleta o snapshot
            let snap = {
                let mut c = collector.lock().unwrap();
                c.collect()
            };

            // Alimenta o detector de padrões
            {
                let mut pd = detector.lock().unwrap();
                let detected = pd.push(&snap);
                if !detected.is_empty() {
                    log::debug!("{} padrões detectados", detected.len());
                }
            }

            // Publica via SSE
            match serde_json::to_string(&snap) {
                Ok(json) => broadcaster.publish(format!("data: {}\n\n", json).into_bytes()),
                Err(e) => log::warn!("Falha ao serializar snapshot: {}", e),
            }

            if start.elapsed().as_secs() % 60 == 0 && start.elapsed().as_secs() > 0 {
                log::debug!(
                    "Uptime: {}s | Clientes SSE: {}",
                    start.elapsed().as_secs(),
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
