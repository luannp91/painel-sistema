use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::auth;
use crate::broadcaster::Broadcaster;
use crate::config::Config;
use crate::routes;
use crate::routes::security::SecurityCache;
use crate::settings::EventSettings;
use crate::storage::Storage;
use crate::sysinfo::Collector;
use crate::sysinfo::events::EventCollector;
use crate::sysinfo::patterns::PatternDetector;

pub fn run(config: Config, security_cache: SecurityCache) -> Result<()> {
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

    // Abre o banco de dados (se habilitado)
    let storage: Option<Arc<Storage>> = match config.db_path() {
        Some(path) => match Storage::open(&path) {
            Ok(s) => {
                let s = Arc::new(s);
                let (ns, np) = s.stats().unwrap_or((0, 0));
                log::info!("Histórico: {} amostras, {} padrões persistidos", ns, np);
                Some(s)
            }
            Err(e) => {
                log::error!("Falha ao abrir DB ({}). Continuando sem persistência.", e);
                None
            }
        },
        None => {
            log::info!("Persistência desabilitada no config.toml");
            None
        }
    };

    let collector = Arc::new(Mutex::new(Collector::new()));
    let broadcaster = Arc::new(Broadcaster::new());
    let detector = Arc::new(Mutex::new(PatternDetector::new_with_settings(
        &config.settings.patterns,
        &config.settings.thresholds,
    )));
    let event_collector = Arc::new(Mutex::new(EventCollector::with_default_ttl()));

    // Thread de publicação (SSE + persistência + motor de segurança)
    spawn_publisher(
        collector.clone(),
        broadcaster.clone(),
        detector.clone(),
        storage.clone(),
        config.interval,
        security_cache.clone(),
    );

    // Thread de manutenção do DB (prune + checkpoint a cada hora)
    if let (Some(s), true) = (storage.clone(), config.settings.database.enabled) {
        let retention_days = config.settings.database.retention_days.max(1);
        spawn_db_maintenance(s, retention_days);
    }

    for request in server.incoming_requests() {
        let collector = collector.clone();
        let broadcaster = broadcaster.clone();
        let detector = detector.clone();
        let storage = storage.clone();
        let web_root = config.web_root.clone();
        let auth_enabled = config.auth_enabled;
        let auth_token = config.auth_token.clone();
        let event_settings = config.settings.events.clone();
        let update_settings = config.settings.updates.clone();
        let security_cache = security_cache.clone();
        let event_collector = event_collector.clone();

        thread::spawn(move || {
            if let Err(e) = route(
                request,
                collector,
                broadcaster,
                detector,
                storage,
                web_root,
                auth_enabled,
                &auth_token,
                &event_settings,
                &update_settings,
                security_cache,
                event_collector,
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
    storage: Option<Arc<Storage>>,
    web_root: Option<std::path::PathBuf>,
    auth_enabled: bool,
    auth_token: &str,
    event_settings: &EventSettings,
    update_settings: &crate::settings::UpdateSettings,
    security_cache: SecurityCache,
    event_collector: Arc<Mutex<EventCollector>>,
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

    // Health check é público — usado por monitoramento e pela UI pra
    // descobrir a versão do binário. Não expõe nada sensível.
    if path == "/api/health" {
        let body = format!(
            "{{\"status\":\"ok\",\"version\":\"{}\",\"clients\":{}}}",
            env!("CARGO_PKG_VERSION"),
            broadcaster.client_count()
        );
        let header = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
        let response = Response::from_string(body).with_header(header);
        request.respond(response)?;
        return Ok(());
    }

    if path.starts_with("/api/") && !auth::is_authorized(&request, auth_enabled, auth_token) {
        request.respond(auth::unauthorized_response())?;
        return Ok(());
    }

    match path {
        "/api/update-check" => routes::update::handle(request, update_settings),
        "/api/snapshot" => routes::snapshot::handle(request, collector),
        "/api/security/snapshot" => routes::security::handle(request, security_cache),
        "/api/stream" => routes::stream::handle(request, broadcaster),
        "/api/events" => routes::events::handle(request, event_settings, event_collector),
        "/api/patterns" => routes::patterns::handle(request, detector),
        "/api/db-stats" => match storage {
            Some(s) => {
                let (ns, np) = s.stats().unwrap_or((0, 0));
                let body = format!("{{\"samples\":{},\"patterns\":{}}}", ns, np);
                let header = Header::from_bytes("Content-Type", "application/json").unwrap();
                let response = Response::from_string(body).with_header(header);
                request.respond(response)?;
                Ok(())
            }
            None => {
                let header = Header::from_bytes("Content-Type", "application/json").unwrap();
                let response =
                    Response::from_string(r#"{"samples":0,"patterns":0}"#).with_header(header);
                request.respond(response)?;
                Ok(())
            }
        },
        "/api/auth-check" => {
            let body = r#"{"status":"ok","authenticated":true}"#;
            let header = Header::from_bytes("Content-Type", "application/json").unwrap();
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
    storage: Option<Arc<Storage>>,
    interval: Duration,
    security_cache: SecurityCache,
) {
    thread::spawn(move || {
        let start = Instant::now();
        loop {
            let t0 = Instant::now();

            // Um lock, um refresh: `collect()` atualiza o sysinfo;
            // `collect_security()` consome o estado fresco e avança
            // baseline/lineage. Chamar em sequência evita refresh duplo.
            let (snap, security) = {
                let mut c = collector.lock().unwrap();
                let snap = c.collect();
                let security = c.collect_security();
                (snap, security)
            };

            // Publica o snapshot de segurança no SSE como evento nomeado
            // antes de mover pro cache (evita clonar).
            match serde_json::to_string(&security) {
                Ok(json) => {
                    broadcaster.publish(format!("event: security\ndata: {}\n\n", json).into_bytes())
                }
                Err(e) => log::warn!("Falha ao serializar security snapshot: {}", e),
            }

            *security_cache.lock().unwrap() = Some(Arc::new(security));

            let detected = {
                let mut pd = detector.lock().unwrap();
                let (patterns, sample) = pd.push(&snap);

                if let Some(ref s) = storage {
                    if let Err(e) = s.insert_sample(&sample) {
                        log::warn!("Falha ao inserir sample: {}", e);
                    }
                    for p in &patterns {
                        if let Err(e) = s.upsert_pattern(p) {
                            log::warn!("Falha ao persistir padrão: {}", e);
                        }
                    }
                }

                if !patterns.is_empty() {
                    log::debug!("{} padrões detectados", patterns.len());
                }
                patterns
            };
            let _ = detected;

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

fn spawn_db_maintenance(storage: Arc<Storage>, retention_days: u64) {
    thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(3600)); // 1h
            let cutoff = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
                .saturating_sub(retention_days * 24 * 3600 * 1000);

            match storage.prune_older_than(cutoff) {
                Ok(n) if n > 0 => log::info!("DB: {} amostras antigas removidas", n),
                Err(e) => log::warn!("DB: falha ao podar: {}", e),
                _ => {}
            }
        }
    });
}
