//! `GET /api/security/snapshot` — último [`SecuritySnapshot`] produzido
//! pelo publisher.
//!
//! Não coleta ao vivo: `engine.collect_security()` avança estado interno
//! (baseline, lineage) e não é idempotente. Quem coleta é o publisher do
//! SSE, uma vez por ciclo. Esta rota só lê o cache.

use std::sync::{Arc, Mutex};

use tiny_http::{Header, Request, Response, StatusCode};

use crate::security::engine::SecuritySnapshot;

/// Cache compartilhado com o publisher.
pub type SecurityCache = Arc<Mutex<Option<Arc<SecuritySnapshot>>>>;

pub fn handle(request: Request, cache: SecurityCache) -> anyhow::Result<()> {
    let cached = cache.lock().unwrap().clone();

    let (status, body) = match cached {
        Some(snap) => (StatusCode(200), serde_json::to_vec(&*snap)?),
        None => (
            StatusCode(503),
            br#"{"error":"not_ready","message":"Aguardando primeiro ciclo de coleta de seguranca"}"#
                .to_vec(),
        ),
    };

    let content_type =
        Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    let cors = Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap();
    let cache_hdr = Header::from_bytes("Cache-Control", "no-store").unwrap();

    request.respond(
        Response::from_data(body)
            .with_status_code(status)
            .with_header(content_type)
            .with_header(cors)
            .with_header(cache_hdr),
    )?;
    Ok(())
}
