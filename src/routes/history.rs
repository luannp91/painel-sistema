use std::sync::Arc;

use serde::Serialize;
use tiny_http::{Header, Request, Response};

use crate::storage::Storage;

#[derive(Serialize)]
struct HistoryResponse {
    from_ms: u64,
    to_ms: u64,
    count: usize,
    samples: Vec<crate::sysinfo::patterns::Sample>,
}

pub fn handle(request: Request, storage: Arc<Storage>) -> anyhow::Result<()> {
    let url = request.url().to_string();
    let query = url.split('?').nth(1).unwrap_or("");

    let minutes = parse_qs(query, "minutes")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60)
        .clamp(1, 60 * 24 * 30); // até 30 dias

    let max_points = parse_qs(query, "limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(5000)
        .clamp(100, 50000);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let from_ms = now_ms.saturating_sub(minutes * 60 * 1000);

    let samples = storage.query_samples(from_ms, now_ms, max_points)?;

    let payload = HistoryResponse {
        from_ms,
        to_ms: now_ms,
        count: samples.len(),
        samples,
    };

    let body = serde_json::to_vec(&payload)?;
    let header = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    let cors = Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap();
    let cache = Header::from_bytes("Cache-Control", "no-store").unwrap();

    let response = Response::from_data(body)
        .with_header(header)
        .with_header(cors)
        .with_header(cache);

    request.respond(response)?;
    Ok(())
}

fn parse_qs(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(v.to_string());
        }
    }
    None
}
