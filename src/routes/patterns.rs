use std::sync::{Arc, Mutex};

use serde::Serialize;
use tiny_http::{Header, Request, Response};

use crate::sysinfo::patterns::{Pattern, PatternDetector, Sample};

#[derive(Serialize)]
struct PatternsResponse {
    patterns: Vec<Pattern>,
    history: Vec<Sample>,
    now_ms: u64,
}

pub fn handle(request: Request, detector: Arc<Mutex<PatternDetector>>) -> anyhow::Result<()> {
    let url = request.url().to_string();
    let limit = url
        .split('?')
        .nth(1)
        .and_then(|qs| {
            qs.split('&')
                .find(|p| p.starts_with("limit="))
                .and_then(|p| p.trim_start_matches("limit=").parse::<usize>().ok())
        })
        .unwrap_or(100)
        .clamp(1, 500);

    let payload = {
        let pd = detector.lock().unwrap();
        PatternsResponse {
            patterns: pd.latest(limit),
            history: pd.samples(60),
            now_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        }
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
