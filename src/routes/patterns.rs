//! Rotas de padrões clássicos:
//! - `GET /api/patterns` — padrões ativos agora (memória) + samples recentes
//! - `GET /api/patterns/history` — histórico persistido (tabela `patterns`)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tiny_http::{Header, Request, Response, StatusCode};

use crate::storage::Storage;
use crate::sysinfo::patterns::{Pattern, PatternDetector, Sample};

// ---------------------------------------------------------------------------
// GET /api/patterns (memória)
// ---------------------------------------------------------------------------

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
            now_ms: now_millis(),
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

// ---------------------------------------------------------------------------
// GET /api/patterns/history (SQLite)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HistoryResponse {
    patterns: Vec<crate::storage::PatternRow>,
    count: usize,
    /// `true` quando o DB está desabilitado ou a query falhou.
    empty: bool,
}

pub fn history(request: Request, storage: Option<Arc<Storage>>) -> anyhow::Result<()> {
    let url = request.url().to_string();
    let qs = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let params = parse_query(qs);

    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(500)
        .clamp(1, 1000);

    let kind = params
        .get("kind")
        .map(String::as_str)
        .filter(|s| !s.is_empty());

    let level = params
        .get("level")
        .map(String::as_str)
        .filter(|s| !s.is_empty());

    let search = params
        .get("search")
        .map(String::as_str)
        .filter(|s| !s.is_empty());

    let (rows, empty) = match storage {
        Some(s) => match s.query_patterns(limit, kind, level, search) {
            Ok(r) => (r, false),
            Err(e) => {
                log::warn!("query_patterns falhou: {:#}", e);
                (Vec::new(), true)
            }
        },
        None => (Vec::new(), true),
    };

    let count = rows.len();
    let body = serde_json::to_vec(&HistoryResponse {
        patterns: rows,
        count,
        empty,
    })?;

    let header = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    let cors = Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap();
    let cache = Header::from_bytes("Cache-Control", "no-store").unwrap();

    request.respond(
        Response::from_data(body)
            .with_status_code(StatusCode(200))
            .with_header(header)
            .with_header(cors)
            .with_header(cache),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parse de query string mínima: `k=v&k2=v2`, com `%XX` e `+`.
fn parse_query(qs: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(url_decode(k), url_decode(v));
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_basic() {
        let p = parse_query("limit=50&kind=cpu_spike");
        assert_eq!(p.get("limit").map(String::as_str), Some("50"));
        assert_eq!(p.get("kind").map(String::as_str), Some("cpu_spike"));
    }

    #[test]
    fn parse_query_percent_decode() {
        let p = parse_query("search=cpu%20spike");
        assert_eq!(p.get("search").map(String::as_str), Some("cpu spike"));
    }

    #[test]
    fn parse_query_plus_as_space() {
        let p = parse_query("search=cpu+spike");
        assert_eq!(p.get("search").map(String::as_str), Some("cpu spike"));
    }
}
