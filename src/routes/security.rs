//! Rotas de segurança:
//! - `GET /api/security/snapshot` — último `SecuritySnapshot` em cache.
//! - `GET /api/security/findings` — histórico persistido (paginado).
//!
//! Ambas leem de cache/storage; não coletam ao vivo.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tiny_http::{Header, Request, Response, StatusCode};

use crate::security::engine::SecuritySnapshot;
use crate::security::types::Severity;
use crate::storage::Storage;

/// Cache compartilhado com o publisher do SSE.
pub type SecurityCache = Arc<Mutex<Option<Arc<SecuritySnapshot>>>>;

// ---------------------------------------------------------------------------
// GET /api/security/snapshot
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// GET /api/security/findings
// ---------------------------------------------------------------------------

/// Resposta da listagem de findings.
#[derive(serde::Serialize)]
struct FindingsResponse {
    findings: Vec<crate::storage::FindingRow>,
    count: usize,
    /// `true` quando o DB está desabilitado ou a query falhou.
    empty: bool,
}

pub fn findings(request: Request, storage: Option<Arc<Storage>>) -> anyhow::Result<()> {
    let url = request.url().to_string();
    let qs = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let params = parse_query(qs);

    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(200)
        .clamp(1, 1000);

    let kind = params
        .get("kind")
        .map(String::as_str)
        .filter(|s| !s.is_empty());

    let severity = params.get("severity").and_then(|s| parse_severity(s));

    let search = params
        .get("search")
        .map(String::as_str)
        .filter(|s| !s.is_empty());

    let (rows, empty) = match storage {
        Some(s) => match s.query_findings(limit, kind, severity, search) {
            Ok(r) => (r, false),
            Err(e) => {
                log::warn!("query_findings falhou: {:#}", e);
                (Vec::new(), true)
            }
        },
        None => (Vec::new(), true),
    };

    let count = rows.len();
    let body = serde_json::to_vec(&FindingsResponse {
        findings: rows,
        count,
        empty,
    })?;

    let content_type =
        Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    let cors = Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap();
    let cache_hdr = Header::from_bytes("Cache-Control", "no-store").unwrap();

    request.respond(
        Response::from_data(body)
            .with_header(content_type)
            .with_header(cors)
            .with_header(cache_hdr),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "clean" => Some(Severity::Clean),
        "attention" => Some(Severity::Attention),
        "suspicious" => Some(Severity::Suspicious),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Parse de query string mínima: `k=v&k2=v2`, com `%XX` e `+`.
/// Sem alocação desnecessária.
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
        let p = parse_query("limit=50&kind=lol_bin");
        assert_eq!(p.get("limit").map(String::as_str), Some("50"));
        assert_eq!(p.get("kind").map(String::as_str), Some("lol_bin"));
    }

    #[test]
    fn parse_query_empty() {
        assert!(parse_query("").is_empty());
    }

    #[test]
    fn parse_query_percent_decode() {
        let p = parse_query("search=svchost%20tmp");
        assert_eq!(p.get("search").map(String::as_str), Some("svchost tmp"));
    }

    #[test]
    fn parse_query_plus_as_space() {
        let p = parse_query("search=a+b");
        assert_eq!(p.get("search").map(String::as_str), Some("a b"));
    }

    #[test]
    fn parse_query_invalid_percent_kept() {
        let p = parse_query("x=%ZZ");
        assert_eq!(p.get("x").map(String::as_str), Some("%ZZ"));
    }

    #[test]
    fn parse_severity_works() {
        assert_eq!(parse_severity("attention"), Some(Severity::Attention));
        assert_eq!(parse_severity("CRITICAL"), Some(Severity::Critical));
        assert_eq!(parse_severity("foo"), None);
    }
}
