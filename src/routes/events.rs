use tiny_http::{Header, Request, Response};

use crate::sysinfo::events::collect_events;

pub fn handle(request: Request) -> anyhow::Result<()> {
    // Lê ?limit=N da query string (padrão 100, máximo 500)
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

    let events = collect_events(limit);
    let body = serde_json::to_vec(&events)?;

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
