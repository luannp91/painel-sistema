use tiny_http::{Header, Request, Response};

use crate::settings::UpdateSettings;
use crate::update;

pub fn handle(request: Request, settings: &UpdateSettings) -> anyhow::Result<()> {
    let info = update::check(settings.enabled, &settings.github_token).unwrap_or_else(|e| {
        log::debug!("Falha ao checar update: {}", e);
        update::offline_stub()
    });

    let body = serde_json::to_vec(&info)?;
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
