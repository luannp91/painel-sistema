//! `POST /api/auth/exchange` — troca uma chave de bootstrap (`otk`)
//! pelo token real.

use tiny_http::{Header, Request, Response, StatusCode};

use crate::auth_bootstrap::BootstrapKey;

pub fn exchange(
    mut request: Request,
    bootstrap: BootstrapKey,
    real_token: String,
) -> anyhow::Result<()> {
    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);

    let candidate = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("otk").and_then(|s| s.as_str()).map(str::to_string))
        .unwrap_or_default();

    if candidate.is_empty() || !bootstrap.matches(&candidate) {
        let resp = Response::from_string(
            r#"{"error":"invalid_bootstrap_key","message":"Chave inválida ou expirada"}"#,
        )
        .with_status_code(StatusCode(401))
        .with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
        request.respond(resp)?;
        return Ok(());
    }

    let payload = serde_json::json!({ "token": real_token });
    let body = serde_json::to_vec(&payload)?;

    let resp = Response::from_data(body)
        .with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
    request.respond(resp)?;
    Ok(())
}
