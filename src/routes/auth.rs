//! `POST /api/auth/exchange` — troca chave de bootstrap (`otk`) por
//! cookie de sessão.
//! `POST /api/auth/session` — troca token por cookie de sessão (usado
//! pelo prompt manual quando o cookie expirou ou nunca existiu).

use tiny_http::{Header, Request, Response, StatusCode};

use crate::auth;
use crate::auth_bootstrap::BootstrapKey;
use crate::auth_sessions::set_cookie_header;

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
        return reject(request, "chave de bootstrap inválida ou expirada");
    }

    ok(request, &real_token)
}

pub fn session(mut request: Request, real_token: String) -> anyhow::Result<()> {
    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);

    let candidate = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("token").and_then(|s| s.as_str()).map(str::to_string))
        .unwrap_or_default();

    if candidate.is_empty() || !auth::constant_time_eq(&candidate, &real_token) {
        return reject(request, "token inválido");
    }

    ok(request, &real_token)
}

fn ok(request: Request, real_token: &str) -> anyhow::Result<()> {
    let body = serde_json::to_vec(&serde_json::json!({ "ok": true }))?;
    let cookie = set_cookie_header(real_token);

    let resp = Response::from_data(body)
        .with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap())
        .with_header(Header::from_bytes("Set-Cookie", cookie).unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
    request.respond(resp)?;
    Ok(())
}

fn reject(request: Request, msg: &str) -> anyhow::Result<()> {
    let body = serde_json::to_vec(&serde_json::json!({
        "error": "invalid_credentials",
        "message": msg,
    }))?;
    let resp = Response::from_data(body)
        .with_status_code(StatusCode(401))
        .with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
    request.respond(resp)?;
    Ok(())
}
