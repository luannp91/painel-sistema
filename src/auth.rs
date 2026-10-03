use tiny_http::{Header, Request, Response, StatusCode};

/// Verifica se a requisição tem o token correto.
/// Retorna `true` se autorizada (ou se auth está desabilitada).
pub fn is_authorized(request: &Request, enabled: bool, token: &str) -> bool {
    if !enabled {
        return true;
    }

    // 1) Header Authorization: Bearer <token>
    for header in request.headers() {
        if header.field.equiv("Authorization") {
            let value = header.value.as_str().trim();
            if let Some(stripped) = value.strip_prefix("Bearer ")
                && constant_time_eq(stripped, token)
            {
                return true;
            }
        }
    }

    // 2) Query param ?token=... (EventSource não suporta headers custom)
    let url = request.url().to_string();
    if let Some(qs) = url.split('?').nth(1) {
        for pair in qs.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && k == "token"
                && constant_time_eq(v, token)
            {
                return true;
            }
        }
    }

    false
}

pub fn unauthorized_response() -> Response<std::io::Cursor<Vec<u8>>> {
    let body = r#"{"error":"unauthorized","message":"Token inválido ou ausente"}"#;
    let header = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    let www = Header::from_bytes("WWW-Authenticate", "Bearer realm=\"painel-sistema\"").unwrap();

    Response::from_string(body)
        .with_status_code(StatusCode(401))
        .with_header(header)
        .with_header(www)
}

/// Comparação em tempo constante (evita timing attacks).
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
