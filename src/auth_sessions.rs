//! Session IDs derivados do token — autenticação por cookie HttpOnly.
//!
//! O token real nunca aparece em URL nem em `localStorage`. As requests
//! seguintes (REST + SSE) carregam um cookie cujo valor é
//! `sha256(SALT || token)`. Como o token é estável, o session ID também
//! é — o servidor reconhece o cookie mesmo após reiniciar, sem
//! precisar guardar nada em memória.

use sha2::{Digest, Sha256};

const SESSION_SALT: &[u8] = b"painel-session-v1:";

/// Nome do cookie.
pub const COOKIE_NAME: &str = "painel_session";

/// Deriva o session ID a partir do token real.
pub fn session_id_from_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(SESSION_SALT);
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

/// Comparação em tempo constante.
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

/// `true` se o valor do cookie bate com o token atual.
pub fn validate_session_cookie(cookie_value: &str, token: &str) -> bool {
    if cookie_value.is_empty() || token.is_empty() {
        return false;
    }
    constant_time_eq(cookie_value, &session_id_from_token(token))
}

/// Header `Set-Cookie` completo.
///
/// - `HttpOnly` — JS não lê, só o browser envia automaticamente.
/// - `SameSite=Strict` — só viaja em requests same-origin (localhost).
/// - `Max-Age=604800` — 7 dias.
pub fn set_cookie_header(token: &str) -> String {
    let sid = session_id_from_token(token);
    format!("{COOKIE_NAME}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800")
}

/// Extrai `painel_session` do header `Cookie:`, se presente.
pub fn parse_session_cookie(cookie_header: &str) -> Option<&str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(v) = pair
            .strip_prefix(COOKIE_NAME)
            .and_then(|s| s.strip_prefix('='))
        {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let a = session_id_from_token("abc");
        let b = session_id_from_token("abc");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn validate_accepts_matching_cookie() {
        let tok = "meu-token";
        let sid = session_id_from_token(tok);
        assert!(validate_session_cookie(&sid, tok));
    }

    #[test]
    fn validate_rejects_wrong_cookie() {
        assert!(!validate_session_cookie("nao-bate", "meu-token"));
        assert!(!validate_session_cookie("", "meu-token"));
    }

    #[test]
    fn parse_finds_cookie_between_others() {
        let h = "other=1; painel_session=abc123; another=2";
        assert_eq!(parse_session_cookie(h), Some("abc123"));
    }

    #[test]
    fn parse_returns_none_if_absent() {
        assert_eq!(parse_session_cookie("other=1; another=2"), None);
    }

    #[test]
    fn set_cookie_has_flags() {
        let h = set_cookie_header("meu-token");
        assert!(h.contains("HttpOnly"));
        assert!(h.contains("SameSite=Strict"));
        assert!(h.contains("Path=/"));
    }
}
