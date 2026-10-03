use std::fs;
use std::path::{Component, Path, PathBuf};

use tiny_http::{Header, Request, Response, StatusCode};

use crate::embedded::WebAssets;

pub fn handle(request: Request, web_root: Option<&Path>) -> anyhow::Result<()> {
    let url = request.url().to_string();
    let path_part = url.split('?').next().unwrap_or("/");
    let rel = if path_part == "/" || path_part.is_empty() {
        "index.html"
    } else {
        path_part.trim_start_matches('/')
    };

    // Previne path traversal
    let candidate = PathBuf::from(rel);
    for comp in candidate.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => return respond_text(request, 400, "Caminho inválido"),
        }
    }

    // MODO 1: servidor de arquivos (dev). Se --web foi passado e existe, usa.
    if let Some(root) = web_root
        && root.exists()
    {
        let full_path = root.join(&candidate);
        if full_path.starts_with(root)
            && let Ok(data) = fs::read(&full_path)
        {
            let mime = mime_from_path(&full_path);
            return respond_bytes(request, data, mime);
        }
        // Cai para o embed se não achar no disco
    }

    // MODO 2: assets embutidos no .exe
    match WebAssets::get_file(rel) {
        Some((data, mime)) => respond_bytes(request, data, &mime),
        None => respond_text(request, 404, "Arquivo não encontrado"),
    }
}

fn respond_bytes(request: Request, data: Vec<u8>, mime: &str) -> anyhow::Result<()> {
    let header = Header::from_bytes("Content-Type", mime).unwrap();
    let cache = Header::from_bytes("Cache-Control", "no-cache").unwrap();
    let response = Response::from_data(data)
        .with_header(header)
        .with_header(cache);
    request.respond(response)?;
    Ok(())
}

fn respond_text(request: Request, code: u16, body: &str) -> anyhow::Result<()> {
    let status = StatusCode(code);
    let header = Header::from_bytes("Content-Type", "text/plain; charset=utf-8").unwrap();
    let response = Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(header);
    request.respond(response)?;
    Ok(())
}

fn mime_from_path(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}
