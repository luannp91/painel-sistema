use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/"]
pub struct WebAssets;

impl WebAssets {
    /// Busca um arquivo embutido. Retorna `(bytes, mime_type)`.
    pub fn get_file(path: &str) -> Option<(Vec<u8>, String)> {
        let path = path.trim_start_matches('/');
        let file = Self::get(path)?;
        let mime = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();
        Some((file.data.into_owned(), mime))
    }

    /// Verifica se existe um index.html embutido.
    pub fn has_index() -> bool {
        Self::get("index.html").is_some()
    }
}
