use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const GITHUB_API: &str = "https://api.github.com/repos/luannp91/painel-sistema/releases/latest";
const USER_AGENT: &str = "painel-sistema-update-check";

#[derive(Debug, Clone, Serialize)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub has_update: bool,
    pub download_url: Option<String>,
    pub release_notes: Option<String>,
    pub published_at: Option<String>,
    pub html_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    published_at: Option<String>,
    html_url: Option<String>,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Consulta o GitHub Releases e compara com a versão atual.
pub fn check() -> Result<UpdateInfo> {
    let current = current_version().to_string();

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .build();

    let response = agent
        .get(GITHUB_API)
        .set("Accept", "application/vnd.github.v3+json")
        .call()
        .context("falha ao consultar GitHub Releases")?;

    let release: GithubRelease = response
        .into_json()
        .context("resposta do GitHub não é JSON válido")?;

    // tag_name costuma vir como "v0.2.0" — normaliza
    let latest = release.tag_name.trim_start_matches('v').to_string();

    let has_update = version_gt(&latest, &current);

    // Prefere o .msi; senão pega o primeiro asset disponível
    let download_url = release
        .assets
        .iter()
        .find(|a| a.name.ends_with(".msi"))
        .or_else(|| release.assets.first())
        .map(|a| a.browser_download_url.clone());

    Ok(UpdateInfo {
        current,
        latest,
        has_update,
        download_url,
        release_notes: release.body.or(release.name),
        published_at: release.published_at,
        html_url: release.html_url,
    })
}

/// Compara versões semver simples (X.Y.Z).
/// Retorna true se `a > b`.
fn version_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|x| !x.is_empty())
            .filter_map(|x| x.parse::<u32>().ok())
            .collect()
    };

    let va = parse(a);
    let vb = parse(b);

    for i in 0..va.len().max(vb.len()) {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

/// Fallback offline (útil em testes ou quando o GitHub estiver fora).
pub fn offline_stub() -> UpdateInfo {
    UpdateInfo {
        current: current_version().to_string(),
        latest: current_version().to_string(),
        has_update: false,
        download_url: None,
        release_notes: None,
        published_at: None,
        html_url: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(version_gt("0.2.0", "0.1.0"));
        assert!(version_gt("0.2.1", "0.2.0"));
        assert!(version_gt("1.0.0", "0.99.99"));
        assert!(version_gt("v0.3.0", "0.2.0"));
        assert!(!version_gt("0.1.0", "0.2.0"));
        assert!(!version_gt("0.2.0", "0.2.0"));
    }
}
