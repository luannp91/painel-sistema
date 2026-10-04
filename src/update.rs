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
    pub platform: String,
    pub arch: String,
    pub downloads: Vec<Download>,
    pub release_notes: Option<String>,
    pub published_at: Option<String>,
    pub html_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Download {
    pub name: String,
    pub url: String,
    pub kind: String,
    pub size_bytes: Option<u64>,
    pub recommended: bool,
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
    size: Option<u64>,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Retorna (os, arch) normalizados para uso no matching de assets.
fn detect_platform() -> (&'static str, &'static str) {
    let os = std::env::consts::OS; // "windows", "linux", "macos", "freebsd"...
    let arch = std::env::consts::ARCH; // "x86_64", "aarch64", "arm", "x86"
    (os, arch)
}

/// Verifica se o nome do asset bate com o SO/arch atual.
fn classify_asset(name: &str) -> Option<&'static str> {
    let n = name.to_lowercase();

    // Extensões binárias
    if n.ends_with(".exe") {
        return Some("exe");
    }
    if n.ends_with(".msi") {
        return Some("msi");
    }
    if n.ends_with(".deb") {
        return Some("deb");
    }
    if n.ends_with(".rpm") {
        return Some("rpm");
    }
    if n.ends_with(".dmg") {
        return Some("dmg");
    }
    if n.ends_with(".pkg") {
        return Some("pkg");
    }
    if n.ends_with(".appimage") {
        return Some("appimage");
    }
    if n.ends_with(".tar.gz") {
        return Some("tarball");
    }

    // Binários sem extensão
    if n.contains("windows") {
        return Some("exe");
    }
    if n.contains("linux") || n.contains("gnu") || n.contains("musl") {
        return Some("binary");
    }
    if n.contains("apple") || n.contains("darwin") || n.contains("macos") {
        return Some("binary");
    }

    None
}

/// Verifica se o asset bate com a arquitetura atual.
fn matches_arch(name: &str, arch: &str) -> bool {
    let n = name.to_lowercase();
    match arch {
        "x86_64" => n.contains("x86_64") || n.contains("amd64") || !n.contains("aarch64"),
        "aarch64" => n.contains("aarch64") || n.contains("arm64"),
        "x86" => n.contains("i686") || n.contains("i386"),
        _ => true,
    }
}

/// Ordena e filtra os assets para o SO/arch atual.
/// Retorna uma lista na ordem de preferência.
fn select_downloads(assets: &[GithubAsset], os: &str, arch: &str) -> Vec<Download> {
    // Cada SO tem uma ordem de prioridade por tipo de artefato
    let priorities: &[&str] = match os {
        "windows" => &["exe", "msi"],
        "linux" => &["deb", "rpm", "binary", "appimage", "tarball"],
        "macos" => &["dmg", "pkg", "binary", "tarball"],
        _ => &["binary", "tarball"],
    };

    let mut ordered: Vec<Download> = Vec::new();

    for kind in priorities {
        for a in assets {
            let Some(asset_kind) = classify_asset(&a.name) else {
                continue;
            };
            if &asset_kind != kind {
                continue;
            }

            // Filtra por arquitetura (só quando aplicável)
            if !matches_arch(&a.name, arch) {
                continue;
            }

            // Evita duplicar
            if ordered.iter().any(|d| d.name == a.name) {
                continue;
            }

            ordered.push(Download {
                name: a.name.clone(),
                url: a.browser_download_url.clone(),
                kind: asset_kind.to_string(),
                size_bytes: a.size,
                recommended: false,
            });
        }
    }

    // Marca o primeiro como recomendado
    if let Some(first) = ordered.first_mut() {
        first.recommended = true;
    }

    ordered
}

pub fn check(enabled: bool, token: &str) -> Result<UpdateInfo> {
    if !enabled {
        return Ok(offline_stub());
    }

    let (os, arch) = detect_platform();
    let current = current_version().to_string();

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .build();

    let mut req = agent
        .get(GITHUB_API)
        .set("Accept", "application/vnd.github.v3+json");

    if !token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", token));
    }

    let response = req.call().context("falha ao consultar GitHub Releases")?;

    let release: GithubRelease = response
        .into_json()
        .context("resposta do GitHub não é JSON válido")?;

    let latest = release.tag_name.trim_start_matches('v').to_string();
    let has_update = version_gt(&latest, &current);

    let downloads = select_downloads(&release.assets, os, arch);

    Ok(UpdateInfo {
        current,
        latest,
        has_update,
        platform: os.to_string(),
        arch: arch.to_string(),
        downloads,
        release_notes: release.body.or(release.name),
        published_at: release.published_at,
        html_url: release.html_url,
    })
}

/// Compara versões semver simples.
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

/// Fallback offline (sem acesso ao GitHub).
pub fn offline_stub() -> UpdateInfo {
    let (os, arch) = detect_platform();
    UpdateInfo {
        current: current_version().to_string(),
        latest: current_version().to_string(),
        has_update: false,
        platform: os.to_string(),
        arch: arch.to_string(),
        downloads: Vec::new(),
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

    #[test]
    fn classifies_assets() {
        assert_eq!(
            classify_asset("painel-sistema-x86_64-pc-windows-msvc.exe"),
            Some("exe")
        );
        assert_eq!(classify_asset("PainelSistema-0.3.0.msi"), Some("msi"));
        assert_eq!(
            classify_asset("painel-sistema_0.3.0_amd64.deb"),
            Some("deb")
        );
        assert_eq!(
            classify_asset("painel-sistema-0.3.0.x86_64.rpm"),
            Some("rpm")
        );
        assert_eq!(
            classify_asset("painel-sistema-x86_64-apple-darwin"),
            Some("binary")
        );
        assert_eq!(classify_asset("arquivo-random.txt"), None);
    }

    #[test]
    fn filters_downloads_for_windows() {
        let assets = vec![
            GithubAsset {
                name: "painel-sistema-x86_64-pc-windows-msvc.exe".into(),
                browser_download_url: "u1".into(),
                size: Some(1),
            },
            GithubAsset {
                name: "painel-sistema_0.3.0_amd64.deb".into(),
                browser_download_url: "u2".into(),
                size: Some(2),
            },
            GithubAsset {
                name: "painel-sistema-0.3.0.x86_64.rpm".into(),
                browser_download_url: "u3".into(),
                size: Some(3),
            },
            GithubAsset {
                name: "painel-sistema-x86_64-apple-darwin".into(),
                browser_download_url: "u4".into(),
                size: Some(4),
            },
        ];
        let downloads = select_downloads(&assets, "windows", "x86_64");
        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].kind, "exe");
        assert!(downloads[0].recommended);
    }

    #[test]
    fn filters_downloads_for_linux() {
        let assets = vec![
            GithubAsset {
                name: "painel-sistema-x86_64-pc-windows-msvc.exe".into(),
                browser_download_url: "u1".into(),
                size: Some(1),
            },
            GithubAsset {
                name: "painel-sistema_0.3.0_amd64.deb".into(),
                browser_download_url: "u2".into(),
                size: Some(2),
            },
            GithubAsset {
                name: "painel-sistema-0.3.0.x86_64.rpm".into(),
                browser_download_url: "u3".into(),
                size: Some(3),
            },
            GithubAsset {
                name: "painel-sistema-x86_64-unknown-linux-gnu".into(),
                browser_download_url: "u4".into(),
                size: Some(4),
            },
        ];
        let downloads = select_downloads(&assets, "linux", "x86_64");
        assert_eq!(downloads.len(), 3);
        assert_eq!(downloads[0].kind, "deb");
        assert_eq!(downloads[1].kind, "rpm");
        assert_eq!(downloads[2].kind, "binary");
    }

    #[test]
    fn filters_downloads_for_macos_arm() {
        let assets = vec![
            GithubAsset {
                name: "painel-sistema-x86_64-apple-darwin".into(),
                browser_download_url: "u1".into(),
                size: Some(1),
            },
            GithubAsset {
                name: "painel-sistema-aarch64-apple-darwin".into(),
                browser_download_url: "u2".into(),
                size: Some(2),
            },
            GithubAsset {
                name: "painel-sistema_0.3.0_amd64.deb".into(),
                browser_download_url: "u3".into(),
                size: Some(3),
            },
        ];
        let downloads = select_downloads(&assets, "macos", "aarch64");
        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].name, "painel-sistema-aarch64-apple-darwin");
    }
}
