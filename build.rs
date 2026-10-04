fn main() {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("web/assets/icons/favicon.ico");
        res.set("ProductName", "Painel do Sistema");
        res.set("FileDescription", "Agente nativo + painel web");
        res.set("CompanyName", "Luann P.");
        res.set("LegalCopyright", "MIT License");
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        res.set("FileVersion", env!("CARGO_PKG_VERSION"));
        res.set("OriginalFilename", "painel-sistema.exe");
        res.set("InternalName", "painel-sistema");

        if let Err(e) = res.compile() {
            eprintln!("Aviso: falha ao compilar recursos do Windows: {e}");
        }
    }
}
