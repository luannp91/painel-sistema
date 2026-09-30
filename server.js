// server.js — servidor HTTP mínimo, sem dependências
import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL(".", import.meta.url));
const PORT = process.env.PORT || 8000;

const MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".woff2": "font/woff2"
};

const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://localhost:${PORT}`);
        let pathname = decodeURIComponent(url.pathname);
        if (pathname === "/") pathname = "/index.html";

        // Impede path traversal
        const safePath = normalize(pathname).replace(/^(\.\.(\/|\\|$))+/, "");
        const filePath = join(ROOT, safePath);

        // Garante que o arquivo está dentro de ROOT
        if (!filePath.startsWith(ROOT.endsWith(sep) ? ROOT : ROOT + sep)) {
            throw new Error("Fora do diretório");
        }

        const info = await stat(filePath);
        if (info.isDirectory()) throw new Error("É um diretório");

        const data = await readFile(filePath);
        const ext = extname(filePath).toLowerCase();

        res.writeHead(200, {
            "Content-Type": MIME[ext] || "application/octet-stream",
            "Cache-Control": "no-cache"
        });
        res.end(data);
    } catch {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("404 — Não encontrado");
    }
});

server.listen(PORT, () => {
    console.log(`\n✅ Servidor em http://localhost:${PORT}\n`);
});
