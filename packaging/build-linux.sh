#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-0.2.0}"

cd "$ROOT"

echo "▶ Compilando release…"
cargo build --release

echo "▶ Verificando nfpm…"
if ! command -v nfpm >/dev/null 2>&1; then
    echo "Instalando nfpm (via go)…"
    if ! command -v go >/dev/null 2>&1; then
        echo "ERRO: precisa do Go ou do nfpm instalado."
        echo "Instale: https://nfpm.goreleaser.com/install/"
        exit 1
    fi
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
    export PATH="$PATH:$(go env GOPATH)/bin"
fi

echo "▶ Gerando .deb e .rpm…"
nfpm package --config packaging/nfpm.yaml --packager deb --target "packaging/dist/painel-sistema_${VERSION}_amd64.deb"
nfpm package --config packaging/nfpm.yaml --packager rpm --target "packaging/dist/painel-sistema-${VERSION}.x86_64.rpm"

echo "✅ Pacotes em packaging/dist/:"
ls -lh packaging/dist/
