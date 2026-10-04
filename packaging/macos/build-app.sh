#!/bin/bash
set -euo pipefail

VERSION="${1:-0.2.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_NAME="Painel do Sistema"
APP_DIR="$ROOT/packaging/macos/dist/$APP_NAME.app"

echo "▶ Limpando dist anterior…"
rm -rf "$ROOT/packaging/macos/dist"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

echo "▶ Copiando binário…"
cp "$ROOT/target/release/painel-sistema" "$APP_DIR/Contents/MacOS/painel-sistema"
chmod +x "$APP_DIR/Contents/MacOS/painel-sistema"

echo "▶ Gerando launcher…"
cat > "$APP_DIR/Contents/MacOS/launcher" <<EOF
#!/bin/bash
DIR="\$(cd "\$(dirname "\$0")" && pwd)"
"\$DIR/painel-sistema" --port 8080 &
sleep 1
open http://localhost:8080
EOF
chmod +x "$APP_DIR/Contents/MacOS/launcher"

echo "▶ Copiando Info.plist…"
sed "s/0\.2\.0/$VERSION/g" "$ROOT/packaging/macos/Info.plist" > "$APP_DIR/Contents/Info.plist"

echo "▶ Convertendo ícone…"
if [ -f "$ROOT/web/assets/icons/favicon.svg" ] && command -v sips >/dev/null; then
    # SVG → PNG → ICNS
    sips -s format png "$ROOT/web/assets/icons/favicon.svg" --out /tmp/icon.png >/dev/null 2>&1 || true
    if [ -f /tmp/icon.png ]; then
        mkdir -p /tmp/icon.iconset
        for size in 16 32 64 128 256 512; do
            sips -z $size $size /tmp/icon.png --out "/tmp/icon.iconset/icon_${size}x${size}.png" >/dev/null 2>&1
        done
        iconutil -c icns /tmp/icon.iconset -o "$APP_DIR/Contents/Resources/AppIcon.icns" 2>/dev/null || true
    fi
fi

echo "▶ Gerando DMG…"
if command -v hdiutil >/dev/null; then
    hdiutil create -volname "$APP_NAME" \
        -srcfolder "$ROOT/packaging/macos/dist" \
        -ov -format UDZO \
        "$ROOT/packaging/macos/dist/PainelSistema-$VERSION.dmg"
fi

echo "✅ Feito! App em: $APP_DIR"
