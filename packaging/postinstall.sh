#!/bin/bash
set -e

# Recarrega o systemd e habilita o serviço
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable painel-sistema.service >/dev/null 2>&1 || true

    # Só inicia se não foi desabilitado explicitamente
    if [ ! -f /etc/painel-sistema/disable-autostart ]; then
        systemctl start painel-sistema.service >/dev/null 2>&1 || true
    fi
fi

echo ""
echo "✅ Painel do Sistema instalado!"
echo "   Inicie o serviço:  sudo systemctl start painel-sistema"
echo "   Acesse:            http://localhost:8080"
echo ""
