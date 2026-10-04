#!/bin/bash
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop painel-sistema.service >/dev/null 2>&1 || true
    systemctl disable painel-sistema.service >/dev/null 2>&1 || true
fi
