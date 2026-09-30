# 💻 Painel do Sistema

Dashboard web que exibe informações do sistema operacional, navegador, hardware e rede detectadas diretamente pelo
browser — **sem backend**.

## ✨ Recursos

-   Detecção de SO, navegador, motor e arquitetura
-   Informações de tela, GPU (WebGL), rede, bateria e armazenamento
-   Preferências do usuário, permissões e codecs suportados
-   Tema claro/escuro com persistência em `localStorage`
-   Exportação e cópia dos dados como JSON
-   Atalhos de teclado: `R` (atualizar), `C` (copiar), `E` (exportar)
-   Layout responsivo e acessível

## 🚀 Como executar

Devido ao uso de **ES Modules**, é necessário servir os arquivos por HTTP:

```bash
# Opção 1 — Python
python -m http.server 8000

# Opção 2 — Node (npx)
npx serve .

# Opção 3 — VS Code Live Server
# Basta clicar em "Go Live" com o index.html aberto
```

Depois acesse `http://localhost:8000`.

## 📁 Estrutura

```
painel-sistema/
├── index.html
├── css/
│   ├── base.css         # Reset, variáveis, tipografia
│   ├── layout.css       # Grid, cabeçalho, rodapé, responsivo
│   ├── components.css   # Botões, cards, toast, spinner
│   └── themes.css       # Tema claro
├── js/
│   ├── main.js          # Ponto de entrada
│   ├── config.js        # Metadados e listas
│   ├── state.js         # Estado global
│   ├── utils/           # Helpers (safe, format, dom, detect, perf)
│   ├── collectors/      # Um coletor por categoria
│   ├── ui/              # Render, tema, toast, relógio
│   └── actions/         # Refresh, copiar, exportar
└── assets/
    └── icons/favicon.svg
```

## ⚠️ Limitações

Navegadores restringem o acesso ao SO por segurança. Alguns dados só estão disponíveis em **HTTPS** ou **localhost**, e
outros apenas em navegadores específicos (Chrome/Edge expõem mais APIs que Firefox/Safari).

## 📜 Licença

MIT — use livremente.
